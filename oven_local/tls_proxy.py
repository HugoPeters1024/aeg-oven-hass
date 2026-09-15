import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import re
import signal
import ssl
import time


def upstream_security(mode, fingerprint):
    if mode == 'ca':
        return ssl.create_default_context(), None
    if mode != 'pinned':
        raise ValueError('UPSTREAM_TLS_MODE must be ca or pinned')
    normalized = fingerprint.strip().replace(':', '').lower()
    if not re.fullmatch(r'[0-9a-f]{64}', normalized):
        raise ValueError('Pinned mode requires an explicit 64-digit SHA-256 certificate fingerprint')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context, normalized


def verify_upstream_pin(writer, expected):
    if expected is None:
        return
    session = writer.get_extra_info('ssl_object')
    certificate = session.getpeercert(binary_form=True) if session else None
    if not certificate:
        raise RuntimeError('Pinned upstream did not provide a certificate; no oven data forwarded')
    actual = hashlib.sha256(certificate).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise RuntimeError('Upstream certificate pin mismatch; no oven data forwarded')


class MQTTObserver:
    def __init__(self, direction, log, capture_commands=False, telemetry=None, availability=None):
        self.direction = direction
        self.log = log
        self.capture_commands = capture_commands
        self.telemetry = telemetry
        self.availability = availability
        self.buffer = bytearray()
        self.disabled = False

    def feed(self, chunk):
        if self.disabled:
            return
        self.buffer.extend(chunk)
        while self.buffer:
            remaining = 0
            multiplier = 1
            header_size = None
            for offset in range(1, min(len(self.buffer), 5)):
                digit = self.buffer[offset]
                remaining += (digit & 127) * multiplier
                if not digit & 128:
                    header_size = offset + 1
                    break
                multiplier *= 128
            if remaining > 1048576 or (header_size is None and len(self.buffer) >= 5):
                self.disabled = True
                self.buffer.clear()
                self.log('warning', f'{self.direction}: MQTT inspection disabled; invalid or oversized frame')
                return
            if header_size is None or len(self.buffer) < header_size + remaining:
                return
            flags = self.buffer[0]
            body = bytes(self.buffer[header_size:header_size + remaining])
            del self.buffer[:header_size + remaining]
            try:
                self.observe(flags, body)
            except Exception as error:
                self.log('warning', f'MQTT observer error: {type(error).__name__}')

    def observe(self, flags, body):
        packet_type = flags >> 4
        event = {'time': time.time(), 'direction': self.direction,
                 'type': packet_type, 'bytes': len(body)}
        if packet_type in (1, 15):
            event['payload'] = '[authentication omitted]'
        elif packet_type == 2 and len(body) >= 2:
            event['connect_result'] = body[1]
            if self.availability:
                self.availability(body[1] == 0)
        elif packet_type == 3 and len(body) >= 2:
            topic_length = int.from_bytes(body[:2], 'big')
            qos = (flags >> 1) & 3
            payload_start = 2 + topic_length + (2 if qos else 0)
            if payload_start > len(body):
                return
            topic = body[2:2 + topic_length].decode('utf-8', 'replace')
            payload = body[payload_start:]
            event.update(topic=topic, qos=qos, retain=bool(flags & 1), duplicate=bool(flags & 8))
            if self.direction == 'cloud-to-oven' and topic.startswith('cmd/') and self.capture_commands:
                event['payload_hex'] = payload[:4096].hex()
                event['truncated'] = len(payload) > 4096
            else:
                event['payload'] = '[omitted]'
            if self.direction == 'oven-to-cloud' and self.telemetry:
                self.telemetry(payload.decode('utf-8', 'replace'))
        elif packet_type == 8 and len(body) >= 2:
            topics = []
            offset = 2
            while offset + 2 <= len(body):
                length = int.from_bytes(body[offset:offset + 2], 'big')
                offset += 2
                if offset + length >= len(body):
                    break
                topics.append(body[offset:offset + length].decode('utf-8', 'replace'))
                offset += length + 1
            event['topics'] = topics
        self.log('info' if packet_type in (1, 2, 8) or self.direction == 'cloud-to-oven' else 'debug',
                 'MQTT ' + json.dumps(event))


async def serve_proxy(server_context, port, log, telemetry, availability):
    hostname = os.environ.get('UPSTREAM_HOST', 'mqtt-ecc.eu.ecp.electrolux.com')
    upstream_port = int(os.environ.get('UPSTREAM_PORT', '8883'))
    allowed_source = os.environ.get('PROXY_SOURCE_IP', '192.168.178.2')
    capture = os.environ.get('CAPTURE_COMMANDS', 'false').lower() == 'true'
    security_mode = os.environ.get('UPSTREAM_TLS_MODE', 'ca')
    upstream_context, fingerprint = upstream_security(
        security_mode, os.environ.get('UPSTREAM_CERT_SHA256', ''))
    if fingerprint:
        log('warning', 'Pinned TLS mode: explicit certificate trust replaces CA, hostname, and expiry validation')
    active = False
    clients = set()

    async def relay(reader, writer, observer):
        while True:
            chunk = await reader.read(16384)
            if not chunk:
                return
            writer.write(chunk)
            await writer.drain()
            observer.feed(chunk)

    async def connected(reader, writer):
        nonlocal active
        peer = writer.get_extra_info('peername')
        if active or not peer or peer[0] != allowed_source:
            writer.close()
            return
        active = True
        task = asyncio.current_task()
        clients.add(task)
        upstream_writer = None
        pumps = []
        try:
            addresses = await asyncio.get_running_loop().getaddrinfo(hostname, upstream_port, type=1)
            addresses = [entry for entry in addresses if ipaddress.ip_address(entry[4][0]).is_global]
            if not addresses:
                raise RuntimeError('Upstream DNS has no public address; check for the local broker override')
            last_error = None
            for entry in addresses:
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(entry[4][0], upstream_port, ssl=upstream_context,
                                                server_hostname=hostname, ssl_handshake_timeout=10), 15)
                    verify_upstream_pin(upstream_writer, fingerprint)
                    break
                except (OSError, asyncio.TimeoutError) as error:
                    last_error = error
            if upstream_writer is None:
                raise last_error or RuntimeError('No upstream connection')
            log('info', f'TLS relay connected with {security_mode} verification; real app commands are enabled')
            pumps = [asyncio.create_task(relay(reader, upstream_writer,
                         MQTTObserver('oven-to-cloud', log, telemetry=telemetry))),
                     asyncio.create_task(relay(upstream_reader, writer,
                         MQTTObserver('cloud-to-oven', log, capture, availability=availability)))]
            done, pending = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for completed in done:
                completed.result()
        except Exception as error:
            log('warning', f'TLS relay ended: {type(error).__name__}: {error}')
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            for stream in (writer, upstream_writer):
                if stream is not None:
                    stream.close()
                    try:
                        await asyncio.wait_for(stream.wait_closed(), 3)
                    except Exception:
                        pass
            active = False
            availability(False)
            clients.discard(task)

    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stopped.set)
    server = await asyncio.start_server(connected, '0.0.0.0', port, ssl=server_context,
                                       ssl_handshake_timeout=10)
    log('warning', f'PROXY MODE on {port}: cloud commands can operate the oven; supervise testing')
    async with server:
        await stopped.wait()
    for task in list(clients):
        task.cancel()
    await asyncio.gather(*clients, return_exceptions=True)
