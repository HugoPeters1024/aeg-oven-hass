#!/usr/bin/env python3
"""
AEG oven -> Home Assistant bridge (PoC).

1. ARP-redirects the oven's MQTT/TLS (8883) to this container (impersonation).
2. Terminates the oven's TLS with a self-signed cert (the oven does not validate it),
   speaks minimal MQTT, and decodes the oven's 'hacl' telemetry.
3. Republishes decoded values to the HA Mosquitto broker using MQTT Discovery, so HA
   auto-creates entities (door, light, temperatures, Wi-Fi signal, availability).

Read-only for now: we can observe/decode everything, but the write/command format is
not yet cracked, so no controllable entities are exposed.
"""
import os, ssl, json, time, socket, threading, subprocess, signal, re, sys

import paho.mqtt.client as mqtt
from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, conf

OVEN   = os.environ.get("OVEN_IP", "192.168.178.124")
GW     = os.environ.get("GATEWAY_IP", "192.168.178.1")
OVEN_PORT   = 8883      # the port the oven dials (we redirect it)
LISTEN_PORT = 18883     # our broker's real listen port; 8883 is taken by Mosquitto on this host
DATA   = "/data"
EC_CRT = f"{DATA}/fake_broker_ec.crt"; EC_KEY = f"{DATA}/fake_broker_ec.key"
RSA_CRT= f"{DATA}/fake_broker.crt";    RSA_KEY= f"{DATA}/fake_broker.key"
SUBJ   = '-subj "/CN=mqtt-ecc.eu.ecp.electrolux.com" -addext "subjectAltName=DNS:mqtt-ecc.eu.ecp.electrolux.com"'

MQTT_HOST = os.environ.get("MQTT_HOST") or "127.0.0.1"
# under host_network the internal name 'core-mosquitto' does not resolve, but the
# Mosquitto add-on maps 1883 onto the host, so localhost reaches it.
if MQTT_HOST == "core-mosquitto": MQTT_HOST = "127.0.0.1"
MQTT_PORT = int(os.environ.get("MQTT_PORT") or 1883)
MQTT_USER = os.environ.get("MQTT_USER") or ""
MQTT_PASS = os.environ.get("MQTT_PASSWORD") or ""
LOG_LEVEL = os.environ.get("LOG_LEVEL", "info")

DISCOVERY_PREFIX = "homeassistant"
BASE  = "oven_local"                       # our state topic namespace
AVAIL = f"{BASE}/status"                    # online / offline
DEVICE = {
    "identifiers": ["aeg_oven_944005078"],
    "name": "AEG Oven",
    "manufacturer": "AEG / Electrolux",
    "model": "944005078 (ECP)",
}

def log(level, *a):
    order = {"debug":0,"info":1,"warning":2,"error":3}
    if order.get(level,1) >= order.get(LOG_LEVEL,1):
        print(f"[{level.upper()}]", *a, flush=True)

def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True)

# ---------------------------------------------------------------- entity map
# key -> how to expose it in HA. decode turns the raw value bytes into a state string.
def dec_signed(v):  return str(int.from_bytes(v, "big", signed=True)) if v else "unknown"
def dec_temp(v):    # observed as 00 XX XX 00; the middle 16 bits look like degrees C
    if len(v) >= 3: return str(int.from_bytes(v[1:3], "big"))
    return str(int.from_bytes(v, "big")) if v else "unknown"
def dec_onoff(v):   return v.hex()

ENTITIES = {
    "RP1OC1:0460": {"kind":"binary_sensor","name":"Oven Door","device_class":"door",
                    "decode":dec_onoff,"payload_on":"01","payload_off":"00"},
    "RP1OC1:0490": {"kind":"binary_sensor","name":"Oven Light",
                    "decode":dec_onoff,"payload_on":"01","payload_off":"00"},
    "RP1NIU:0031": {"kind":"sensor","name":"Oven Wi-Fi Signal","device_class":"signal_strength",
                    "unit":"dBm","decode":dec_signed},
    "RP1OC1:0431": {"kind":"sensor","name":"Oven Cavity Temperature (provisional)",
                    "device_class":"temperature","unit":"°C","decode":dec_temp},
    "RP1OC1:0432": {"kind":"sensor","name":"Oven Target Temperature (provisional)",
                    "device_class":"temperature","unit":"°C","decode":dec_temp},
}
def obj_id(key): return key.replace(":", "_").lower()
def state_topic(key): return f"{BASE}/{obj_id(key)}/state"

# ---------------------------------------------------------------- MQTT (to HA)
try:   # paho-mqtt 2.x requires an explicit callback API version
    mqc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id="oven_local_bridge")
except (AttributeError, TypeError):   # paho-mqtt 1.x
    mqc = mqtt.Client(client_id="oven_local_bridge")
if MQTT_USER: mqc.username_pw_set(MQTT_USER, MQTT_PASS)
mqc.will_set(AVAIL, "offline", retain=True)

def publish_discovery():
    for key, e in ENTITIES.items():
        cfg = {
            "name": e["name"],
            "unique_id": f"{BASE}_{obj_id(key)}",
            "object_id": f"aeg_{obj_id(key)}",
            "state_topic": state_topic(key),
            "availability_topic": AVAIL,
            "device": DEVICE,
        }
        if e.get("device_class"): cfg["device_class"] = e["device_class"]
        if e["kind"] == "binary_sensor":
            cfg["payload_on"] = e["payload_on"]; cfg["payload_off"] = e["payload_off"]
        if "unit" in e: cfg["unit_of_measurement"] = e["unit"]
        topic = f"{DISCOVERY_PREFIX}/{e['kind']}/{BASE}/{obj_id(key)}/config"
        mqc.publish(topic, json.dumps(cfg), retain=True)
    log("info", f"published discovery for {len(ENTITIES)} entities")

def on_connect(c, u, flags, rc):
    log("info", f"MQTT connected rc={rc}")
    publish_discovery()
    c.publish(AVAIL, "offline", retain=True)   # until the oven actually connects

def mqtt_start():
    while True:
        try:
            mqc.on_connect = on_connect
            mqc.connect(MQTT_HOST, MQTT_PORT, keepalive=60)
            mqc.loop_start()
            return
        except Exception as ex:
            log("warning", f"MQTT connect to {MQTT_HOST}:{MQTT_PORT} failed: {ex}; retrying in 5s")
            time.sleep(5)

# ---------------------------------------------------------------- hacl decode
def decode_hacl(hexstr):
    try: p = bytes.fromhex(hexstr)
    except Exception: return None
    if not p or p[0] != 0xAD: return None
    i = 1
    while i < len(p) and (0x30 <= p[i] <= 0x39 or 0x41 <= p[i] <= 0x5a): i += 1
    cont = p[1:i].decode("ascii", "replace")
    prop = p[i:i+2].hex()
    val  = p[i+3:]                       # skip 2-byte prop + 1 type byte
    return f"{cont}:{prop}", val

def handle_state_json(js):
    try: obj = json.loads(js)
    except Exception: return
    for item in obj.get("data", []):
        d = decode_hacl(item.get("payload",""))
        if not d: continue
        key, val = d
        e = ENTITIES.get(key)
        if not e: continue
        try: st = e["decode"](val)
        except Exception: st = val.hex()
        mqc.publish(state_topic(key), st, retain=True)
        log("debug", f"{key} -> {st}")

# ---------------------------------------------------------------- MQTT (oven side, minimal)
def enc_len(n):
    out=b""
    while True:
        d=n%128; n//=128; out+=bytes([d|(0x80 if n>0 else 0)])
        if n==0: return out
def read_len(sock):
    n=0; m=1
    while True:
        b=sock.recv(1)
        if not b: return None
        n+=(b[0]&0x7f)*m
        if not (b[0]&0x80): return n
        m*=128
def read_packet(sock):
    b=sock.recv(1)
    if not b: return None
    typ=b[0]; ln=read_len(sock)
    if ln is None: return None
    data=b""
    while len(data)<ln:
        ch=sock.recv(ln-len(data))
        if not ch: return None
        data+=ch
    return typ,data
def mk(typ, payload=b""): return bytes([typ])+enc_len(len(payload))+payload

# ---------------------------------------------------------------- network plumbing
stop = threading.Event()
def autodetect():
    r = sh(f"ip route get {GW}").stdout
    iface = (re.search(r"dev (\S+)", r) or [None,None])[1]
    myip  = (re.search(r"src (\S+)", r) or [None,None])[1]
    return iface, myip

def ensure_certs():
    os.makedirs(DATA, exist_ok=True)
    if not os.path.exists(RSA_CRT):
        sh(f'openssl req -x509 -newkey rsa:2048 -nodes -keyout "{RSA_KEY}" -out "{RSA_CRT}" -days 3650 {SUBJ}')
    if not os.path.exists(EC_CRT):
        sh(f'openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes '
           f'-keyout "{EC_KEY}" -out "{EC_CRT}" -days 3650 {SUBJ}')

def resolve_mac(iface, ip):
    ans,_ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, retry=4, iface=iface)
    for _,x in ans: return x.hwsrc
    return None

def main():
    iface, myip = autodetect()
    if not iface or not myip:
        log("error", f"cannot find route to {GW}"); sys.exit(1)
    conf.iface = iface; conf.verb = 0
    my_mac = get_if_hwaddr(iface)
    log("info", f"iface={iface} me={myip}/{my_mac}")
    ensure_certs()

    oven_mac = resolve_mac(iface, OVEN); gw_mac = resolve_mac(iface, GW)
    if not oven_mac or not gw_mac:
        log("error", f"MAC resolve failed oven={oven_mac} gw={gw_mac}"); sys.exit(1)
    log("info", f"oven {OVEN}={oven_mac} gw {GW}={gw_mac}")

    # forwarding + redirect the oven's 8883 into us; reset its existing cloud flow
    sh("sysctl -w net.ipv4.ip_forward=1")
    sh("sysctl -w net.ipv4.conf.all.send_redirects=0")
    sh(f"iptables -t nat -A PREROUTING -i {iface} -p tcp -s {OVEN} --dport {OVEN_PORT} -j REDIRECT --to-ports {LISTEN_PORT}")
    sh(f"iptables -A FORWARD -i {iface} -p tcp -s {OVEN} --dport {OVEN_PORT} -j REJECT --reject-with tcp-reset")
    sh(f"conntrack -D -s {OVEN} 2>/dev/null")

    def poison(a,am,sp): sendp(Ether(dst=am)/ARP(op=2,pdst=a,hwdst=am,psrc=sp,hwsrc=my_mac),iface=iface)
    def heal(a,am,rp,rm): sendp(Ether(dst=am)/ARP(op=2,pdst=a,hwdst=am,psrc=rp,hwsrc=rm),iface=iface)
    def spoof():
        while not stop.is_set():
            poison(OVEN,oven_mac,GW); poison(GW,gw_mac,OVEN); time.sleep(1)
    threading.Thread(target=spoof, daemon=True).start()

    def cleanup(*_):
        stop.set(); time.sleep(0.3)
        for _ in range(5):
            heal(OVEN,oven_mac,GW,gw_mac); heal(GW,gw_mac,OVEN,oven_mac); time.sleep(0.1)
        sh(f"iptables -t nat -D PREROUTING -i {iface} -p tcp -s {OVEN} --dport {OVEN_PORT} -j REDIRECT --to-ports {LISTEN_PORT}")
        sh(f"iptables -D FORWARD -i {iface} -p tcp -s {OVEN} --dport {OVEN_PORT} -j REJECT --reject-with tcp-reset")
        try: mqc.publish(AVAIL, "offline", retain=True); mqc.loop_stop()
        except Exception: pass
        log("info", "cleaned up ARP / iptables"); os._exit(0)
    signal.signal(signal.SIGTERM, cleanup); signal.signal(signal.SIGINT, cleanup)

    # TLS impersonation context
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    for c,k in [(EC_CRT,EC_KEY),(RSA_CRT,RSA_KEY)]:
        try: ctx.load_cert_chain(c,k)
        except Exception as ex: log("warning", f"cert load {c}: {ex}")
    try: ctx.set_ciphers("ALL:@SECLEVEL=0")
    except Exception: pass
    ctx.verify_mode = ssl.CERT_NONE

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT)); srv.listen(5); srv.settimeout(1.0)
    log("info", f"local broker listening on {myip}:{LISTEN_PORT} (oven dials {OVEN_PORT}, redirected)")

    while not stop.is_set():
        try: raw, addr = srv.accept()
        except socket.timeout: continue
        except Exception: break
        if not addr[0].startswith(OVEN):
            raw.close(); continue
        try: tls = ctx.wrap_socket(raw, server_side=True)
        except Exception as ex:
            log("warning", f"TLS failed: {ex}"); continue
        log("info", f"oven connected {addr} {tls.version()}")
        mqc.publish(AVAIL, "online", retain=True)
        tls.settimeout(120)
        cmd_topic = None
        try:
            while not stop.is_set():
                pk = read_packet(tls)
                if pk is None: break
                typ, data = pk; t = typ & 0xF0
                if t == 0x10:                                   # CONNECT
                    tls.send(mk(0x20, b"\x00\x00"))
                elif t == 0x80:                                 # SUBSCRIBE
                    pid = data[0:2]; tl = int.from_bytes(data[2:4],"big")
                    topic = data[4:4+tl].decode("ascii","replace")
                    if topic.startswith("cmd/"): cmd_topic = topic
                    tls.send(mk(0x90, pid + b"\x00"))
                elif t == 0x30:                                 # PUBLISH (state)
                    qos = (typ>>1)&0x03
                    tl = int.from_bytes(data[0:2],"big"); rest = data[2+tl:]
                    if qos>0:
                        pid = rest[0:2]; rest = rest[2:]; tls.send(mk(0x40, pid))
                    handle_state_json(rest.decode("utf-8","replace"))
                elif t == 0xC0:                                 # PINGREQ
                    tls.send(mk(0xD0))
                elif t == 0xE0:                                 # DISCONNECT
                    break
        except Exception as ex:
            log("warning", f"session error: {ex}")
        finally:
            try: tls.close()
            except Exception: pass
            mqc.publish(AVAIL, "offline", retain=True)
            log("info", "oven disconnected; awaiting reconnect")

if __name__ == "__main__":
    mqtt_start()
    main()
