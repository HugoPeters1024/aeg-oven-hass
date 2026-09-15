# AEG Oven Local Bridge (PoC)

## Optional cloud relay (0.4.0)

### Temporary certificate pinning (0.4.1)

The Electrolux broker uses a private CA. Normal `ca` mode remains the default.
For a supervised capture session, select `upstream_tls_mode: pinned` and supply `upstream_cert_sha256`.
The value must contain the SHA-256 fingerprint of the complete DER-encoded server certificate, not its public key.
Uppercase hex and colon-separated fingerprints are accepted.

Pinned mode replaces CA, hostname, and certificate-expiry validation with an exact certificate match.
The proxy still sends the configured hostname as TLS SNI. It checks the pin before starting either relay direction.
An absent, malformed, or mismatched pin stops the connection. It never learns or replaces pins automatically.

Obtaining a fingerprint from an unverified connection is a first-observation trust decision, not independent proof of identity.
An attacker present during that observation could supply the initial certificate. Certificate renewal requires deliberate pin replacement.
Never update the pin automatically after a mismatch.

Add these options to the existing proxy configuration:

```yaml
upstream_tls_mode: pinned
upstream_cert_sha256: "REPLACE_WITH_EXPLICIT_SHA256_FINGERPRINT"
```

Keep the oven idle and supervised. Start with one light toggle.
After capture, select `bridge_mode: mock` and restart the add-on.

Mock mode remains the default. Proxy mode connects the oven to the real cloud broker.
The proxy verifies the cloud certificate and forwards bytes unchanged in both directions.
It does not generate MQTT acknowledgements or replay commands.
Telemetry decoding and Home Assistant publishing remain active.

**Warning: Real app commands can start heating. Supervise the oven during testing.**

After rebuilding the add-on, set these options:

```yaml
bridge_mode: proxy
own_redirect: false
upstream_host: mqtt-ecc.eu.ecp.electrolux.com
upstream_port: 8883
proxy_source_ip: 192.168.178.2
capture_commands: true
```

Keep the existing MQTT credentials and OpenWrt rules unchanged.
Start the add-on and inspect its logs. Test one light toggle with the oven idle.
Return `bridge_mode` to `mock` and restart the add-on after the capture session.

The Pi must resolve the cloud hostname to a public address. The proxy rejects private upstream addresses to prevent a local loop.
The upstream TLS connection sends no client certificate. A cloud requirement for mutual TLS will prevent operation.
Blocked oven HTTPS or time services can also prevent cloud authentication. Do not open unrestricted access to compensate.

CONNECT and AUTH contents are never logged. PUBLISH contents are omitted by default.
With `capture_commands: true`, cloud PUBLISH payloads on `cmd/` topics are logged as hex, limited to 4096 bytes.
These payloads and topic names can contain sensitive identifiers or application secrets. Keep logs private.
Other cloud payloads remain omitted. MQTT inspection assumes version 3.x; forwarding does not depend on successful inspection.
Inspection stops for malformed frames or packets larger than 1 MiB, without stopping the relay.
Only one authenticated TLS session from `proxy_source_ip` is relayed at a time.

No deployed firmware or running service changes are required until you choose to rebuild and restart.

Brings an AEG/Electrolux ECP oven into Home Assistant **without the cloud**, by impersonating
the Electrolux MQTT broker on your LAN and republishing the oven's telemetry via MQTT Discovery.

This is a proof of concept. It currently exposes **read-only** entities (door, light, temperatures,
Wi-Fi signal). Sending commands to the oven is not yet supported (the write format isn't cracked).

## How it works

1. The add-on ARP-redirects the oven's outbound MQTT/TLS (port 8883) to itself.
2. It answers the oven's TLS with a self-signed certificate (the oven does not validate it),
   speaks minimal MQTT, and decodes the oven's internal "hacl" telemetry.
3. It publishes the decoded values to your Mosquitto broker using MQTT Discovery, so entities
   appear automatically under a device named **AEG Oven**.

## Requirements

- **Mosquitto broker** add-on installed and started.
- The **MQTT** integration configured in Home Assistant.
- The add-on runs with host networking and the `NET_ADMIN` / `NET_RAW` capabilities (already
  declared) so it can ARP-redirect and set the `iptables` rule.

## Options

| Option | Meaning |
|---|---|
| `oven_ip` | The oven's LAN IP (give it a static DHCP lease). |
| `gateway_ip` | Your router's LAN IP. |
| `mqtt_host` | Leave blank to auto-use the Mosquitto add-on. Set to your HA machine's IP or `127.0.0.1` if the bridge can't reach MQTT. |
| `mqtt_port` / `mqtt_user` / `mqtt_password` | Only needed if you set `mqtt_host` manually. |
| `log_level` | `debug` to see every decoded property. |

## Notes and caveats

- **ARP redirect is a PoC mechanism.** It continuously ARP-spoofs the oven so its traffic routes
  through this add-on. If the add-on stops, the oven falls back to the cloud until it restarts.
  A router-level DNAT (OpenWrt / EdgeRouter) is the cleaner long-term replacement.
- **`iptables` on HA OS**: HA OS uses nftables; the container ships `iptables`/`iptables-legacy`.
  If the redirect doesn't take, this is the first thing to check in the logs.
- **Provisional temperature entities**: the temperature decode is a best guess from observed data
  and may need calibrating once you heat the oven and watch the values.
