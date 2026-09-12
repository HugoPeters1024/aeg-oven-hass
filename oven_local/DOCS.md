# AEG Oven Local Bridge (PoC)

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
