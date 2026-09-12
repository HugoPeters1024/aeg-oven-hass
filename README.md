# AEG Oven Local — Home Assistant add-on repository

A proof-of-concept Home Assistant add-on that brings an AEG/Electrolux ECP oven into Home
Assistant **locally**, without the Electrolux cloud, by impersonating the oven's MQTT broker on
your LAN and republishing its telemetry via MQTT Discovery.

## Install

1. In Home Assistant: **Settings → Add-ons → Add-on Store → ⋮ → Repositories**.
2. Add this repository's Git URL.
3. Install **AEG Oven Local Bridge** from the store.
4. Make sure the **Mosquitto broker** add-on and the **MQTT** integration are set up.
5. In the add-on's **Configuration** tab, set `oven_ip` and `gateway_ip`, then start it.
6. The oven appears in Home Assistant as a device named **AEG Oven**.

See the add-on's Documentation tab (`oven_local/DOCS.md`) for options and caveats.

## Status

- Read-only today: door, light, temperatures (provisional), Wi-Fi signal, availability.
- Control is not yet implemented; the oven's command encoding is still being reverse-engineered.

## How it was built

The reverse-engineering trail lives in the parent project's `NOTES.md`.
