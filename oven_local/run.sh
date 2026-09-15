#!/usr/bin/with-contenv bashio
# Entry point: read add-on options, resolve MQTT credentials, launch the bridge.
#
# To verify the SAME bridge on a Wi-Fi laptop (proving the wired-Pi position is the blocker),
# run this on the laptop instead (do NOT run it while the add-on is also active):
#   wget -O /tmp/oven_bridge_prod.py http://192.168.178.27:8000/ha-addon/oven_local/oven_bridge.py
#   sudo OVEN_MAC=44:3e:07:79:bf:4a GATEWAY_IP=192.168.178.1 DATA_DIR=/tmp/ovencerts \
#        LOG_LEVEL=debug python3 /tmp/oven_bridge_prod.py
# (or just: wget the verify_on_laptop.sh helper and `sudo bash verify_on_laptop.sh`)

export OVEN_IP="$(bashio::config 'oven_ip')"
export OVEN_MAC="$(bashio::config 'oven_mac')"
export GATEWAY_IP="$(bashio::config 'gateway_ip')"
export INTERFACE="$(bashio::config 'interface')"
export OWN_REDIRECT="$(bashio::config 'own_redirect')"
export LOG_LEVEL="$(bashio::config 'log_level')"
export BRIDGE_MODE="$(bashio::config 'bridge_mode' 'mock')"
export UPSTREAM_HOST="$(bashio::config 'upstream_host' 'mqtt-ecc.eu.ecp.electrolux.com')"
export UPSTREAM_PORT="$(bashio::config 'upstream_port' '8883')"
export UPSTREAM_TLS_MODE="$(bashio::config 'upstream_tls_mode' 'ca')"
export UPSTREAM_CERT_SHA256="$(bashio::config 'upstream_cert_sha256')"
export PROXY_SOURCE_IP="$(bashio::config 'proxy_source_ip' '192.168.178.2')"
export CAPTURE_COMMANDS="$(bashio::config 'capture_commands' 'false')"

# MQTT: prefer explicit options; otherwise use the Supervisor-provided MQTT service.
if bashio::config.has_value 'mqtt_host'; then
  export MQTT_HOST="$(bashio::config 'mqtt_host')"
  export MQTT_PORT="$(bashio::config 'mqtt_port')"
  export MQTT_USER="$(bashio::config 'mqtt_user')"
  export MQTT_PASSWORD="$(bashio::config 'mqtt_password')"
else
  export MQTT_HOST="$(bashio::services mqtt 'host')"
  export MQTT_PORT="$(bashio::services mqtt 'port')"
  export MQTT_USER="$(bashio::services mqtt 'username')"
  export MQTT_PASSWORD="$(bashio::services mqtt 'password')"
fi

bashio::log.info "AEG oven bridge starting (oven=${OVEN_IP}, gw=${GATEWAY_IP})"
bashio::log.info "MQTT target: ${MQTT_HOST}:${MQTT_PORT}"
# NOTE: with host_network the internal name 'core-mosquitto' may not resolve.
# If the bridge cannot reach MQTT, set 'mqtt_host' in the add-on options to the
# Home Assistant machine's LAN IP (or 127.0.0.1) and 'mqtt_port' to 1883.

exec python3 -u /oven_bridge.py
