#!/usr/bin/with-contenv bashio
# Entry point: read add-on options, resolve MQTT credentials, launch the bridge.

export OVEN_IP="$(bashio::config 'oven_ip')"
export OVEN_MAC="$(bashio::config 'oven_mac')"
export GATEWAY_IP="$(bashio::config 'gateway_ip')"
export LOG_LEVEL="$(bashio::config 'log_level')"

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
