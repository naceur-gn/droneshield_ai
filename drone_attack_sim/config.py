"""Configuration for the attack simulator. Mirror droneshield_ai/main/secrets.h here."""
# Broker (HiveMQ Cloud)
MQTT_HOST = "YOUR_CLUSTER.s1.eu.hivemq.cloud"
MQTT_PORT = 8883
MQTT_USERNAME = "droneshield_device_01"
MQTT_PASSWORD = "YOUR_HIVEMQ_PASSWORD"
MQTT_CLIENT_ID = "attack_sim_pc"

# Must match firmware DSHL_HMAC_KEY exactly
HMAC_KEY = "REPLACE_WITH_32_PLUS_RANDOM_BYTES"

# Target device
DEVICE_ID = "device_01"
TOPIC_COMMANDS = f"droneshield/{DEVICE_ID}/commands"
