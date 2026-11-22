"""Configuration for the attack simulator. Mirror droneshield_ai/main/secrets.h here."""
# Broker (HiveMQ Cloud)
MQTT_HOST = "3741a09c57ad476c8fd43f8042614b57.s1.eu.hivemq.cloud"
MQTT_PORT = 8883
MQTT_USERNAME = "droneshield_device_01"
MQTT_PASSWORD = "23176345a"
MQTT_CLIENT_ID = "attack_sim_pc"

# Must match firmware DSHL_HMAC_KEY exactly
HMAC_KEY = "4cac37551b8d42bc928880df376e67d66df3d37d0bc3b28d3bfe83c65c34ba32"

# Target device
DEVICE_ID = "device_01"
TOPIC_COMMANDS = f"droneshield/{DEVICE_ID}/commands"
