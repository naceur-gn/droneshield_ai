"""Shared helpers for attack simulation."""
import json
import hmac
import hashlib
import time
import ssl

import paho.mqtt.client as mqtt

from config import *


def canonical_params(params: dict) -> str:
    return json.dumps(params, separators=(",", ":"), sort_keys=True)


def sign(device_id, seq, timestamp, command, params, key=HMAC_KEY):
    canon = f"{device_id}|{seq}|{timestamp}|{command}|{canonical_params(params)}"
    return hmac.new(key.encode(), canon.encode(), hashlib.sha256).hexdigest()


def make_payload(device_id=DEVICE_ID, seq=1, timestamp=None, command="STATUS_REQUEST",
                params=None, signature=None, hmac_key=HMAC_KEY, extra=None):
    if params is None:
        params = {}
    if timestamp is None:
        timestamp = int(time.time())
    if signature is None:
        signature = sign(device_id, seq, timestamp, command, params, hmac_key)
    payload = {
        "device_id": device_id,
        "seq": seq,
        "timestamp": timestamp,
        "command": command,
        "params": params,
        "signature": signature,
    }
    if extra:
        payload.update(extra)
    return payload


def connect_client(client_id=MQTT_CLIENT_ID):
    client = mqtt.Client(client_id=client_id, protocol=mqtt.MQTTv5)
    client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)
    client.tls_set(cert_reqs=ssl.CERT_REQUIRED)
    client.connect(MQTT_HOST, MQTT_PORT, 60)
    client.loop_start()
    # wait for connect
    import time as _t
    for _ in range(50):
        if client.is_connected():
            return client
        _t.sleep(0.1)
    raise RuntimeError("MQTT connect timeout")


def publish(client, payload, topic=TOPIC_COMMANDS, qos=1):
    if isinstance(payload, dict):
        payload = json.dumps(payload, separators=(",", ":"))
    info = client.publish(topic, payload, qos=qos)
    info.wait_for_publish(timeout=5)
    print(f"[PUB] topic={topic} payload={payload}")
    return info


def now():
    return int(time.time())
