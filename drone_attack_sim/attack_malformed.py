"""Malformed JSON / missing fields. Expected: REJECT (validator)."""
import time, json
from common import *

def main():
    client = connect_client("atk_malformed")
    try:
        # missing signature
        publish(client, {"device_id": "device_01", "seq": 1, "timestamp": int(time.time()),
                        "command": "PING", "params": {}})
        time.sleep(0.5)
        # invalid JSON
        client.publish(TOPIC_COMMANDS, "{not json", qos=1)
        print("[PUB] raw malformed json")
        time.sleep(0.5)
        # unknown command
        seq = int(time.time()) % 100000
        payload = make_payload(seq=seq, command="FORMAT_DISK", params={})
        publish(client, payload)
        time.sleep(1)
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
