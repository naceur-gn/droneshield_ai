"""Unknown topic publish (different device topic). Expected: ignored (not subscribed)."""
import time
from common import *

def main():
    client = connect_client("atk_unknowntopic")
    try:
        seq = int(time.time()) % 100000
        payload = make_payload(seq=seq, command="PING", params={})
        # publish to a topic the device does not subscribe to
        client.publish("droneshield/device_02/commands", __import__("json").dumps(payload), qos=1)
        print("[PUB] to device_02 topic (device_01 should ignore)")
        time.sleep(1)
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
