"""Oversized payload (>512 bytes). Expected: dropped/rejected (oversize)."""
import time, json
from common import *

def main():
    client = connect_client("atk_oversize")
    try:
        seq = int(time.time()) % 100000
        big = "A" * 600
        payload = make_payload(seq=seq, command="STATUS_REQUEST", params={"blob": big})
        publish(client, payload)
        time.sleep(1)
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
