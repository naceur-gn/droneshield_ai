"""Flood: many messages fast to trip rate limiter / AI. Expected: some REJECT (rate limit)."""
import time
from common import *

def main():
    client = connect_client("atk_flood")
    try:
        base = int(time.time()) % 100000
        for i in range(25):
            seq = base + i
            payload = make_payload(seq=seq, command="STATUS_REQUEST", params={})
            publish(client, payload)
            time.sleep(0.05)
        time.sleep(2)
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
