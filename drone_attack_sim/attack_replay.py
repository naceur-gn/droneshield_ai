"""Replay attack: resend an old (seq,timestamp) message. Expected: REJECT (anti-replay)."""
import time
from common import *

def main():
    client = connect_client("atk_replay")
    try:
        seq = 42
        ts = int(time.time()) - 60  # stale timestamp
        payload = make_payload(seq=seq, timestamp=ts, command="STATUS_REQUEST", params={})
        # send twice
        publish(client, payload)
        time.sleep(0.5)
        publish(client, payload)
        time.sleep(1)
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
