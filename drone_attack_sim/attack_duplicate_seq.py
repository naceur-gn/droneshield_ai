"""Duplicate seq within session (replay of seq). Expected: REJECT (anti-replay)."""
import time
from common import *

def main():
    client = connect_client("atk_dupseq")
    try:
        seq = int(time.time()) % 100000
        p1 = make_payload(seq=seq, command="PING", params={})
        publish(client, p1)
        time.sleep(0.5)
        # new timestamp but same seq -> replay
        p2 = make_payload(seq=seq, timestamp=int(time.time()), command="PING", params={})
        publish(client, p2)
        time.sleep(1)
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
