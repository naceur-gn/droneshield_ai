"""Baseline: a correctly signed, fresh command. Expected: ACCEPT + forwarded to UART."""
import time
from common import *

def main():
    client = connect_client("atk_valid")
    try:
        seq = int(time.time()) % 100000
        payload = make_payload(seq=seq, command="PING", params={})
        publish(client, payload)
        time.sleep(1)
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
