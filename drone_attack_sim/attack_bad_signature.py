"""Bad signature: tampered payload / wrong HMAC. Expected: REJECT (crypto)."""
import time
from common import *

def main():
    client = connect_client("atk_badsig")
    try:
        seq = int(time.time()) % 100000
        payload = make_payload(seq=seq, command="ARM", params={"mode": 1})
        # corrupt signature
        payload["signature"] = "0" * 64
        publish(client, payload)
        time.sleep(1)
        # tamper command after signing
        payload2 = make_payload(seq=seq+1, command="DISARM", params={})
        payload2["command"] = "ARM"  # mismatched signature
        publish(client, payload2)
        time.sleep(1)
    finally:
        client.loop_stop()
        client.disconnect()

if __name__ == "__main__":
    main()
