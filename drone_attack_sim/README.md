# Attack simulator (PC -> ESP32 via HiveMQ)

Simulates malicious MQTT traffic against the DroneShield ESP32 gateway.
Requires the same broker credentials and HMAC key as `droneshield_ai/main/secrets.h`.

## Setup
1. Edit `config.py` to match your HiveMQ cluster + `DSHL_HMAC_KEY`.
2. `pip install -r requirements.txt`
3. Flash the ESP32 firmware and open serial monitor.

## Run
```bash
python attack_valid.py              # baseline, should be ACCEPTED
python attack_replay.py            # anti-replay rejection
python attack_bad_signature.py     # crypto rejection
python attack_malformed.py         # validator rejection
python attack_unknown_topic.py     # ignored (not subscribed)
python attack_duplicate_seq.py     # anti-replay rejection
python attack_flood.py             # rate limiter / AI quarantine
python attack_oversized_payload.py # oversize rejection
python run_all.py                  # all sequentially
```

Watch the ESP32 serial monitor for `[DECISION]` lines.
