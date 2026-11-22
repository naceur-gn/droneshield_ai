# DroneShield AI

Embedded security gateway for a drone simulator. An ESP32-S2 (ESP-IDF 5.5.x) receives signed MQTT commands over TLS (HiveMQ Cloud), validates them (schema + HMAC + anti-replay + rate limit + freshness), scores them with an on-device decision tree, and forwards only accepted commands to a UART-linked simulator. A PC-side ML pipeline trains the tree from real MQTT attack data, and a PC-side attack simulator exercises the gateway.

## Repository layout

```
simulator_drone/
├── droneshield_ai/          # Firmware (ESP-IDF project)
│   ├── main/                # All C source (see main/ order below)
│   ├── CMakeLists.txt
│   ├── sdkconfig.defaults   # target: esp32s2
│   └── README.md
├── drone_ai_model/          # Offline ML training (PC only)
│   ├── collect_serial.py    # capture real sessions from ESP32 serial
│   ├── collect_mqtt.py      # capture from HiveMQ
│   ├── adapt_mqtt_uad.py    # adapt public MQTT_UAD dataset
│   ├── train_model.py       # train + export tree to firmware
│   └── external/            # downloaded real datasets
├── drone_attack_sim/        # PC attack simulator (MQTT)
│   ├── common.py            # signing + publish helpers
│   ├── config.py            # broker + HMAC key (mirror secrets.h)
│   └── attack_*.py          # replay, bad sig, flood, ...
└── README.md                # this file
```

## Firmware pipeline (main/)

1. `app_config.h` / `secrets.h` — config + credentials
2. `main.c` — boot, tasks, queues
3. `wifi_manager` — Wi-Fi + SNTP
4. `mqtt_manager` — TLS MQTT subscribe to commands topic
5. `message_validator` — JSON parse + canonical params
6. `crypto_security` — HMAC-SHA256 verify
7. `rule_engine` — allowlist, rate limit, freshness
8. `anti_replay` + `nvs_store` — persisted last_seq, commit on accept
9. `feature_extractor` — 11 features over 5 s windows
10. `ai_model` + `exported_model` — decision tree inference (can only quarantine, never override reject)
11. `decision_manager` — combine rules/AI/NVS, decide, forward
12. `uart_gateway` — authenticated UART frame to simulator
13. `security_logger` — event + reason logging (no secrets)

## Build & flash

```bash
cd droneshield_ai
# set ESP-IDF env (idf_tools.py export), then:
idf.py set-target esp32s2
idf.py build
idf.py -p COMx flash monitor
```

Fill `main/secrets.h` with real Wi-Fi/MQTT/HMAC values first.

## Train the AI model

```bash
cd drone_ai_model
python adapt_mqtt_uad.py      # or collect_serial.py for your own captures
python train_model.py          # exports to ../droneshield_ai/main/exported_model.*
cd ../droneshield_ai && idf.py build
```

## Run attacks

```bash
cd drone_attack_sim
# edit config.py to match secrets.h
pip install -r requirements.txt
python run_all.py
```

Watch the ESP32 serial monitor for `[DECISION]` lines.

## Security notes

- Secrets live in `main/secrets.h` (gitignored). Never commit real keys.
- Anti-replay commits to NVS only on final ACCEPT (fail closed).
- AI can only turn ACCEPT into QUARANTINE; it never overrides a REJECT.
- Only accepted commands are forwarded to UART.
