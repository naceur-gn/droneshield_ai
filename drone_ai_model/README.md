# AI model (offline training)

Python folder for the ESP32 decision tree. **Nothing here runs on the device** —
training happens on the PC; only the exported C tree is compiled into firmware.

**The dataset must be REAL** — captured from your ESP32 + HiveMQ during actual
normal and attack sessions. There is no committed synthetic CSV.

## Downloaded real dataset (MQTT_UAD)

A real public MQTT dataset is already fetched into external/:
- MQTT_UAD (Aveleira-Mata et al.) - real MQTT testbed, DoS/MitM/Intrusion attacks.
- Source: https://figshare.com/articles/dataset/24420958 (DOI 10.6084/m9.figshare.24420958)

Convert it to training rows:

```bash
python adapt_mqtt_uad.py      # -> dataset.csv (session_id + label + 11 features)
python train_model.py          # -> ../main/exported_model.c/.h
```

## Real data workflow

```
 ┌────────────────────────────┐     ┌─────────────────────────────┐
 │ ESP32 serial monitor       │     │ HiveMQ live traffic         │
 │ collect_serial.py          │     │ collect_mqtt.py             │
 │ (primary: all 11 features) │     │ (message rate / payload)    │
 └──────────────┬─────────────┘     └──────────────┬──────────────┘
                │  rows with session_id + label     │
                └──────────────┬────────────────────┘
                               ▼
                    ┌──────────────────────────────┐
                    │  ai_model/dataset.csv        │
                    └──────────────┬───────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │  python train_model.py       │
                    │  split BY SESSION            │
                    │  precision/recall/F1/FPR     │
                    └──────────────┬───────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │  ../main/exported_model.c/.h │  ← firmware
                    └──────────────┬───────────────┘
                                   ▼
                            idf.py build
```

### 1. Record sessions (each needs a unique `--session` id)

Flash the firmware first, open the device, then:

```bash
cd ai_model
pip install pyserial paho-mqtt

# --- NORMAL sessions (label 0) ---
# idle + occasional STATUS_REQUEST every few seconds, ~2 min each
python collect_serial.py --port COM5 --session s01_normal_idle   --label 0 --duration 120
python collect_serial.py --port COM5 --session s02_normal_cmds   --label 0 --duration 120

# --- ATTACK sessions (label 1) ---
# while recording, run your attacks (replay bursts, spoofed msgs, bad UART frames)
python collect_serial.py --port COM5 --session s10_replay_burst  --label 1 --duration 120
#   ... in another terminal: publish the same signed payload many times
python collect_serial.py --port COM5 --session s11_spoof_burst   --label 1 --duration 120
#   ... send garbage / bad-tag UART frames
python collect_serial.py --port COM5 --session s12_uart_malformed --label 1 --duration 120
```

Optional broker-side view (partial features only):

```bash
export DSHL_MQTT_HOST=... DSHL_MQTT_USER=... DSHL_MQTT_PASS=...
python collect_mqtt.py --session s01b_mqtt_normal --label 0 --duration 120
```

Or parse a saved monitor log:

```bash
python collect_serial.py --log capture.log --session s13_from_log --label 1
```

### 2. Train + export into firmware

```bash
python train_model.py
cd .. && idf.py build
```

## Requirements for a good dataset

- **≥ 2 sessions per class** (normal + attack) so `GroupShuffleSplit` can hold
  out whole sessions — never split random rows from one capture
- Every row has a unique `session_id` per recording
- `label`: `0` = normal, `1` = attack
- Feature order in the CSV must match `FEATURE_COLS` (same as
  `DSHL_FEATURE_NAMES` in `main/feature_extractor.h`)
- Do not feed secrets or passwords into the dataset

## Files

| File | Purpose |
|------|---------|
| `collect_serial.py` | **Primary.** Live serial or saved log → real 5 s windows |
| `collect_mqtt.py`   | Broker-side capture → message/payload features |
| `dataset.csv`       | Your real captures (created by collectors; not committed empty) |
| `train_model.py`    | Trains tree, prints metrics, writes `../main/exported_model.*` |
| `make_dataset.py`   | Synthetic data — **pipeline smoke-test only**, not for reported results |

## Rules

- The exported tree can only flag anomalies (ACCEPT → QUARANTINE in firmware).
  It can never override a rule-based REJECT.
- Report precision, recall, F1, confusion matrix and false-positive rate on
  **held-out sessions** — accuracy alone is not enough.
