#!/usr/bin/env python3
"""Collect a REAL dataset from live HiveMQ traffic (broker side).

Subscribes to the command topic (and optionally status/events), timestamps
every message, and writes 5-second feature windows into dataset.csv.

Use together with collect_serial.py:
  - MQTT side  -> message rate, payload size, invalid JSON, duplicates
  - serial side -> Wi-Fi/MQTT reconnects, UART errors, device decisions

Record sessions while you publish normal or attack traffic:

  Normal (label 0):
    python collect_mqtt.py --session s01_normal --label 0 --duration 120

  Attack bursts (label 1) — publish replays/invalid msgs while this runs:
    python collect_mqtt.py --session s10_replay --label 1 --duration 120

Env: DSHL_MQTT_HOST, DSHL_MQTT_USER, DSHL_MQTT_PASS  (or --host/--user/--pass)
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from pathlib import Path

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("pip install paho-mqtt", file=sys.stderr)
    raise SystemExit(2)

HERE = Path(__file__).resolve().parent
DEFAULT_OUT = HERE / "dataset.csv"

FEATURE_COLS = [
    "mqtt_msg_count",
    "avg_payload_len",
    "max_payload_len",
    "duplicate_count",
    "invalid_json_count",
    "unknown_topic_count",
    "invalid_command_count",
    "wifi_disconnect_count",
    "mqtt_reconnect_count",
    "uart_frame_error_count",
    "uart_bytes_per_second",
]
WINDOW_MS = 5000

# Device-side events we cannot see from the broker; filled from serial logs.
# Left at 0 here — merge both sources by collecting both and appending rows,
# or use collect_serial.py as the primary source for a single complete row set.


class Window:
    def __init__(self, start_ms: int):
        self.start_ms = start_ms
        self.mqtt_msg_count = 0
        self.payload_len_sum = 0
        self.max_payload_len = 0
        self.duplicate_count = 0
        self.invalid_json_count = 0
        self.unknown_topic_count = 0
        self.invalid_command_count = 0
        self.wifi_disconnect_count = 0
        self.mqtt_reconnect_count = 0
        self.uart_frame_error_count = 0
        self.uart_bytes = 0
        self._seen_payloads: set[str] = set()

    def add_msg(self, topic: str, payload: bytes, base_topic: str) -> None:
        self.mqtt_msg_count += 1
        n = len(payload)
        self.payload_len_sum += n
        self.max_payload_len = max(self.max_payload_len, n)

        key = payload.decode("utf-8", errors="replace")
        if key in self._seen_payloads:
            self.duplicate_count += 1
        else:
            self._seen_payloads.add(key)

        try:
            obj = json.loads(payload)
            if not isinstance(obj, dict):
                self.invalid_json_count += 1
            else:
                for field in ("device_id", "seq", "timestamp", "command",
                              "params", "signature"):
                    if field not in obj:
                        self.invalid_json_count += 1
                        break
                cmd = obj.get("command")
                allow = {"STATUS_REQUEST", "PING", "ARM", "DISARM", "SIM_RESET"}
                if not isinstance(cmd, str) or cmd not in allow:
                    self.invalid_command_count += 1
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.invalid_json_count += 1

        if topic != base_topic:
            self.unknown_topic_count += 1

    def row(self, session: str, label: int) -> dict:
        avg = (self.payload_len_sum / self.mqtt_msg_count) if self.mqtt_msg_count else 0.0
        return {
            "session_id": session,
            "label": label,
            "window_start_ms": self.start_ms,
            "mqtt_msg_count": self.mqtt_msg_count,
            "avg_payload_len": round(avg, 2),
            "max_payload_len": self.max_payload_len,
            "duplicate_count": self.duplicate_count,
            "invalid_json_count": self.invalid_json_count,
            "unknown_topic_count": self.unknown_topic_count,
            "invalid_command_count": self.invalid_command_count,
            "wifi_disconnect_count": self.wifi_disconnect_count,
            "mqtt_reconnect_count": self.mqtt_reconnect_count,
            "uart_frame_error_count": self.uart_frame_error_count,
            "uart_bytes_per_second": round(self.uart_bytes / (WINDOW_MS / 1000.0), 2),
        }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default=os.environ.get("DSHL_MQTT_HOST", ""))
    p.add_argument("--port", type=int, default=int(os.environ.get("DSHL_MQTT_PORT", "8883")))
    p.add_argument("--user", default=os.environ.get("DSHL_MQTT_USER", ""))
    p.add_argument("--password", default=os.environ.get("DSHL_MQTT_PASS", ""))
    p.add_argument("--base-topic", default="droneshield/device_01/commands")
    p.add_argument("--listen-topic", default=None,
                   help="default: <base-topic> plus siblings .../status and .../events")
    p.add_argument("--session", required=True)
    p.add_argument("--label", type=int, required=True, choices=[0, 1])
    p.add_argument("--duration", type=int, default=120)
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = p.parse_args()

    if not args.host or not args.user:
        print("Need --host/--user (or DSHL_MQTT_HOST / DSHL_MQTT_USER)", file=sys.stderr)
        return 2

    base = args.base_topic
    if args.listen_topic:
        topics = [args.listen_topic]
    else:
        prefix = base.rsplit("/", 1)[0]
        topics = [base, f"{prefix}/status", f"{prefix}/events"]

    windows: dict[int, Window] = {}
    t_end = time.time() + args.duration
    connected = {"ok": False, "drops": 0}

    def get_window(ts_ms: int) -> Window:
        slot = (ts_ms // WINDOW_MS) * WINDOW_MS
        if slot not in windows:
            windows[slot] = Window(slot)
        return windows[slot]

    def on_connect(c, u, f, rc, props=None):
        connected["ok"] = rc == 0
        for t in topics:
            c.subscribe(t, qos=1)

    def on_disconnect(c, u, f, rc, props=None):
        connected["ok"] = False
        connected["drops"] += 1

    def on_message(c, u, msg):
        ts = int(time.time() * 1000)
        get_window(ts).add_msg(msg.topic, msg.payload, base)

    client = mqtt.Client(client_id=f"cap_{args.session}", protocol=mqtt.MQTTv311)
    client.username_pw_set(args.user, args.password)
    client.tls_set()
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    print(f"Recording {args.duration}s from {args.host}")
    print(f"session={args.session} label={args.label} topics={topics}")
    print("Publish your test traffic now (normal rate, or attack bursts)...")

    try:
        client.connect(args.host, args.port, 30)
    except Exception as exc:  # noqa: BLE001
        print(f"connect failed: {exc}", file=sys.stderr)
        return 1

    client.loop_start()
    try:
        while time.time() < t_end:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopped early.")
    client.loop_stop()
    client.disconnect()

    rows = [windows[k].row(args.session, args.label) for k in sorted(windows)]
    if not rows:
        print("No messages captured — nothing published on the topics?",
              file=sys.stderr)
        return 1

    fieldnames = ["session_id", "label", "window_start_ms"] + FEATURE_COLS
    write_header = not args.output.exists()
    with args.output.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} windows -> {args.output}  (session={args.session})")
    print("Note: wifi/uart columns are 0 from MQTT capture — also run "
          "collect_serial.py for those features.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
