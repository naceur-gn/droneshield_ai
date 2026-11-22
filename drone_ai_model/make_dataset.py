#!/usr/bin/env python3
"""Generate a synthetic multi-session dataset.csv for pipeline bring-up.

Produces realistic 5-second feature windows for normal and attack sessions so
train_model.py can run before hardware captures exist.

REPLACE with real ESP32 logs once available:
  1. Save serial logs from normal / attack sessions
  2. Convert with the same window logic (see parse_log() below) or extend this
     script to read your log format
  3. Keep session_id distinct per capture so the group split is meaningful
"""
from __future__ import annotations

import csv
import random
from pathlib import Path

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
random.seed(42)


def normal_window() -> dict:
    n = random.randint(0, 4)
    avg = random.uniform(120, 200)
    return {
        "mqtt_msg_count": n,
        "avg_payload_len": round(avg, 2),
        "max_payload_len": int(avg + random.randint(0, 40)),
        "duplicate_count": 0,
        "invalid_json_count": 0,
        "unknown_topic_count": 0,
        "invalid_command_count": 0,
        "wifi_disconnect_count": 0,
        "mqtt_reconnect_count": 0,
        "uart_frame_error_count": random.randint(0, 1),
        "uart_bytes_per_second": round(random.uniform(0, 40), 2),
    }


def normal_reconnect_window() -> dict:
    w = normal_window()
    w["wifi_disconnect_count"] = 1
    w["mqtt_reconnect_count"] = 1
    return w


def replay_burst_window() -> dict:
    w = normal_window()
    w["mqtt_msg_count"] = random.randint(8, 15)
    w["duplicate_count"] = random.randint(5, 12)
    w["avg_payload_len"] = round(random.uniform(150, 190), 2)
    w["max_payload_len"] = random.randint(160, 200)
    return w


def spoof_burst_window() -> dict:
    w = normal_window()
    w["mqtt_msg_count"] = random.randint(6, 14)
    w["invalid_json_count"] = random.randint(2, 8)
    w["invalid_command_count"] = random.randint(1, 6)
    w["unknown_topic_count"] = random.randint(0, 3)
    return w


def uart_malformed_window() -> dict:
    w = normal_window()
    w["uart_frame_error_count"] = random.randint(8, 30)
    w["uart_bytes_per_second"] = round(random.uniform(400, 2000), 2)
    w["mqtt_msg_count"] = random.randint(0, 3)
    return w


def reconnect_storm_window() -> dict:
    w = normal_window()
    w["wifi_disconnect_count"] = random.randint(3, 6)
    w["mqtt_reconnect_count"] = random.randint(3, 6)
    return w


def write_session(writer: csv.DictWriter, session: str, label: int,
                  n: int, factory) -> None:
    base = random.randint(0, 10_000_000)
    for i in range(n):
        writer.writerow({
            "session_id": session,
            "label": label,
            "window_start_ms": base + i * WINDOW_MS,
            **factory(),
        })


def main() -> None:
    out = Path(__file__).resolve().parent / "dataset.csv"
    fieldnames = ["session_id", "label", "window_start_ms"] + FEATURE_COLS
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        # Normal sessions (multiple, so group split holds some out)
        write_session(writer, "s01_normal_idle", 0, 35, normal_window)
        write_session(writer, "s02_normal_commands", 0, 35, normal_window)
        write_session(writer, "s03_normal_reconnect", 0, 25, normal_reconnect_window)
        write_session(writer, "s04_normal_uart", 0, 30, normal_window)
        write_session(writer, "s05_normal_idle_2", 0, 30, normal_window)
        write_session(writer, "s06_normal_reconnect_2", 0, 20, normal_reconnect_window)

        # Attack sessions: each attack type appears in >= 2 sessions
        write_session(writer, "s10_replay_burst", 1, 25, replay_burst_window)
        write_session(writer, "s11_replay_burst_2", 1, 25, replay_burst_window)
        write_session(writer, "s12_spoof_tamper", 1, 25, spoof_burst_window)
        write_session(writer, "s13_spoof_tamper_2", 1, 25, spoof_burst_window)
        write_session(writer, "s14_uart_malformed", 1, 25, uart_malformed_window)
        write_session(writer, "s15_uart_malformed_2", 1, 25, uart_malformed_window)
        write_session(writer, "s16_reconnect_storm", 1, 20, reconnect_storm_window)
        write_session(writer, "s17_reconnect_storm_2", 1, 20, reconnect_storm_window)

    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
