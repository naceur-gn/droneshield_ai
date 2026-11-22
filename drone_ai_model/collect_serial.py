#!/usr/bin/env python3
"""Collect a REAL dataset from the ESP32 serial monitor.

Reads live from a COM port, or from a saved log file (idf.py monitor output),
parses [DECISION] / [EVENT] lines, and writes 5-second feature windows into
dataset.csv with a session_id and label you provide.

Record several sessions (normal + attack), each with a unique --session id:

  Normal (label 0):
    python collect_serial.py --port COM5 --session s01_normal --label 0 --duration 120
    python collect_serial.py --port COM5 --session s02_commands --label 0 --duration 120

  Attacks (label 1):
    python collect_serial.py --port COM5 --session s10_replay --label 1 --duration 120
    # run tools/replay_test.py (or publish bursts) while this is recording

  From a saved monitor log:
    python collect_serial.py --log capture.log --session s11_spoof --label 1

Then train:
    python train_model.py
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
import time
from pathlib import Path

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

# ESP-IDF log: I (1234567) SECURITY: [DECISION] ...
TS_RE = re.compile(r"[IWE]\s*\((\d+)\)")
DECISION_RE = re.compile(
    r"\[DECISION\]\s+(ACCEPT|REJECT|RATE_LIMIT|QUARANTINE)\s+"
    r"stage=\S+\s+reason=(\S+)\s+seq=(\d+)\s+cmd=(\S+)\s+len=(\d+)"
)
EVENT_RE = re.compile(r"\[EVENT\]\s+id=(\d+)\s+reason=(\S+)")
UART_RE = re.compile(r"\[UART_GW\].*(rejected|error|bad tag|replay|malformed)", re.I)


class Window:
    __slots__ = (
        "start_ms", "mqtt_msg_count", "payload_len_sum", "max_payload_len",
        "duplicate_count", "invalid_json_count", "unknown_topic_count",
        "invalid_command_count", "wifi_disconnect_count", "mqtt_reconnect_count",
        "uart_frame_error_count", "uart_bytes",
    )

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


class SessionRecorder:
    def __init__(self, session: str, label: int):
        self.session = session
        self.label = label
        self.windows: dict[int, Window] = {}
        self.mqtt_connect_seen = 0

    def _window(self, ts_ms: int) -> Window:
        slot = (ts_ms // WINDOW_MS) * WINDOW_MS
        if slot not in self.windows:
            self.windows[slot] = Window(slot)
        return self.windows[slot]

    def feed_line(self, line: str) -> None:
        m = TS_RE.search(line)
        ts = int(m.group(1)) if m else (max(self.windows) if self.windows else 0) + 100
        w = self._window(ts)

        m = DECISION_RE.search(line)
        if m:
            reason = m.group(2)
            plen = int(m.group(5))
            w.mqtt_msg_count += 1
            w.payload_len_sum += plen
            w.max_payload_len = max(w.max_payload_len, plen)
            if reason == "REPLAY":
                w.duplicate_count += 1
            if reason in ("BAD_JSON", "MISSING_FIELD", "BAD_TYPE"):
                w.invalid_json_count += 1
            if reason in ("UNKNOWN_COMMAND", "BAD_PARAMS"):
                w.invalid_command_count += 1
            return

        m = EVENT_RE.search(line)
        if m:
            eid = int(m.group(1))
            if eid == 101:            # WIFI_DISCONNECTED
                w.wifi_disconnect_count += 1
            elif eid == 200:          # MQTT_CONNECTED
                self.mqtt_connect_seen += 1
                if self.mqtt_connect_seen > 1:
                    w.mqtt_reconnect_count += 1
            elif eid in (201, 202):   # MQTT_DISCONNECTED / RECONNECT_ATTEMPT
                w.mqtt_reconnect_count += 1
            elif eid in (501, 502):   # UART frame error / rejected
                w.uart_frame_error_count += 1
                w.uart_bytes += 64
            elif eid == 203:          # MQTT_MSG_RECEIVED
                w.mqtt_msg_count += 1
            return

        if UART_RE.search(line):
            w.uart_frame_error_count += 1
            w.uart_bytes += 64

    def rows(self) -> list[dict]:
        return [self.windows[k].row(self.session, self.label)
                for k in sorted(self.windows)]


def append_rows(path: Path, rows: list[dict]) -> None:
    fieldnames = ["session_id", "label", "window_start_ms"] + FEATURE_COLS
    write_header = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if write_header:
            writer.writeheader()
        writer.writerows(rows)


def collect_from_file(path: Path, rec: SessionRecorder) -> None:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            rec.feed_line(line)


def collect_from_serial(port: str, baud: int, duration_s: int,
                        rec: SessionRecorder) -> None:
    try:
        import serial  # pyserial
    except ImportError:
        print("pip install pyserial", file=sys.stderr)
        raise SystemExit(2)

    ser = serial.Serial(port, baud, timeout=0.5)
    print(f"Recording {duration_s}s from {port} @ {baud} ...")
    print(f"session={rec.session} label={rec.label}  (Ctrl+C to stop early)")
    end = time.time() + duration_s
    try:
        while time.time() < end:
            raw = ser.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").rstrip()
            if line:
                rec.feed_line(line)
    except KeyboardInterrupt:
        print("\nStopped early.")
    finally:
        ser.close()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--port", help="serial port, e.g. COM5 or /dev/ttyUSB0")
    src.add_argument("--log", type=Path, help="saved idf.py monitor / serial log file")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--duration", type=int, default=120, help="seconds (live mode)")
    p.add_argument("--session", required=True, help="unique capture session id")
    p.add_argument("--label", type=int, required=True, choices=[0, 1],
                   help="0=normal, 1=attack")
    p.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = p.parse_args()

    rec = SessionRecorder(args.session, args.label)
    if args.log:
        if not args.log.exists():
            print(f"Not found: {args.log}", file=sys.stderr)
            return 1
        collect_from_file(args.log, rec)
    else:
        collect_from_serial(args.port, args.baud, args.duration, rec)

    rows = rec.rows()
    if not rows:
        print("No windows extracted — is the ESP32 printing [DECISION]/[EVENT] lines?",
              file=sys.stderr)
        return 1

    append_rows(args.output, rows)
    print(f"Wrote {len(rows)} windows -> {args.output}  (session={args.session})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
