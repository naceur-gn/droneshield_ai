#!/usr/bin/env python3
"""Convert real MQTT_UAD packet CSVs into DroneShield 5-second feature windows.

Source: MQTT_UAD (Aveleira-Mata et al.) — real MQTT testbed captures.
https://figshare.com/articles/dataset/24420958
Cite: MQTT_UAD, figshare DOI 10.6084/m9.figshare.24420958

Usage:
  python adapt_mqtt_uad.py            # uses external/MQTT_UAD_*.csv
  python adapt_mqtt_uad.py -o dataset.csv
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from collections import defaultdict
from pathlib import Path

WINDOW_S = 5.0
# Topics we treat as expected on the gateway (others count as unknown)
KNOWN_TOPICS = {
    "droneshield/device_01/commands",
    "droneshield/device_01/status",
    "droneshield/device_01/events",
    "droneshield/device_00/commands",
    "droneshield/device_00/status",
    "droneshield/device_00/events",
    "droneshield/device_02/commands",
    "droneshield/device_02/status",
    "droneshield/device_02/events",
    "sensors/temperature",
    "sensors/humidity",
    "home/livingroom/light",
    "home/kitchen/light",
}
# MQTT control packet types present in the capture
MSG_CONNECT = "1"
MSG_PUBLISH = "3"
MSG_DISCONNECT = "14"

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
    "label",
]


def open_rows(path: Path):
    # MQTT_UAD CSVs are quoted CSV with possible BOM
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        yield from csv.DictReader(f)


def adapt_file(path: Path, session_id: str) -> list[dict]:
    # bucket packets by 5s window of absolute capture time
    buckets: dict[int, dict] = defaultdict(
        lambda: {
            "t0": None,
            "t1": None,
            "mqtt_n": 0,
            "payloads": [],
            "dup": 0,
            "bad_json": 0,
            "unknown_topic": 0,
            "invalid_cmd": 0,
            "reconnect": 0,
            "attack_pkts": 0,
            "total_pkts": 0,
        }
    )

    for row in open_rows(path):
        try:
            t = float(row.get("frame.time_epoch") or 0)
        except ValueError:
            continue
        if t <= 0:
            continue
        label = (row.get("type") or "normal").strip().lower()
        is_attack = label not in ("normal", "benign", "")
        w = int(t // WINDOW_S)
        b = buckets[w]
        b["total_pkts"] += 1
        if b["t0"] is None:
            b["t0"] = w * WINDOW_S
        b["t1"] = t
        if is_attack:
            b["attack_pkts"] += 1

        msgtype = (row.get("mqtt.msgtype") or "").strip()
        if not msgtype:
            continue  # non-MQTT frame (ARP/TCP/etc.)

        b["mqtt_n"] += 1

        if msgtype == MSG_CONNECT:
            b["reconnect"] += 1
            # CONNECT flood is the DoS signature
            if is_attack:
                b["invalid_cmd"] += 1
            continue

        if msgtype == MSG_PUBLISH:
            try:
                mlen = int(float(row.get("mqtt.len") or 0))
            except ValueError:
                mlen = 0
            if mlen <= 0:
                # fall back to frame length if mqtt.len missing
                try:
                    mlen = int(float(row.get("frame.len") or 0))
                except ValueError:
                    mlen = 0
            b["payloads"].append(mlen)

            dup = (row.get("mqtt.dupflag") or "").strip()
            if dup in ("1", "True", "true"):
                b["dup"] += 1

            topic = (row.get("mqtt.topic") or "").strip()
            if topic and topic not in KNOWN_TOPICS:
                b["unknown_topic"] += 1
            elif not topic:
                b["unknown_topic"] += 1

            # Capture has no JSON payload text — approximate "bad command"
            # as attack-labelled publishes (malformed/injection traffic).
            if is_attack:
                b["invalid_cmd"] += 1
                # empty mqtt.msg on a PUBLISH under attack ≈ malformed body
                msg = (row.get("mqtt.msg") or "").strip()
                if not msg and mlen == 0:
                    b["bad_json"] += 1

    windows: list[dict] = []
    for w in sorted(buckets):
        b = buckets[w]
        if b["total_pkts"] < 3:
            continue  # skip nearly-empty windows
        payloads = b["payloads"]
        avg_pl = (sum(payloads) / len(payloads)) if payloads else 0.0
        max_pl = max(payloads) if payloads else 0
        # label window attack if a meaningful share of packets were malicious
        label = 1 if b["attack_pkts"] >= max(3, int(0.05 * b["total_pkts"])) else 0
        windows.append(
            {
                "session_id": session_id,
                "mqtt_msg_count": b["mqtt_n"],
                "avg_payload_len": round(avg_pl, 2),
                "max_payload_len": max_pl,
                "duplicate_count": b["dup"],
                "invalid_json_count": b["bad_json"],
                "unknown_topic_count": b["unknown_topic"],
                "invalid_command_count": b["invalid_cmd"],
                "wifi_disconnect_count": 0,  # not in this capture
                "mqtt_reconnect_count": b["reconnect"],
                "uart_frame_error_count": 0,  # not in this capture
                "uart_bytes_per_second": 0,  # not in this capture
                "label": label,
            }
        )
    return windows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    ap.add_argument(
        "--src",
        nargs="+",
        default=[
            here / "external" / "MQTT_UAD_DoS.csv",
            here / "external" / "MQTT_UAD_Intrusion.csv",
            here / "external" / "MQTT_UAD_MitM.csv",
        ],
        help="MQTT_UAD packet CSV files",
    )
    ap.add_argument("-o", "--output", default=here / "dataset.csv")
    args = ap.parse_args()

    all_rows: list[dict] = []
    for p in args.src:
        p = Path(p)
        if not p.exists():
            print(f"skip missing: {p}", file=sys.stderr)
            continue
        wins = adapt_file(p, p.stem)
        print(f"{p.name}: {len(wins)} windows (label1={sum(w['label'] for w in wins)})")
        all_rows.extend(wins)

    if not all_rows:
        print("No windows produced — check source CSVs.", file=sys.stderr)
        return 1

    out = Path(args.output)
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["session_id"] + FEATURE_COLS)
        w.writeheader()
        w.writerows(all_rows)

    n1 = sum(r["label"] for r in all_rows)
    print(f"Wrote {len(all_rows)} rows -> {out} (attack={n1}, normal={len(all_rows)-n1})")
    print("Source: MQTT_UAD, figshare DOI 10.6084/m9.figshare.24420958")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
