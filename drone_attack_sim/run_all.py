"""Run all attacks sequentially."""
import time, subprocess, sys, os

scripts = [
    "attack_valid.py",
    "attack_replay.py",
    "attack_bad_signature.py",
    "attack_malformed.py",
    "attack_unknown_topic.py",
    "attack_duplicate_seq.py",
    "attack_flood.py",
    "attack_oversized_payload.py",
]

here = os.path.dirname(os.path.abspath(__file__))
for s in scripts:
    print(f"\n===== Running {s} =====")
    subprocess.run([sys.executable, os.path.join(here, s)], check=False)
    time.sleep(2)
print("\nAll attacks done.")
