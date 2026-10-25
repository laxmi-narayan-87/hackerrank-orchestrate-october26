#!/usr/bin/env python3
"""Normalize proposed actions so they never cite evidence that does not yet exist."""
import argparse
import csv
import json
from pathlib import Path

def normalize(path: Path) -> int:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = reader.fieldnames
        if fields != ["case_id", "deletion_status", "steps_json"]:
            raise SystemExit(f"{path}: unexpected header {fields!r}")
        rows = list(reader)

    changed = 0
    for row in rows:
        if row["deletion_status"] != "INCOMPLETE":
            continue
        steps = json.loads(row["steps_json"])
        for step in steps:
            # Findings describe observed evidence. Remediation and future verification
            # are proposed actions, not completed facts, so their evidence IDs must be blank.
            if step.get("phase") in {"REMEDIATION", "VERIFICATION"} and step.get("evidence_id"):
                step["evidence_id"] = ""
                changed += 1
        row["steps_json"] = json.dumps(steps, ensure_ascii=False, separators=(",", ":"))

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"{path}: cleared {changed} evidence IDs from proposed remediation/future-verification steps")
    return changed

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_path", type=Path)
    args = parser.parse_args()
    normalize(args.csv_path)
