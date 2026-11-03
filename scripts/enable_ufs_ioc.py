#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

OLD = b'{"EnableUfsIOC", 0}'
NEW = b'{"EnableUfsIOC", 1}'


def transform(data):
    assert data.count(OLD) == 1, "Expected exactly one disabled EnableUfsIOC setting"
    updated = data.replace(OLD, NEW, 1)
    assert updated.count(NEW) == 1 and OLD not in updated
    return updated


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    before = args.source.read_bytes()
    after = transform(before)
    args.source.write_bytes(after)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({
        "setting": "EnableUfsIOC",
        "value": 1,
        "replacement_count": 1,
        "source_sha256_before": hashlib.sha256(before).hexdigest(),
        "source_sha256_after": hashlib.sha256(after).hexdigest(),
    }, indent=2) + "\n")


if __name__ == "__main__":
    main()
