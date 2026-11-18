#!/usr/bin/env python3
"""Deterministic NON-MODEL checker over SYNTHETIC member metadata.

Stands in for a real deterministic tool (e.g. a strings/YARA rule). It reads
the synthetic fixture, applies a fixed rule, and writes canonical JSON output.
Same inputs => byte-identical output => identical SHA-256 across replays.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

RULE = "SYNTH_DEFAULT_CRED="


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--metadata", required=True)
    ap.add_argument("--member", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    meta = json.loads(Path(a.metadata).read_text())["members"][a.member]
    hits = [s for s in meta["synthetic_strings"] if s.startswith(RULE)]
    result = {"tool": "synthetic_check", "rule": RULE, "member_sha256": a.member, "label": meta["label"],
              "hits": hits, "matched": bool(hits), "synthetic": True}
    data = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    Path(a.out).write_bytes(data)
    print(json.dumps({"matched": bool(hits), "output_sha256": hashlib.sha256(data).hexdigest(), "out": a.out}))
    return 0 if hits else 1


if __name__ == "__main__":
    raise SystemExit(main())
