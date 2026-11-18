#!/usr/bin/env python3
"""Operator entry point for the DSR corpus-hunt MVP slice (live Spark + REA). Stdlib only.

Wires existing functions: ingest_firmware -> advance_to_middle -> enqueue_hunt -> run_slice.
Never starts Spark (run_slice only probes it). Runs on a host with opencode + REA + Ghidra.

rea_facts_fn (D1): promotion must rest on REAL REA tool output, never the verify model's
self-reported facts. ``no_model_rea_facts`` deliberately ignores the model and supplies no
facts, so ``promote_or_hold`` HOLDS every finding at ``hypothesis`` (fail-safe) until a
host-side REA fact extractor is plugged in via ``run(..., rea_facts_fn=...)``.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_BASE_URL = "http://127.0.0.1:8000/v1"  # any OpenAI-compatible endpoint
DEFAULT_MODEL = "local-model"
DEFAULT_PACK = ROOT / "examples" / "dsr_hunt_advisory_pack.json"
DEFAULT_REA_CMD = ["rea", "mcp"]  # must be on PATH, or set DSR_REA_COMMAND
# REA drives Ghidra; pass the install locations through when the caller has set them.
DEFAULT_REA_ENV = {k: os.environ[k] for k in ("GHIDRA_INSTALL_DIR", "JAVA_HOME") if k in os.environ}
OPERATOR, HUNTER, VERIFIER = "operator", "spark-hunt", "verifier"


def no_model_rea_facts(lite, cid, finding) -> dict:
    """Fail-safe: supply NO facts (never the model's own), so nothing is promoted."""
    return {}


def run(target: str, technique: str, *, base_url: str = DEFAULT_BASE_URL, model: str = DEFAULT_MODEL,
        pack: str | Path = DEFAULT_PACK, out_dir: str | None = None, db: str = ":memory:",
        rea_command: list[str] | None = None, rea_env: dict | None = None, timeout_s: int = 900,
        max_iters: int = 3, rea_facts_fn=no_model_rea_facts, probe=None) -> dict:
    from refall_lite import RefallLite
    from refall_lite.corpus_hunt import advance_to_middle, enqueue_hunt, ingest_firmware
    from refall_lite.corpus_hunt_runner import run_slice
    from refall_lite.opencode_worker import OpenCodeWorker
    from refall_lite.verify import VerifyWorker

    out_dir = out_dir or tempfile.mkdtemp(prefix="dsr-slice-")
    rea_command = rea_command or DEFAULT_REA_CMD
    rea_env = DEFAULT_REA_ENV if rea_env is None else rea_env
    bundle = json.loads(Path(pack).read_text())
    lite = RefallLite(db)
    lite.register_actor(OPERATOR, kind="supervisor")
    lite.register_actor(HUNTER, kind="model", provider="spark")
    lite.register_actor(VERIFIER, kind="tool")
    cfg = {"methodology_bundle": bundle}
    try:
        from tests.helpers import base_config  # richer default config when available
        cfg = base_config(methodology_bundle=bundle)
    except Exception:
        pass
    cid = lite.create_campaign("mvp-slice", config=cfg, actor=OPERATOR)["id"]
    ing = ingest_firmware(lite, cid, target, out_dir, actor=OPERATOR)
    if ing["escalation"] or not ing["members"]:
        return {"cid": cid, "lite": lite, "ingest": ing, "result": None, "findings": []}
    advance_to_middle(lite, cid, ing["image_id"], actor=OPERATOR, worker_id=HUNTER)
    enqueue_hunt(lite, cid, ing["members"][0]["sha256"], technique_id=technique, actor=OPERATOR)
    common = dict(model=model, base_url=base_url, api_key=os.environ.get("DSR_SPARK_API_KEY", "not-needed"), rea_command=rea_command,
                  rea_env=rea_env, workdir_for=lambda packet: out_dir, timeout_s=timeout_s)
    result = run_slice(lite, cid, hunt_worker=OpenCodeWorker(HUNTER, **common),
                       verify_worker=VerifyWorker("spark-verify", **common), base_url=base_url,
                       verifier_actor=VERIFIER, max_iters=max_iters, probe=probe,
                       rea_facts_fn=rea_facts_fn)
    return {"cid": cid, "lite": lite, "ingest": ing, "result": result, "findings": lite.list_findings(cid)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run the DSR corpus-hunt MVP slice on one image.")
    ap.add_argument("--target", required=True, help="firmware/ELF image path")
    ap.add_argument("--technique", required=True, help="methodology technique id")
    ap.add_argument("--base-url", default=os.environ.get("DSR_SPARK_BASE_URL", DEFAULT_BASE_URL))
    ap.add_argument("--model", default=os.environ.get("DSR_SPARK_MODEL", DEFAULT_MODEL))
    ap.add_argument("--pack", default=str(DEFAULT_PACK), help="methodology pack JSON")
    ap.add_argument("--out-dir", default=None, help="unpack dir (default: fresh temp dir)")
    ap.add_argument("--db", default=":memory:")
    ap.add_argument("--timeout-s", type=int, default=900, help="per-lead opencode timeout")
    ap.add_argument("--max-iters", type=int, default=3)
    a = ap.parse_args(argv)
    env_cmd = os.environ.get("DSR_REA_COMMAND")
    env_env = os.environ.get("DSR_REA_ENV_JSON")
    out = run(a.target, a.technique, base_url=a.base_url, model=a.model, pack=a.pack, out_dir=a.out_dir,
              db=a.db, timeout_s=a.timeout_s, max_iters=a.max_iters,
              rea_command=env_cmd.split() if env_cmd else None,
              rea_env=json.loads(env_env) if env_env else None)
    print("ingest:", {k: v for k, v in out["ingest"].items() if k != "members"},
          "members:", len(out["ingest"]["members"]))
    print("result:", out["result"])
    for f in out["findings"]:
        print(f"finding {f['id']} tier={f['tier']} title={f.get('title')!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
