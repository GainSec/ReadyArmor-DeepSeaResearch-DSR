"""Live end-to-end slice (real model endpoint + opencode + REA). Needs all three on the host
and DSR_TARGET set to a binary to hunt: pytest -m live.

D1 note: rea_facts_fn is the fail-safe ``no_model_rea_facts`` (no facts supplied, model
self-reports ignored), so the asserted outcome is: finding stays ``hypothesis`` (held) and
nothing is promoted without matched mechanical facts.
"""
import importlib.util
import os
from pathlib import Path

import pytest

from refall_lite.corpus_hunt_runner import brain_available

pytestmark = pytest.mark.live
SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "run_mvp_slice.py"
BASE_URL = os.environ.get("DSR_SPARK_BASE_URL", "http://127.0.0.1:8000/v1")
MODEL = os.environ.get("DSR_SPARK_MODEL", "local-model")
TARGET = os.environ.get("DSR_TARGET", "")
TECHNIQUE = os.environ.get("DSR_TECHNIQUE", "ghidra_initial_auto_analysis")


def _script():
    spec = importlib.util.spec_from_file_location("run_mvp_slice", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_live_slice_end_to_end(tmp_path):
    if not os.path.exists(TARGET):
        pytest.skip(f"target not staged: {TARGET}")
    if not brain_available(BASE_URL):
        pytest.skip(f"Spark unavailable at {BASE_URL}")
    mod = _script()
    out = mod.run(TARGET, TECHNIQUE, base_url=BASE_URL, model=MODEL, out_dir=str(tmp_path / "unpack"),
                  rea_command=(os.environ.get("DSR_REA_COMMAND") or "").split() or None,
                  timeout_s=900, max_iters=2, rea_facts_fn=mod.no_model_rea_facts)
    assert not out["ingest"]["escalation"] and out["ingest"]["members"]
    res = out["result"]
    assert res and not res["brain_unavailable"] and res["hunted"] >= 1
    findings = out["findings"]
    assert findings, "no candidate finding produced"
    for f in findings:
        assert f["evidence"], "candidate must carry evidence citing REA output"
        # deterministic: held at hypothesis (no real REA facts supplied -> never promoted)
        assert f["tier"] == "hypothesis"
    assert res["promoted"] == 0 and res["held"] == len(res["finding_ids"])
