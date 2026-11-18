"""MVP slice runner: brain-check gate -> hunt leads -> verify/promote.

The runner NEVER starts, stops or manages the brain (Spark). The only I/O it performs
itself is an HTTP GET health probe. If the brain is down it flags and idles.

Verify seam: ``verify_worker.run({"finding": <finding dict>, "target": {...}})`` is called
directly (no job) and must return a submission whose first ``findings`` entry carries
``rederived``. ``rea_facts`` come ONLY from the host-side ``rea_facts_fn(lite, cid, finding)`` (e.g. built on
``verify.host_rea_facts``); without it they are ``{}`` -> held. The verify model's own
``rea_facts`` are never read.
"""
from __future__ import annotations

import urllib.request

from .corpus_hunt import run_hunt_once
from .verify import promote_or_hold
from .worker import parse_submission


def _urllib_get(url: str, timeout_s: float) -> int:
    with urllib.request.urlopen(url, timeout=timeout_s) as resp:
        return resp.status


def brain_available(base_url: str, *, timeout_s: float = 10, probe=None) -> bool:
    """True iff GET <base_url>/models returns HTTP 200. Any error -> False."""
    probe = probe or _urllib_get
    try:
        return probe(base_url.rstrip("/") + "/models", timeout_s) == 200
    except Exception:
        return False


def _verify(lite, cid, finding, verify_worker, rea_facts_fn) -> tuple[dict, dict]:
    out = verify_worker.run({"finding": finding, "target": {"member_sha256": finding.get("member_sha256")}})
    payload, _ = parse_submission(out)
    entry = ((payload or {}).get("findings") or [{}])[0]
    rederived = entry.get("rederived") or {}
    rea_facts = rea_facts_fn(lite, cid, finding) if rea_facts_fn else {}
    return rederived, rea_facts


def run_slice(lite, cid: str, *, hunt_worker, verify_worker, base_url: str, verifier_actor: str,
              max_iters: int = 1000, probe=None, rea_facts_fn=None) -> dict:
    if not brain_available(base_url, probe=probe):
        return {"brain_unavailable": True, "hunted": 0, "promoted": 0, "held": 0, "finding_ids": []}
    hunted = promoted = held = 0
    fids: list[str] = []
    for _ in range(max_iters):
        res = run_hunt_once(lite, cid, hunt_worker, stage="middle")
        if not res.get("claimed"):
            break
        hunted += 1
        for fid in res.get("finding_ids") or []:
            finding = lite.get_finding(fid)
            if finding["tier"] != "hypothesis":
                continue
            fids.append(fid)
            try:
                rederived, rea_facts = _verify(lite, cid, finding, verify_worker, rea_facts_fn)
            except Exception:
                held += 1
                continue
            out = promote_or_hold(lite, cid, fid, actor=verifier_actor, claim=finding.get("claim") or {},
                                  rederived=rederived, rea_facts=rea_facts)
            promoted += bool(out["promoted"])
            held += not out["promoted"]
    return {"brain_unavailable": False, "hunted": hunted, "promoted": promoted, "held": held, "finding_ids": fids}
