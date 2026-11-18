#!/usr/bin/env python3
"""End-to-end REFALL Lite campaign over SYNTHETIC fleet metadata.

Every step is a separate `refall-lite` CLI process, so the ArcticBase store is
closed and reopened between every action (restart/resume proof by construction).

Honesty constraints:
- Inputs are synthetic fixtures in examples/synthetic_fleet/ (hashes are
  sha256("SYNTHETIC-NOT-REAL:...")). No real firmware is analyzed.
- "Workers" here are deterministic simulations standing in for Hermes-routed
  Qwen/Claude lanes. No model is invoked; submissions say so.
- The independent check / replay is a real deterministic program
  (examples/synthetic_check.py) run over the synthetic metadata.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FLEET = HERE / "synthetic_fleet"
META = FLEET / "member-metadata.json"
SIM = "[simulated worker; no model invoked; synthetic metadata]"


class Runner:
    def __init__(self, workdir: Path, cli: str | None) -> None:
        self.workdir = workdir
        self.db = workdir / "arcticbase.sqlite"
        self.calls = 0
        self.log: list[dict] = []
        if cli:
            self.base = [cli]
            self.env = dict(os.environ)
        else:
            self.base = [sys.executable, "-m", "refall_lite"]
            self.env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT), os.environ.get("PYTHONPATH", "")]))
        self.metadata = json.loads(META.read_text())["members"]
        self.files = 0
        # Telemetry: every CLI child joins one run in <workdir>/logs unless the caller chose a log dir.
        self.env.setdefault("FIRMWARE_SPIDER_LOG_DIR", str(workdir / "logs"))
        self.env.setdefault("FIRMWARE_SPIDER_RUN_ID", f"run_example_{workdir.name.replace('.', '_')}_{os.getpid()}")

    def __call__(self, *args: str, ok: bool = True) -> Any:
        proc = subprocess.run([*self.base, "--db", str(self.db), *args], capture_output=True, text=True, env=self.env)
        self.calls += 1
        out = json.loads(proc.stdout) if proc.stdout.strip() else {}
        self.log.append({"args": list(args), "rc": proc.returncode})
        if ok and proc.returncode != 0:
            raise SystemExit(f"command failed: {args}\n{proc.stdout}\n{proc.stderr}")
        return out

    def write(self, obj: object, name: str | None = None) -> str:
        self.files += 1
        path = self.workdir / (name or f"in-{self.files:03d}.json")
        path.write_text(obj if isinstance(obj, str) else json.dumps(obj, sort_keys=True))
        return str(path)


def simulated_submission(job: dict, meta: dict) -> dict:
    """Deterministic stand-in for a Qwen/Claude worker result."""
    target = job["target_ref"]
    findings = []
    if job["target_type"] == "member":
        m = meta[target]
        summary = f"{SIM} {job['stage']} triage of {m['label']} ({m['kind']}, {m['size_bytes']} bytes)"
        evidence = [{"kind": "synthetic-strings", "ref": f"synthetic:{target}:strings", "claim": f"{len(m['synthetic_strings'])} strings"}]
        if job["stage"] == "middle" and any(s.startswith("SYNTH_DEFAULT_CRED=") for s in m["synthetic_strings"]):
            findings.append({
                "title": "Default credential string in web server (synthetic)",
                "vuln_class": "hardcoded-credential", "severity": "high",
                "description": "Model-style hypothesis: credential-like constant present in synthetic strings.",
                "evidence": [{"kind": "string-hit", "ref": f"synthetic:{target}:strings", "claim": "SYNTH_DEFAULT_CRED= present"}],
                "artifact_refs": [f"member:{target}"], "confidence": "low",
                "limitations": ["synthetic strings only", "no reachability analysis"],
                "tier": "validated",  # deliberately over-claims; REFALL Lite must downgrade to hypothesis
            })
        if job["stage"] == "middle" and "SYNTH_DEBUG_BANNER" in m["synthetic_strings"]:
            findings.append({
                "title": "Debug banner left enabled (synthetic)", "vuln_class": "info-leak", "severity": "info",
                "evidence": [{"kind": "string-hit", "ref": f"synthetic:{target}:strings", "claim": "debug banner"}],
                "artifact_refs": [f"member:{target}"], "confidence": "low", "limitations": ["synthetic strings only"],
            })
    else:
        summary = f"{SIM} inventory of image {target}"
        evidence = [{"kind": "synthetic-manifest", "ref": f"synthetic:{target}:manifest", "claim": "member list recorded"}]
    return {"schema": "refall-lite.submit.v1", "type": "job_result", "status": "done", "summary": summary,
            "evidence": evidence, "artifact_refs": [evidence[0]["ref"]], "confidence": "medium",
            "limitations": ["synthetic metadata only; simulated worker"], "findings": findings, "cost_units": 1}


def drain(r: Runner, cid: str, stage: str, worker: str, *, fail_first: bool = False) -> list[dict]:
    results, failed_once = [], False
    while True:
        claim = r("job", "claim", cid, "--worker", worker, "--stage", stage)
        if not claim["claimed"]:
            return results
        job = claim["job"]
        if fail_first and not failed_once:
            failed_once = True
            r("job", "fail", cid, job["id"], "--token", job["claim_token"], "--status", "provider_timeout",
              "--error", "simulated provider timeout (retry path demo)")
            continue
        packet = r("job", "packet", cid, job["id"])
        assert packet["protocol"] == "refall-lite.job.v1"
        sub = simulated_submission(job, r.metadata)
        text = "worker transcript...\n```refall-submit\n" + json.dumps(sub) + "\n```\n"
        res = r("job", "submit", cid, job["id"], "--token", job["claim_token"], "--file", r.write(text, f"sub-{job['id']}.md"))
        assert res["accepted"], res
        results.append(res)


def run_checker(r: Runner, member: str, tag: str) -> dict:
    out = r.workdir / f"check-{tag}.json"
    proc = subprocess.run([sys.executable, str(HERE / "synthetic_check.py"), "--metadata", str(META), "--member", member,
                           "--out", str(out)], capture_output=True, text=True)
    res = json.loads(proc.stdout)
    res["command"] = f"python3 examples/synthetic_check.py --metadata examples/synthetic_fleet/member-metadata.json --member {member}"
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--cli", help="path to an installed refall-lite console script (default: python -m refall_lite)")
    a = ap.parse_args()
    wd = Path(a.workdir)
    wd.mkdir(parents=True, exist_ok=True)
    r = Runner(wd, a.cli)
    checks: dict[str, bool] = {}

    for actor, kind in [("hermes", "supervisor"), ("qwen-spark", "model"), ("claude-lane", "model"),
                        ("synthetic-checker", "tool"), ("synthetic-replay", "tool")]:
        r("actor", "add", actor, "--kind", kind)
    cfg = {"budgets": {"run": {"max_claims": 40, "max_cost": 60}, "family:*": {"max_claims": 25, "max_cost": 40},
                       "artifact:*": {"max_claims": 4, "max_cost": 6}, "stage:deep": {"max_claims": 2, "max_cost": 4}},
           "max_attempts": 3, "lease_s": 3, "backoff_s": 0, "max_consecutive_failures": 4, "max_deep_selections": 1,
           "methodology_bundle": "ara-methodology-export (static bundle path reference only; not executed)"}
    cid = r("campaign", "create", "synthetic-acme-fleet", "--config", r.write(cfg), "--actor", "hermes")["id"]
    r("manifest", cid, "--run-id", "run-001", "--actor", "hermes",
      "--fields", r.write({"provider_roles": {"supervisor": "hermes", "worker": "qwen-spark (simulated)", "checker": "synthetic-checker"}}))

    # --- broad inventory --------------------------------------------------
    for name in ("ar-1.0", "ar-1.1", "ac-2.0"):
        r("image", "ingest", cid, "--file", str(FLEET / f"image-{name}.json"), "--actor", "hermes")
    r("job", "enqueue-images", cid, "--stage", "inventory", "--kind", "inventory", "--actor", "hermes")
    drain(r, cid, "inventory", "qwen-spark", fail_first=True)
    assert r("stage", "advance", cid, "--actor", "hermes")["advanced"]

    # --- crash/restart: claim, abandon, lease expires, resume reclaims ------
    r("job", "enqueue-members", cid, "--stage", "middle", "--kind", "triage", "--actor", "hermes")
    abandoned = r("job", "claim", cid, "--worker", "qwen-spark", "--stage", "middle")["job"]
    time.sleep(3.5)
    resumed = r("resume", cid, "--actor", "hermes")
    checks["lease_reclaimed_on_resume"] = abandoned["id"] in resumed["reclaimed"]
    late = r("job", "submit", cid, abandoned["id"], "--token", abandoned["claim_token"],
             "--file", r.write(simulated_submission(abandoned, r.metadata)))
    checks["stale_token_refused"] = not late["accepted"]

    # --- representative / middle-depth over unique members -------------------
    again = r("job", "enqueue-members", cid, "--stage", "middle", "--kind", "triage", "--actor", "hermes")
    checks["member_dedup_on_reenqueue"] = again["enqueued"] == 0 and again["deduplicated"] > 0
    middle = drain(r, cid, "middle", "qwen-spark")
    finding_ids = sorted({f for res in middle for f in res["finding_ids"]})
    findings = [r("finding", "show", f) for f in finding_ids]
    cred = next(f for f in findings if f["vuln_class"] == "hardcoded-credential")
    checks["overclaim_downgraded_to_hypothesis"] = cred["tier"] == "hypothesis"

    # late image in another family shipping the identical httpd member
    late_img = r("image", "ingest", cid, "--file", str(FLEET / "image-ac-2.1.json"), "--actor", "hermes")
    r("job", "enqueue-images", cid, "--stage", "inventory", "--kind", "inventory", "--actor", "hermes")
    drain(r, cid, "inventory", "qwen-spark")
    added = r("job", "enqueue-members", cid, "--stage", "middle", "--kind", "triage", "--actor", "hermes")
    drain(r, cid, "middle", "qwen-spark")
    occ = r("finding", "occurrences", cred["id"])
    checks["occurrence_propagated_to_late_image"] = "ac-2.1" in {o["image_name"] for o in occ} and len({o["family"] for o in occ}) == 2
    checks["late_image_only_new_members_enqueued"] = added["enqueued"] == late_img["new_members"]

    assert r("stage", "advance", cid, "--actor", "hermes")["advanced"]
    blocked = r("closeout", "check", cid)
    checks["closeout_blocked_before_validation"] = (not blocked["passed"]) and "material-findings-unvalidated" in blocked["blockers"]

    # --- evidence promotion ------------------------------------------------
    rcpt = r.write({"checker_kind": "deterministic_tool", "commands": ["model says so"], "summary": "model self-check"})
    refusals = [r("finding", "transition", cid, cred["id"], "--to", "independently_checked", "--actor", who,
                  "--receipt-type", "independent_check", "--receipt", rcpt)["accepted"] for who in ("qwen-spark", "claude-lane", "hermes")]
    refusals.append(r("finding", "transition", cid, cred["id"], "--to", "validated", "--actor", "synthetic-replay",
                      "--receipt-type", "deterministic_replay", "--receipt", rcpt)["accepted"])
    checks["model_only_promotion_refused"] = not any(refusals)

    member = cred["member_sha256"]
    chk = run_checker(r, member, "independent")
    res = r("finding", "transition", cid, cred["id"], "--to", "independently_checked", "--actor", "synthetic-checker",
            "--receipt-type", "independent_check", "--receipt", r.write({
                "checker_kind": "deterministic_tool", "commands": [chk["command"]],
                "artifact_refs": [f"check-output:sha256:{chk['output_sha256']}"],
                "summary": "deterministic rule matched synthetic string", "limitations": ["rule-based string match only"]}))
    checks["independent_check_accepted"] = res["accepted"]

    # selective deep work on the one member that earned it
    deep = r("stage", "select-deep", cid, member, "--actor", "hermes", "--reason", "independently checked credential hypothesis")
    cap = r("stage", "select-deep", cid, next(m for m in r.metadata if m != member), "--actor", "hermes", "--reason", "curiosity")
    checks["deep_selection_capped"] = deep["accepted"] and not cap["accepted"]
    drain(r, cid, "deep", "claude-lane")

    replays = [run_checker(r, member, f"replay-{i}") for i in (1, 2)]
    res = r("finding", "transition", cid, cred["id"], "--to", "validated", "--actor", "synthetic-replay",
            "--receipt-type", "deterministic_replay", "--receipt", r.write({
                "checker_kind": "deterministic_replay", "commands": [replays[0]["command"]],
                "artifact_refs": [f"replay-output:sha256:{x['output_sha256']}" for x in replays],
                "replays": [{"run_id": f"replay-{i}", "output_sha256": x["output_sha256"]} for i, x in enumerate(replays, 1)],
                "summary": "two deterministic replays, identical output"}))
    checks["replay_validated"] = res["accepted"]

    # --- fuzz-ready escalation (OSS-CRS optional, not run) -------------------
    harness = r.write({"artifact_refs": ["synthetic-harness:httpd-auth-parse.descriptor.json"],
                       "summary": "synthetic harness descriptor; illustrates readiness gate only"})
    req = r("escalation", "request", cid, member, "--finding", cred["id"], "--actor", "claude-lane", "--receipt", harness)
    appr = r("escalation", "approve", cid, req["action"]["id"], "--actor", "hermes", "--receipt",
             r.write({"evidence_refs": ["synthetic-harness:httpd-auth-parse.descriptor.json"], "summary": "approved for optional specialist lane"}))
    checks["escalation_gate"] = req["accepted"] and appr["accepted"] and appr["job"]["stage"] == "fuzz_ready"
    assert r("stage", "advance", cid, "--actor", "hermes")["advanced"]
    r("job", "cancel", cid, appr["job"]["id"], "--actor", "hermes", "--reason", "OSS-CRS lane optional; not executed in synthetic example")

    # resolve the operator-attention trail (none expected) and close out
    for act in r("pending", "list", cid):
        r("pending", "resolve", cid, act["id"], "--actor", "hermes", "--status", "done", "--receipt-type", "operator_decision",
          "--receipt", r.write({"evidence_refs": [act["title"]], "summary": "acknowledged in synthetic run"}))
    r("checkpoint", cid, "--stage", "deep", "--key", "deep:complete", "--hashes", r.write({"member:" + member: member}), "--actor", "hermes")
    r("manifest", cid, "--run-id", "run-001", "--actor", "hermes")
    r("report", "draft", cid, "--actor", "hermes")
    gate = r("closeout", "check", cid)
    closeout = r("closeout", "run", cid, "--actor", "hermes")
    ledger = r("ledger", "verify", cid)
    checks["ledger_ok"] = ledger["ok"]
    status = r("status", cid)

    # --- separate tiny campaign: run budget hard stop -----------------------
    bid = r("campaign", "create", "budget-demo", "--config", r.write({"budgets": {"run": {"max_claims": 1, "max_cost": 10}}}),
            "--actor", "hermes")["id"]
    for name in ("ar-1.0", "ar-1.1"):
        r("image", "ingest", bid, "--file", str(FLEET / f"image-{name}.json"), "--actor", "hermes")
    r("job", "enqueue-images", bid, "--stage", "inventory", "--kind", "inventory", "--actor", "hermes")
    one = drain(r, bid, "inventory", "qwen-spark")
    bstat = r("status", bid)
    checks["budget_stop_observed"] = len(one) == 1 and bstat["campaign"]["stop_reason"] == "budget_exhausted:run"

    middle_ok = status["jobs_by_stage"].get("middle", {}).get("succeeded", 0)
    summary = {
        "synthetic_only": True,
        "note": "Synthetic metadata + simulated workers + deterministic synthetic checker. No real firmware analyzed; no model invoked.",
        "campaign_id": cid,
        "cli_invocations": r.calls,
        "unique_members": status["unique_members"],
        "member_occurrences": status["member_occurrences"],
        "middle_jobs_succeeded": middle_ok,
        "jobs": status["jobs"],
        "findings": status["findings"],
        "validated_finding": {"id": cred["id"], "families": sorted({o["family"] for o in occ}),
                              "images": sorted({o["image_name"] for o in occ})},
        "closeout_gate_blockers_before": blocked["blockers"],
        "closeout": {"passed": closeout["passed"], "closeout_id": closeout["closeout_id"], "blockers": closeout["blockers"],
                     "warnings": [c["id"] for c in gate["checks"] if c["status"] == "warn"]},
        "ledger": ledger,
        "checks": checks,
        "store_sha256": hashlib.sha256(r.db.read_bytes()).hexdigest() if r.db.exists() else None,
    }
    (wd / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True))
    print(json.dumps({"passed": closeout["passed"] and all(checks.values()), "checks": checks, "cli_invocations": r.calls}, indent=1))
    return 0 if closeout["passed"] and all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
