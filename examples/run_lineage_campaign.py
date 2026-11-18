#!/usr/bin/env python3
"""End-to-end lineage / knowledge-reuse campaign over SYNTHETIC metadata, driven through the CLI.

What it demonstrates:
- exact duplicate content at different paths/images (tier 0) -> one content object, all occurrences
- non-identical httpd builds clustered by multi-signal lineage evidence into one code family
- false candidates: metadata-only (rtspd) rejected automatically; fuzzy-only (webd) edges rejected by the operator
- representative selection, representative receipt reuse, bounded delta jobs, full-repeat refusal
- applicability gating per occurrence/variant (applicable vs not_present), finding never duplicated
- negative-result reuse only with proven code+config digest equivalence
- one shared attack-chain node with product-specific reachability (router confirmed, cam refuted, nas refused)
- fingerprint algorithm version change staling derived reuse so it can no longer skip work

Honesty: inputs are synthetic fixtures (sha256("SYNTHETIC-NOT-REAL:...")), workers are deterministic
simulations, fingerprints are pre-written synthetic observations standing in for an external analyzer.
No real firmware is analyzed and no model is invoked.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from run_synthetic_campaign import Runner  # noqa: E402

FLEET = HERE / "lineage_fleet"
META = FLEET / "member-metadata.json"
SIM = "[simulated worker; no model invoked; synthetic metadata]"


def h(label: str) -> str:
    return hashlib.sha256(f"SYNTHETIC-NOT-REAL:{label}".encode()).hexdigest()


def scoped(fps: dict, sha: str) -> dict[str, str]:
    return {o["value"]["scope"]: o["value"]["digest"] for o in fps[sha] if o["kind"] == "scoped_digest"}


def result(summary: str, **extra: Any) -> dict:
    out = {"schema": "refall-lite.submit.v1", "type": "job_result", "status": "done", "summary": f"{SIM} {summary}",
           "evidence": [{"kind": "synthetic", "ref": "synthetic:lineage-fixture", "claim": summary}],
           "artifact_refs": ["synthetic:lineage-fixture"], "confidence": "medium",
           "limitations": ["synthetic metadata only; simulated worker"], "cost_units": 1}
    out.update(extra)
    return out


def drain(r: Runner, cid: str, stage: str, worker: str, make) -> list[dict]:
    out = []
    while True:
        c = r("job", "claim", cid, "--worker", worker, "--stage", stage)
        if not c["claimed"]:
            return out
        job = c["job"]
        res = r("job", "submit", cid, job["id"], "--token", job["claim_token"], "--file", r.write(make(job)))
        assert res["accepted"], res
        out.append(res)


def run_checker(member: str, tag: str, workdir: Path) -> dict:
    out = workdir / f"check-{tag}.json"
    proc = subprocess.run([sys.executable, str(HERE / "synthetic_check.py"), "--metadata", str(META), "--member", member,
                           "--out", str(out)], capture_output=True, text=True)
    res = json.loads(proc.stdout)
    res["command"] = f"python3 examples/synthetic_check.py --metadata examples/lineage_fleet/member-metadata.json --member {member}"
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--cli")
    a = ap.parse_args()
    wd = Path(a.workdir)
    wd.mkdir(parents=True, exist_ok=True)
    r = Runner(wd, a.cli)
    meta = json.loads(META.read_text())["members"]
    batches = json.loads((FLEET / "fingerprints.json").read_text())["batches"]
    fps = {b["content_sha256"]: b["observations"] for b in batches}
    A, B, C = h("member:httpd-3.2-buildA"), h("member:httpd-3.2-buildB"), h("member:httpd-3.2-buildC")
    BB, RT, WEBD = h("member:busybox-1.36"), h("member:rtspd-1.0"), h("member:webd-0.9")
    checks: dict[str, bool] = {}
    rc = lambda **kw: r.write({"commands": [kw.pop("cmd", "synthetic deterministic check")], **kw})

    for actor, kind in [("hermes", "supervisor"), ("qwen-spark", "model"), ("claude-lane", "model"), ("fp-tool", "tool"),
                        ("synthetic-checker", "tool"), ("synthetic-replay", "tool")]:
        r("actor", "add", actor, "--kind", kind)
    cfg = {"budgets": {"run": {"max_claims": 60, "max_cost": 80}, "stage:deep": {"max_claims": 10, "max_cost": 20}},
           "max_attempts": 2, "lease_s": 60, "backoff_s": 0, "lineage": {"max_delta_items": 10, "max_delta_jobs": 20}}
    cid = r("campaign", "create", "synthetic-lineage-fleet", "--config", r.write(cfg), "--actor", "hermes")["id"]
    r("manifest", cid, "--run-id", "lineage-run-001", "--actor", "hermes")
    for name in ("lr-1.0", "lr-1.1", "lc-2.0", "ln-1.0"):
        r("image", "ingest", cid, "--file", str(FLEET / f"image-{name}.json"), "--actor", "hermes")

    # broad inventory + middle-depth over unique content objects (tier 0)
    r("job", "enqueue-images", cid, "--stage", "inventory", "--kind", "inventory", "--actor", "hermes")
    drain(r, cid, "inventory", "qwen-spark", lambda j: result(f"inventory {j['target_ref']}"))
    assert r("stage", "advance", cid, "--actor", "hermes")["advanced"]
    mid = r("job", "enqueue-members", cid, "--stage", "middle", "--kind", "triage", "--actor", "hermes")

    def middle(job):
        m = meta[job["target_ref"]]
        findings = []
        if any(s.startswith("SYNTH_DEFAULT_CRED=") for s in m["synthetic_strings"]):
            findings.append({"title": "Default credential bypass in parse_auth (synthetic)", "vuln_class": "hardcoded-credential",
                             "severity": "high", "evidence": [{"kind": "string-hit", "ref": f"synthetic:{job['target_ref']}:strings",
                                                               "claim": "SYNTH_DEFAULT_CRED= present"}],
                             "artifact_refs": [f"member:{job['target_ref']}"], "confidence": "low",
                             "limitations": ["synthetic strings only"]})
        return result(f"middle triage of {m['label']}", findings=findings)

    mres = drain(r, cid, "middle", "qwen-spark", middle)
    finding_id = next(f for x in mres for f in x["finding_ids"])
    bb = r("lineage", "show", cid, BB)
    checks["exact_duplicate_one_content_all_occurrences"] = (bb["tier0"]["occurrence_count"] == 4 and mid["enqueued"] == 6
                                                             and any(o["container"] == "rescue.img" for o in bb["occurrences"]))

    # fingerprint (external analyzer stand-in) -> scheduler insists on clustering before deep
    r("lineage", "ingest", cid, "--file", r.write(batches), "--actor", "fp-tool")
    gate = r("stage", "advance", cid, "--actor", "hermes")
    checks["cluster_required_before_deep"] = (not gate["advanced"]) and "lineage pass" in " ".join(gate["reasons"])
    lp = r("lineage", "pass", cid, "--actor", "hermes")
    checks["metadata_only_candidates_rejected"] = lp["metadata_only_rejected"] >= 1 and len(lp["families_proposed"]) == 1
    unit = lambda sha: r("lineage", "units", cid, "--content", sha)[0]["id"]
    uA, uB, uC, uW, uR = unit(A), unit(B), unit(C), unit(WEBD), unit(RT)
    edges = r("lineage", "edges", cid)
    webd_edges = [e for e in edges if uW in (e["unit_a"], e["unit_b"])]
    checks["rtspd_never_paired"] = not any(uR in (e["unit_a"], e["unit_b"]) for e in edges)
    for e in webd_edges:
        assert not e["policy_passed"]
        rej = r("lineage", "edge-reject", cid, e["id"], "--actor", "hermes", "--receipt-type", "lineage_review",
                "--receipt", r.write({"evidence_refs": ["single fuzzy function-hash overlap; different package/sources"],
                                      "summary": "false lineage candidate"}))
        assert rej["accepted"]
    checks["false_fuzzy_candidates_rejected"] = bool(webd_edges) and all(
        e["status"] == "rejected" for e in r("lineage", "edges", cid, "--unit", uW))
    fam = lp["families_proposed"][0]
    approved = r("lineage", "approve", cid, fam, "--actor", "hermes")
    family = approved["family"]
    members = {m["code_unit_id"] for m in family["members"] if m["status"] == "approved"}
    checks["non_identical_builds_one_family"] = approved["accepted"] and members == {uA, uB, uC}
    rep = family["representative_unit_id"]
    checks["representative_selected_with_rationale"] = rep == uA and bool(family["representative_rationale"]["scores"])
    assert r("stage", "advance", cid, "--actor", "hermes")["advanced"]

    # representative full analysis -> receipt -> bounded deltas for variants
    p1 = r("lineage", "plan", cid, "--actor", "hermes")
    rep_digests = scoped(fps, A)
    drain(r, cid, "deep", "claude-lane", lambda j: result(
        "representative deep analysis: upload_handler reviewed, no injection", outcome="negative",
        checked_scope=["code:upload_handler", "config:httpd.conf"],
        checked_digests={"code:upload_handler": rep_digests["code:upload_handler"], "config:httpd.conf": rep_digests["config:httpd.conf"]}))
    p2 = r("lineage", "plan", cid, "--actor", "hermes")
    p3 = r("lineage", "plan", cid, "--actor", "hermes")
    deltas = r("lineage", "deltas", cid)
    checks["one_representative_bounded_deltas"] = (len(p1["representative_jobs"]) == 1 and len(p2["delta_jobs"]) == 2
                                                   and p3["delta_jobs"] == [] and all(len(d["payload"]["delta_items"]) <= 10 for d in deltas))
    full = r("stage", "select-deep", cid, C, "--actor", "hermes", "--reason", "full repeat?")
    checks["full_repeat_refused_for_variant"] = (not full["accepted"]) and "delta" in " ".join(full["reasons"])

    def delta(job):
        v = job["target_ref"]
        same = scoped(fps, v)["code:parse_auth"] == rep_digests["code:parse_auth"]
        return result(f"delta check vs representative ({len(job['payload']['delta_items'])} items)",
                      delta={"outcome": "consistent" if same else "diverged", "changed_items": [] if same else ["code:parse_auth"]})

    drain(r, cid, "deep", "qwen-spark", delta)
    drc = {d["variant_unit_id"]: d["outcome"] for d in r("lineage", "receipts", cid, "--delta")}
    checks["delta_receipts"] = drc == {uB: "consistent", uC: "diverged"}

    # promote the finding on its origin (A) with deterministic non-model checks
    chk = run_checker(A, "independent", wd)
    r("finding", "transition", cid, finding_id, "--to", "independently_checked", "--actor", "synthetic-checker",
      "--receipt-type", "independent_check", "--receipt", r.write({"checker_kind": "deterministic_tool", "commands": [chk["command"]],
                                                                  "artifact_refs": [f"check-output:sha256:{chk['output_sha256']}"]}))
    reps = [run_checker(A, f"replay-{i}", wd) for i in (1, 2)]
    val = r("finding", "transition", cid, finding_id, "--to", "validated", "--actor", "synthetic-replay",
            "--receipt-type", "deterministic_replay", "--receipt", r.write({
                "checker_kind": "deterministic_replay", "commands": [reps[0]["command"]],
                "artifact_refs": [f"replay-output:sha256:{x['output_sha256']}" for x in reps],
                "replays": [{"run_id": f"r{i}", "output_sha256": x["output_sha256"]} for i, x in enumerate(reps, 1)]}))
    assert val["accepted"], val

    # propagate: candidate-only on variants until gates pass
    prop = r("applicability", "propagate", cid, finding_id, "--actor", "hermes")
    rows = {row["content_sha256"]: row for row in prop["rows"]}
    checks["propagated_rows_candidate_only"] = (len(rows) == 3 and all(x["state"] == "candidate_applicable" and not x["validated_on_target"]
                                                                       for x in rows.values()))
    r("report", "draft", cid, "--actor", "hermes")
    blocked = r("closeout", "check", cid)
    checks["closeout_blocked_by_candidate_applicability"] = "applicability-unresolved" in blocked["blockers"]
    model_try = r("applicability", "check", cid, rows[B]["id"], "--gate", "code_path", "--status", "passed", "--actor", "qwen-spark",
                  "--receipt", rc())
    checks["model_cannot_pass_gates"] = not model_try["accepted"]
    for g in ("configuration", "exposure", "preconditions"):
        r("applicability", "check", cid, rows[A]["id"], "--gate", g, "--status", "passed", "--actor", "synthetic-checker", "--receipt", rc())
    for g in ("code_path", "version_constraints", "configuration", "exposure", "preconditions"):
        last = r("applicability", "check", cid, rows[B]["id"], "--gate", g, "--status", "passed", "--actor", "synthetic-checker",
                 "--receipt", rc(cmd=f"synthetic {g} check against delta receipt"))
    r("applicability", "check", cid, rows[C]["id"], "--gate", "code_path", "--status", "failed", "--actor", "synthetic-checker",
      "--receipt", rc(cmd="delta receipt: parse_auth rewritten"))
    neg = r("applicability", "decide", cid, rows[C]["id"], "--state", "not_present", "--actor", "synthetic-checker",
            "--receipt-type", "applicability_check", "--receipt", rc(cmd="delta diverged on code:parse_auth"))
    final = {x["content_sha256"]: x for x in r("applicability", "list", cid, "--finding", finding_id)}
    checks["applicability_gated_per_variant"] = (last["row"]["state"] == "applicable" and final[A]["state"] == "applicable"
                                                 and neg["accepted"] and final[C]["state"] == "not_present"
                                                 and final[B]["validated_on_target"] and not final[C]["validated_on_target"])
    checks["finding_never_duplicated"] = len(r("finding", "list", cid)) == 1

    # negative-result reuse only with code+config equivalence
    receipt = next(x for x in r("lineage", "receipts", cid, "--unit", uA) if x["analysis_kind"] == "full")
    okB = r("lineage", "reuse-negative", cid, receipt["id"], uB, "--actor", "hermes")
    noC = r("lineage", "reuse-negative", cid, receipt["id"], uC, "--actor", "hermes")
    checks["negative_reuse_requires_equivalence"] = okB["accepted"] and not noC["accepted"] and "config:httpd.conf" in " ".join(noC["reasons"])

    # shared attack-chain node, product-specific reachability
    shared = r("chain", "node", cid, "--actor", "hermes", "--kind", "component_weakness", "--label", "parse_auth default credential",
               "--scope", "shared", "--family", fam, "--finding", finding_id)
    wan = r("chain", "node", cid, "--actor", "hermes", "--kind", "entry_point", "--label", "WAN admin portal", "--scope", "product",
            "--product", "router")
    edge = r("chain", "edge", cid, wan["id"], shared["id"], "--actor", "hermes", "--relation", "reaches",
             "--preconditions", r.write(["httpd listens on WAN interface", "admin portal enabled by default"]))
    for p in edge["preconditions"]:
        res = r("chain", "check", cid, p["id"], "--state", "satisfied", "--actor", "synthetic-checker", "--receipt", rc(cmd="synthetic config read"))
    cam = r("chain", "reuse", cid, shared["id"], "--product", "cam", "--entry-label", "LAN web UI", "--actor", "hermes", "--template", edge["id"])
    cam_chk = r("chain", "check", cid, cam["edge"]["preconditions"][0]["id"], "--state", "unsatisfied", "--actor", "synthetic-checker",
                "--receipt", rc(cmd="synthetic: cam httpd bound to LAN only"))
    nas = r("chain", "reuse", cid, shared["id"], "--product", "nas", "--entry-label", "x", "--actor", "hermes", "--template", edge["id"])
    view = r("chain", "show", cid)
    checks["shared_node_product_specific_reachability"] = (
        res["edge"]["status"] == "confirmed" and cam["accepted"] and cam_chk["edge"]["status"] == "refuted"
        and not nas["accepted"] and len([n for n in view["nodes"] if n["scope"] == "shared"]) == 1
        and next(n for n in view["nodes"] if n["id"] == shared["id"])["status"] == "confirmed")

    for act in r("pending", "list", cid):
        r("pending", "resolve", cid, act["id"], "--actor", "hermes", "--status", "done", "--receipt-type", "operator_decision",
          "--receipt", r.write({"evidence_refs": [act["title"]]}))
    r("report", "draft", cid, "--actor", "hermes")
    gate = r("closeout", "check", cid)
    closeout = r("closeout", "run", cid, "--actor", "hermes")
    report = r("report", "show", cid)["content"]["lineage"]
    checks["report_marks_candidate_edges_and_rows"] = all("candidate_only" in e for e in report["attack_chain"]["edges"])
    checks["ledger_ok"] = r("ledger", "verify", cid)["ok"]

    # second campaign: algorithm version change stales derived reuse; work can no longer be skipped
    sid = r("campaign", "create", "lineage-staleness-demo", "--config", r.write(cfg), "--actor", "hermes")["id"]
    r("image", "ingest", sid, "--file", str(FLEET / "image-lr-1.0.json"), "--actor", "hermes")
    r("image", "ingest", sid, "--file", str(FLEET / "image-lr-1.1.json"), "--actor", "hermes")
    r("job", "enqueue-images", sid, "--stage", "inventory", "--kind", "inventory", "--actor", "hermes")
    drain(r, sid, "inventory", "qwen-spark", lambda j: result("inventory"))
    r("stage", "advance", sid, "--actor", "hermes")
    r("job", "enqueue-members", sid, "--stage", "middle", "--kind", "triage", "--actor", "hermes")
    drain(r, sid, "middle", "qwen-spark", lambda j: result("triage"))
    r("lineage", "ingest", sid, "--file", r.write([b for b in batches if b["content_sha256"] in (A, B)]), "--actor", "fp-tool")
    sfam = r("lineage", "pass", sid, "--actor", "hermes")["families_proposed"][0]
    r("lineage", "approve", sid, sfam, "--actor", "hermes")
    r("stage", "advance", sid, "--actor", "hermes")
    r("lineage", "plan", sid, "--actor", "hermes")
    drain(r, sid, "deep", "claude-lane", lambda j: result("representative", outcome="negative"))
    sdel = r("lineage", "plan", sid, "--actor", "hermes")["delta_jobs"]
    srep = r("lineage", "family", sfam)["representative_unit_id"]
    variant = B if r("lineage", "units", sid, "--content", B)[0]["id"] != srep else A
    before = r("stage", "select-deep", sid, variant, "--actor", "hermes", "--reason", "full?")
    change = r("lineage", "set-algorithm", sid, "lite-fp-v2", "--actor", "hermes", "--reason", "new function hasher")
    after = r("stage", "select-deep", sid, variant, "--actor", "hermes", "--reason", "lineage stale; full analysis required")
    checks["algorithm_change_stales_and_cannot_skip"] = (
        (not before["accepted"]) and change["stale_families"] == [sfam] and change["cancelled_delta_jobs"] == sdel
        and after["accepted"] and r("lineage", "family", sfam)["status"] == "stale")

    summary = {
        "synthetic_only": True,
        "note": "Synthetic metadata, synthetic fingerprint observations, simulated workers. No real firmware analyzed; no model invoked.",
        "campaign_id": cid, "staleness_campaign_id": sid, "cli_invocations": r.calls,
        "lineage_pass": {k: lp[k] for k in ("edges_created", "metadata_only_rejected", "families_proposed", "pairs_examined")},
        "family": {"id": fam, "representative_unit_id": rep, "members": sorted(members), "product_families": family["product_families"]},
        "applicability": {k[:12]: v["state"] for k, v in final.items()},
        "closeout": {"passed": closeout["passed"], "blockers": closeout["blockers"],
                     "warnings": [c["id"] for c in gate["checks"] if c["status"] == "warn"]},
        "checks": checks,
    }
    (wd / "lineage-summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True))
    ok = closeout["passed"] and all(checks.values())
    print(json.dumps({"passed": ok, "checks": checks, "cli_invocations": r.calls}, indent=1))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
