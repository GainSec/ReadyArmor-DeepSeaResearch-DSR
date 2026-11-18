#!/usr/bin/env python3
"""Observability synthetic scenario: one run spanning three processes, reconstructed from JSONL alone.

Process A (this script): REFALL campaign + image + jobs, a mock-model worker job with a parse retry and a
model tool call that runs a real subprocess, lineage code-unit/pass events, a forced API exception,
planted secret canaries, a logging outage (dead-letter + recovery) and small segments to force rotation.
Process B (child): joins the run and dies without process.end (simulated crash).
Process C (restart): rejoins the run (process.resume), resumes the campaign, drives one CLI call.

Then an independent reader (stdlib json/gzip only, no fwspider_telemetry import) rebuilds the whole run
from events/INDEX.jsonl + segments and checks exact order, links, rotation and redaction.
Synthetic data only; the model is deterministic (MockModelClient); no network.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def child_env(log_dir: Path, run_id: str, **extra: str) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("FIRMWARE_SPIDER_")}
    env.update(FIRMWARE_SPIDER_LOG_DIR=str(log_dir), FIRMWARE_SPIDER_RUN_ID=run_id, FIRMWARE_SPIDER_LOG_ROTATE_BYTES="65536",
               PYTHONPATH=os.pathsep.join([str(ROOT), os.environ.get("PYTHONPATH", "")]), **extra)
    return env


def canaries() -> dict:
    tag = hashlib.sha256(os.urandom(16)).hexdigest()[:12].upper()
    return {"password": f"pw{tag}CANARY", "bearer": f"CANARYBEARER{tag}", "api_key": "sk" + "-" + f"CANARYAPI{tag}abcdefghijkl",
            "aws": "AK" + "IA" + tag[:10] + "CANARY"}


def phase_a(wd: Path, run_id: str, c: dict) -> dict:
    from fwspider_telemetry import MockModelClient, Telemetry, TelemetryConfig
    from fwspider_telemetry.query import recover_deadletter
    from refall_lite import RefallLite
    from refall_lite.model_worker import ModelWorker, subprocess_tool
    from refall_lite.worker import render_submission, result_payload, run_one

    log_dir, dead = wd / "logs", wd / "dead"
    tel = Telemetry("observability-scenario", config=TelemetryConfig(log_dir=log_dir, rotate_bytes=65536, deadletter_dir=dead),
                    run_id=run_id, env={})
    tel.start_process(sys.argv, kind="scenario")
    tel.emit("scenario.start", {"phase": "A"})
    step = lambda name: tel.emit("scenario.step", {"step": name})  # noqa: E731
    lite = RefallLite(wd / "arcticbase.sqlite", telemetry=tel)
    step("actors")
    for actor, kind in (("hermes", "supervisor"), ("qwen-mock", "model"), ("checker", "tool")):
        lite.register_actor(actor, kind)
    cfg = {"budgets": {"run": {"max_claims": 20, "max_cost": 20}}, "max_attempts": 2, "lease_s": 600, "backoff_s": 0,
           "methodology_bundle": f"ara-export?token={c['bearer']}"}
    cid = lite.create_campaign("observability-scenario", config=cfg, actor="hermes")["id"]
    mem = [{"path": "/usr/sbin/httpd", "sha256": hashlib.sha256(b"SYNTHETIC-NOT-REAL:obs-httpd").hexdigest(), "size_bytes": 1000}]
    lite.ingest_image(cid, family="obs", name="obs-1.0", image_sha256=hashlib.sha256(b"SYNTHETIC-NOT-REAL:obs-img").hexdigest(),
                      members=mem, actor="hermes")
    lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
    step("model-job")
    tool = subprocess_tool(tel, lambda a: [sys.executable, "-c", "import sys; print('synthetic strings:', sys.argv[1])", a["target"]],
                           tool="synthetic-strings")
    sub = render_submission(result_payload(summary=f"[mock model] inventory ok; saw password={c['password']}",
                                           evidence=[{"kind": "tool", "ref": "synthetic:strings", "claim": "strings listed"}],
                                           confidence="medium", artifact_refs=["synthetic:strings"], limitations=["mock model"]))
    model = MockModelClient([
        {"content": f"need strings (Authorization: Bearer {c['bearer']})",
         "tool_calls": [{"id": "call-1", "name": "synthetic-strings", "arguments": {"target": "httpd", "api_key": c["api_key"]}}]},
        {"content": "forgot the block"},
        {"content": sub},
    ])
    res = run_one(lite, cid, ModelWorker("qwen-mock", model, tools={"synthetic-strings": tool}, telemetry=tel))
    assert res["accepted"], res
    step("lineage")
    unit = lite.register_code_unit(cid, mem[0]["sha256"], actor="hermes", name="httpd")
    lite.run_lineage_pass(cid, actor="hermes")
    step("forced-exception")
    try:
        lite.claim_job(cid, worker="hermes")  # supervisors may not claim -> PermissionError
    except PermissionError:
        pass
    try:
        raise RuntimeError(f"forced scenario failure with key {c['aws']}") from KeyError("synthetic cause")
    except RuntimeError as exc:
        tel.exception(exc, campaign_id=cid, retry={"will_retry": False})
    step("logging-outage")
    cur = log_dir / "events" / "current.jsonl"
    os.chmod(cur, 0o400)
    tel.config.policy = "degrade"
    try:
        lite.checkpoint(cid, stage="inventory", key="obs", input_hashes={"img": "x"}, actor="hermes")
    finally:
        os.chmod(cur, 0o600)
        tel.config.policy = "strict"
    stored = [k for k in lite.list_checkpoints(cid) if k.get("checkpoint_key") == "obs"]
    rec = recover_deadletter(tel, dead)
    step("rotation-padding")
    for i in range(120):
        tel.emit("scenario.step", {"step": f"pad-{i}", "pad": "r" * 400})
    lite.close()
    tel.emit("scenario.end", {"phase": "A"})
    tel.end_process(0)
    return {"campaign_id": cid, "unit_id": unit["id"], "checkpoints": len(stored), "recovered": rec["events"]}


def phase_crash(run_id: str) -> None:
    from fwspider_telemetry import get_telemetry
    tel = get_telemetry("observability-scenario.child")
    tel.emit("scenario.step", {"step": "child-before-crash"})
    os._exit(9)  # no process.end: simulated crash


def phase_restart(wd: Path, cid: str) -> None:
    from fwspider_telemetry import get_telemetry
    from refall_lite import RefallLite
    tel = get_telemetry("observability-scenario.restart")
    tel.start_process(sys.argv, kind="scenario")
    tel.emit("scenario.step", {"step": "restart"}, campaign_id=cid)
    with RefallLite(wd / "arcticbase.sqlite", telemetry=tel) as lite:
        lite.resume(cid, actor="hermes")
    p = tel.run_subprocess([sys.executable, "-m", "refall_lite", "--db", str(wd / "arcticbase.sqlite"), "status", cid],
                           tool="refall-lite-cli", campaign_id=cid)
    json.loads(p.stdout)
    tel.emit("scenario.end", {"phase": "C"}, campaign_id=cid)
    tel.end_process(0)


# ------------------------------------------------------------------ independent reconstruction
def read_run(log_dir: Path, run_id: str) -> tuple[list[dict], list[dict]]:
    index = [json.loads(x) for x in (log_dir / "events" / "INDEX.jsonl").read_text().splitlines() if x.strip()] \
        if (log_dir / "events" / "INDEX.jsonl").exists() else []
    latest = {}
    for e in index:
        latest[e["segment"]] = e
    files = [log_dir / "events" / latest[s]["file"] for s in sorted(latest) if latest[s]["status"] == "present"]
    files.append(log_dir / "events" / "current.jsonl")
    out = []
    for f in files:
        raw = gzip.decompress(f.read_bytes()) if f.name.endswith(".gz") else f.read_bytes()
        out += [json.loads(ln) for ln in raw.decode().splitlines() if ln.strip()]
    return [e for e in out if e["run_id"] == run_id], index


def reconstruct(wd: Path, run_id: str, c: dict, a: dict) -> dict:
    log_dir = wd / "logs"
    evs, index = read_run(log_dir, run_id)
    seqs = [e["seq"] for e in evs]
    t = [e["event_type"] for e in evs]
    by_id = {e["event_id"]: e for e in evs}
    steps = [e["data"]["step"] for e in evs if e["event_type"] == "scenario.step" and not e["data"]["step"].startswith("pad-")]
    mc = [e for e in evs if e.get("model_call_id")]
    tc = next(e for e in evs if e["event_type"] == "model.tool_call")
    tr = next(e for e in evs if e["event_type"] == "model.tool_result")
    in_proc = next(e for e in evs if e["event_type"] == "tool.start" and e["tool_call_id"] == tc["tool_call_id"])
    sub_start = next(e for e in evs if e["event_type"] == "tool.start" and e.get("parent_event_id") == in_proc["event_id"])
    sub_end = next(e for e in evs if e["event_type"] == "tool.end" and e["tool_call_id"] == sub_start["tool_call_id"])
    procs = [e for e in evs if e["event_type"] in {"process.start", "process.resume", "process.end"}]
    child_pid = next(e["process_id"] for e in evs if e["data"].get("step") == "child-before-crash")
    cli_start = next(e for e in evs if e["event_type"] == "tool.start" and e["data"]["tool"] == "refall-lite-cli")
    cli_child = [e for e in evs if e["event_type"] == "process.start" and e.get("parent_event_id") == cli_start["event_id"]]
    blob = "".join(p.read_text(errors="ignore") for p in log_dir.rglob("*") if p.is_file() and not p.name.endswith(".gz"))
    blob += "".join(gzip.decompress(p.read_bytes()).decode(errors="ignore") for p in log_dir.rglob("*.gz"))
    blob += "".join(p.read_text(errors="ignore") for p in (wd / "dead").rglob("*") if p.is_file())
    man = json.loads((log_dir / "runs" / run_id / "manifest.json").read_text())
    names = {e["name"] for e in index} | {"seg-%06d" % int((log_dir / "events" / "ACTIVE").read_text())}
    checks = {
        "seq_unique_increasing_in_file_order": seqs == sorted(set(seqs)),
        # the only gaps allowed are seqs reserved by writes that failed during the outage and were dead-lettered
        "seq_gaps_exactly_dead_lettered_reservations": sorted(set(range(1, max(seqs) + 1)) - set(seqs)) == sorted(
            e["data"]["_deadletter"]["reserved_seq"] for e in evs if "_deadletter" in e["data"]),
        "scenario_steps_in_exact_order": steps == ["actors", "model-job", "lineage", "forced-exception", "logging-outage",
                                                   "rotation-padding", "child-before-crash", "restart"],
        "state_transitions_in_causal_order": [x for x in t if x in {"campaign.create", "image.ingest", "job.enqueue", "job.claim",
                                              "job.succeed", "lineage.code_unit", "lineage.pass"}] ==
                                             ["campaign.create", "image.ingest", "job.enqueue", "job.claim", "job.succeed",
                                              "lineage.code_unit", "lineage.pass"],
        "model_call_envelope_complete": [x["event_type"] for x in mc if x["event_type"].startswith("model.")][:1] == ["model.call_start"]
                                        and t.count("model.request") == 3 and t.count("model.response") == 3
                                        and t.count("model.retry") == 1 and t.count("model.parse") == 2 and "model.call_end" in t,
        "model_bodies_hashed_and_stored": all(len(e["data"]["request_sha256"]) == 64 and e["data"]["request_body"]["artifact_ref"]
                                              for e in evs if e["event_type"] == "model.request"),
        "tool_call_result_linked": tc["tool_call_id"] == tr["tool_call_id"] and tc["model_call_id"] == tr["model_call_id"],
        "subprocess_under_tool_call": sub_end["data"]["exit_code"] == 0 and sub_start["job_id"] == tc["job_id"]
                                      and bool(sub_end["data"]["stdout"]["artifact_ref"]),
        "job_chain_links_model_to_state": tc["job_id"] == next(e["job_id"] for e in evs if e["event_type"] == "job.succeed"),
        "forced_exception_has_stack_cause_ids": any(e["event_type"] == "error.exception" and e["data"]["exception"]["stack"]
                                                    and len(e["data"]["exception"]["cause_chain"]) == 2 and e["campaign_id"] == a["campaign_id"]
                                                    for e in evs),
        "api_refusal_recorded": any(e["event_type"] == "api.error" and e["data"]["operation"] == "claim_job" for e in evs),
        "logging_outage_state_kept_and_recovered": a["checkpoints"] == 1 and a["recovered"] >= 1
                                                   and any("_deadletter" in e["data"] and e["event_type"] == "checkpoint.put" for e in evs),
        "crash_leaves_open_process": not any(e["event_type"] == "process.end" and e["process_id"] == child_pid for e in evs),
        "restart_resumes_same_run": any(e["event_type"] == "process.resume" for e in evs) and "runtime.resume" in t,
        "cli_child_correlated": len(cli_child) == 1 and cli_child[0]["campaign_id"] == a["campaign_id"],
        "rotation_happened_and_indexed": len(index) >= 1 and t.count("log.rotate") == len(index),
        "segment_checksums_match": all(hashlib.sha256((log_dir / "events" / e["file"]).read_bytes()).hexdigest() == e["sha256"]
                                       for e in index if e["status"] == "present"),
        "manifest_segments_resolvable": set(man["segments"]) <= names and man["events"]["last_seq"] == max(seqs),
        "parents_resolve_within_run": all(e["parent_event_id"] in by_id for e in evs if e.get("parent_event_id")),
        "no_secret_canary_on_disk": not any(v in blob for v in c.values()),
        "redaction_recorded": "[REDACTED]" in blob and any(e.get("redaction") for e in evs),
        "three_processes_one_run": len({e["process_id"] for e in procs if e["component"].startswith("observability-scenario")}) == 3,
    }
    return {"passed": all(checks.values()), "checks": checks, "events": len(evs), "segments": len(index),
            "processes": len({e["process_id"] for e in evs}), "event_types": len(set(t))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--phase", default="main", choices=["main", "crash", "restart"])
    ap.add_argument("--cid")
    a = ap.parse_args()
    wd = Path(a.workdir)
    if a.phase == "crash":
        phase_crash(os.environ["FIRMWARE_SPIDER_RUN_ID"])
        return 0
    if a.phase == "restart":
        phase_restart(wd, a.cid)
        return 0
    sys.path.insert(0, str(ROOT)) if str(ROOT) not in sys.path else None
    wd.mkdir(parents=True, exist_ok=True)
    run_id = f"run_obs_scenario_{os.getpid()}"
    c = canaries()
    res_a = phase_a(wd, run_id, c)
    me = [sys.executable, str(Path(__file__).resolve()), "--workdir", str(wd)]
    rc = subprocess.run([*me, "--phase", "crash"], env=child_env(wd / "logs", run_id, FIRMWARE_SPIDER_PARENT_EVENT_ID="")).returncode
    assert rc == 9, rc
    subprocess.run([*me, "--phase", "restart", "--cid", res_a["campaign_id"]], env=child_env(wd / "logs", run_id), check=True)
    out = reconstruct(wd, run_id, c, res_a)
    out.update(run_id=run_id, synthetic_only=True, log_dir=str(wd / "logs"))
    (wd / "observability-summary.json").write_text(json.dumps(out, indent=1, sort_keys=True))
    print(json.dumps({"passed": out["passed"], "checks": out["checks"], "events": out["events"], "segments": out["segments"]}, indent=1))
    return 0 if out["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
