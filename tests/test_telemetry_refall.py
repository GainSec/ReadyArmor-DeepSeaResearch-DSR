"""REFALL Lite instrumentation: ledger->event mapping after commit, rollback, API/CLI envelopes, failure severity."""
from __future__ import annotations

import ast
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from fwspider_telemetry import ObservabilityError
from fwspider_telemetry.query import events as read_events
from refall_lite import RefallLite
from refall_lite.arcticbase.contracts import LEDGER_KINDS
from refall_lite.observability import KIND_DOMAIN, instrumented_operations, ledger_event_type

from .helpers import base_config, good_result, members
from .tel_helpers import TelCase

ROOT = Path(__file__).resolve().parents[1]


def ledger_calls() -> set[tuple[str, str]]:
    """Every (kind, action) literal passed to _ledger/append_ledger anywhere in refall_lite (AST audit)."""
    out: set[tuple[str, str]] = set()
    import refall_lite
    for py in Path(refall_lite.__file__).parent.rglob("*.py"):  # repo checkout or installed wheel
        tree = ast.parse(py.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) in {"_ledger", "append_ledger"}:
                args = node.args
                if len(args) < 3:
                    continue
                kinds = _values(args[1])
                actions = _values(args[2])
                for k in kinds:
                    for a in actions:
                        out.add((k, a))
    return out


def _values(n: ast.AST) -> list[str]:
    if isinstance(n, ast.Constant) and isinstance(n.value, str):
        return [n.value]
    if isinstance(n, ast.IfExp):
        return _values(n.body) + _values(n.orelse)
    if isinstance(n, ast.JoinedStr):  # f"edge_{status}" -> statuses used by _decide_edge
        return ["edge_approved", "edge_rejected"]
    if isinstance(n, ast.Name) and n.id == "kind":  # findings transition: kind in {validation, disposition-transition}
        return ["validation", "disposition-transition"]
    if isinstance(n, ast.Name) and n.id == "status":  # findings transition status
        return ["accepted", "refused"]
    return []


class LedgerMappingAuditTests(TelCase):
    def test_every_ledger_kind_action_in_code_maps_to_taxonomy(self):
        pairs = ledger_calls()
        self.assertGreater(len(pairs), 60)
        unmapped = sorted(p for p in pairs if ledger_event_type(*p) == "ledger.unmapped")
        self.assertEqual(unmapped, [])
        self.assertEqual(set(KIND_DOMAIN), LEDGER_KINDS)

    def test_every_public_api_operation_is_instrumented(self):
        ops = instrumented_operations(RefallLite)
        public = sorted(n for n in dir(RefallLite) if not n.startswith("_") and callable(getattr(RefallLite, n))
                        and n not in {"close"})
        self.assertEqual(ops, public)
        self.assertGreaterEqual(len(ops), 90)


class LedgerEventTests(TelCase):
    def setUp(self) -> None:
        super().setUp()
        self.t = self.tel("refall-lite")
        self.db = self.root / "s.sqlite"
        self.lite = RefallLite(self.db, telemetry=self.t)
        self.lite.register_actor("hermes", "supervisor")
        self.lite.register_actor("qwen", "model")

    def tearDown(self) -> None:
        self.lite.close()
        super().tearDown()

    def test_state_transitions_emitted_after_commit_with_ledger_hashes_and_ids(self):
        cid = self.lite.create_campaign("c", config=base_config(), actor="hermes")["id"]
        self.lite.ingest_image(cid, family="f", name="i", image_sha256="b" * 64, members=members("a", "b"), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        self.lite.submit_result(cid, job["id"], job["claim_token"], good_result())
        evs = self.events()
        ledger = self.lite.ledger(cid)
        led_events = [e for e in evs if e.get("data", {}).get("ledger_seq") and e["campaign_id"] == cid]
        self.assertEqual([(e["data"]["ledger_kind"], e["data"]["ledger_action"]) for e in led_events],
                         [(r["kind"], r["action"]) for r in ledger])
        self.assertEqual([e["data"]["entry_hash"] for e in led_events], [r["entry_hash"] for r in ledger])
        claim = next(e for e in evs if e["event_type"] == "job.claim")
        self.assertEqual(claim["job_id"], job["id"])
        self.assertNotIn(job["claim_token"], json.dumps(evs))  # capability token never logged
        img = next(e for e in evs if e["event_type"] == "image.ingest")
        self.assertEqual(img["artifact_id"], "sha256:" + "b" * 64)
        # every ledger event is a child of the api.call that caused it
        calls = {e["event_id"]: e for e in evs if e["event_type"] == "api.call"}
        for e in led_events:
            self.assertIn(e["parent_event_id"], calls, e["event_type"])
        succ = next(e for e in evs if e["event_type"] == "job.succeed")
        self.assertEqual(calls[succ["parent_event_id"]]["data"]["operation"], "submit_result")
        self.assertLogsValid()

    def test_rollback_discards_buffered_events_and_reports_them(self):
        cid = self.lite.create_campaign("c", config=base_config(), actor="hermes")["id"]
        store = self.lite.store
        with self.assertRaises(RuntimeError):
            with store.tx():
                store.append_ledger(cid, "runtime-event", "resume", "hermes", {"probe": 1})
                raise RuntimeError("forced failure inside transaction")
        evs = self.events()
        self.assertNotIn("runtime.resume", [e["event_type"] for e in evs])
        rb = next(e for e in evs if e["event_type"] == "state.rollback")
        self.assertEqual(rb["data"]["discarded"], [{"campaign_id": cid, "kind": "runtime-event", "action": "resume"}])
        self.assertEqual(len(self.lite.ledger(cid, "runtime-event")), 0)

    def test_api_refusal_has_exception_and_correlation(self):
        cid = self.lite.create_campaign("c", config=base_config(), actor="hermes")["id"]
        with self.assertRaises(PermissionError):
            self.lite.resolve_pending_action(cid, "pa_nope", actor="qwen", status="done", receipt_type="x", receipt={})
        err = next(e for e in self.events() if e["event_type"] == "api.error")
        self.assertEqual(err["campaign_id"], cid)
        self.assertEqual(err["data"]["operation"], "resolve_pending_action")
        self.assertEqual(err["data"]["exception"]["type"], "builtins.PermissionError")
        self.assertTrue(err["data"]["exception"]["stack"])

    def test_strict_unwritable_log_refuses_before_store_is_opened(self):
        blocker = self.root / "blk"
        blocker.write_text("x")
        t = self.tel("refall-lite", log_dir=blocker / "log")
        db = self.root / "never.sqlite"
        with self.assertRaises(ObservabilityError):
            RefallLite(db, telemetry=t)
        self.assertFalse(db.exists(), "no canonical work under strict refusal")

    def test_log_failure_after_commit_keeps_canonical_state_and_dead_letters(self):
        cid = self.lite.create_campaign("c", config=base_config(), actor="hermes")["id"]
        ev_dir = self.log_dir / "events"
        os.chmod(ev_dir / "current.jsonl", 0o400)
        try:
            # api.call is critical: strict policy refuses before state is touched
            with self.assertRaises(ObservabilityError):
                self.lite.stop_campaign(cid, actor="hermes", reason="x")
            self.assertEqual(self.lite.store.scalar("SELECT status FROM campaigns WHERE id=?", (cid,)), "active")
            # degrade policy: operation completes; the post-commit events are dead-lettered, not lost
            self.t.config.policy = "degrade"
            self.lite.stop_campaign(cid, actor="hermes", reason="operator stop during log outage")
        finally:
            os.chmod(ev_dir / "current.jsonl", 0o600)
        self.assertEqual(self.lite.store.scalar("SELECT status FROM campaigns WHERE id=?", (cid,)), "stopped")
        self.assertTrue(self.lite.verify_ledger(cid)["ok"])
        dead = [json.loads(ln) for f in self.dead_dir.glob("*.jsonl") for ln in f.read_text().splitlines()]
        self.assertIn("campaign.stop", [(d.get("event") or {}).get("event_type") for d in dead])

    def test_migration_and_refused_store_events(self):
        fx = ROOT / "tests" / "fixtures" / "baseline_v1.sqlite"
        db = self.root / "v1.sqlite"
        db.write_bytes(fx.read_bytes())
        RefallLite(db, telemetry=self.t).close()
        foreign = self.root / "foreign.sqlite"
        con = sqlite3.connect(foreign)
        con.execute("CREATE TABLE x(y)")
        con.close()
        with self.assertRaises(Exception):
            RefallLite(foreign, telemetry=self.t)
        types = self.types()
        self.assertIn("state.migrate", types)
        self.assertIn("runtime.migrate", types)
        self.assertIn("state.open_refused", types)


class CliTelemetryTests(TelCase):
    def run_cli(self, *args, env_extra=None):
        env = {**os.environ, "PYTHONPATH": str(ROOT), "FIRMWARE_SPIDER_LOG_DIR": str(self.log_dir),
               "FIRMWARE_SPIDER_DEADLETTER_DIR": str(self.dead_dir), **(env_extra or {})}
        env.pop("FIRMWARE_SPIDER_RUN_ID", None)
        return subprocess.run([sys.executable, "-m", "refall_lite", "--db", str(self.root / "c.sqlite"), *args],
                              capture_output=True, text=True, env=env)

    def test_stdout_stays_pure_json_and_cli_events_recorded(self):
        p = self.run_cli("actor", "add", "hermes", "--kind", "supervisor")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(json.loads(p.stdout)["id"], "hermes")
        cfg = self.root / "cfg.json"
        cfg.write_text(json.dumps(base_config()))
        p = self.run_cli("campaign", "create", "c", "--config", str(cfg), "--actor", "hermes")
        json.loads(p.stdout)
        bad = self.run_cli("job", "submit", "camp_x", "job_x", "--token", "tok-should-not-log-123", "--file", str(cfg))
        self.assertEqual(bad.returncode, 2)
        self.assertEqual(list(json.loads(bad.stdout)), ["error"])
        evs = read_events(self.log_dir)
        types = [e["event_type"] for e in evs]
        for t in ("process.start", "cli.invoke", "config.load", "cli.result", "cli.error", "process.end"):
            self.assertIn(t, types)
        res = next(e for e in evs if e["event_type"] == "cli.result")
        import hashlib
        first = self.run_cli("info")
        last_res = [e for e in read_events(self.log_dir) if e["event_type"] == "cli.result"][-1]
        self.assertEqual(last_res["data"]["stdout_sha256"], hashlib.sha256(first.stdout.encode()).hexdigest())
        self.assertTrue(res["data"]["stdout_length"] > 0)
        self.assertNotIn("tok-should-not-log-123", (self.log_dir / "events" / "current.jsonl").read_text())

    def test_strict_unwritable_log_dir_exit_4_and_no_db(self):
        blocker = self.root / "blk"
        blocker.write_text("x")
        p = self.run_cli("info", env_extra={"FIRMWARE_SPIDER_LOG_DIR": str(blocker / "log")})
        self.assertEqual(p.returncode, 4)
        self.assertIn("ObservabilityError", json.loads(p.stdout)["error"])
        self.assertFalse((self.root / "c.sqlite").exists())
        self.assertIn("fwspider_telemetry_failure", p.stderr)

    def test_degrade_policy_cli_still_works_and_reports_on_stderr(self):
        blocker = self.root / "blk"
        blocker.write_text("x")
        p = self.run_cli("info", env_extra={"FIRMWARE_SPIDER_LOG_DIR": str(blocker / "log"),
                                            "FIRMWARE_SPIDER_TELEMETRY_POLICY": "degrade"})
        self.assertEqual(p.returncode, 0)
        json.loads(p.stdout)
        self.assertIn("fwspider_telemetry_failure", p.stderr)
        self.assertTrue(list(self.dead_dir.glob("deadletter-*.jsonl")))
