"""fwspider_telemetry core: schema, ordering, concurrency, restart, rotation, artifacts, failures."""
from __future__ import annotations

import gzip
import json
import multiprocessing
import os
import stat
import subprocess
import sys
import threading
from pathlib import Path

from fwspider_telemetry import SCHEMA, TAXONOMY, ObservabilityError, Telemetry, TelemetryConfig, resolve_log_dir
from fwspider_telemetry.query import chain, recover_deadletter, render, validate_event, verify
from fwspider_telemetry.sink import format_human, iter_events, read_index, verify_segments

from .tel_helpers import TelCase

ROOT = Path(__file__).resolve().parents[1]


def _proc_writer(log_dir: str, run_id: str, n: int, tag: str) -> None:
    tel = Telemetry("proc-writer", config=TelemetryConfig(log_dir=log_dir, rotate_bytes=8192), run_id=run_id, env={})
    for i in range(n):
        tel.emit("scenario.step", {"writer": tag, "i": i, "pad": "x" * 200})
    tel.end_process(0)


class SchemaTests(TelCase):
    def test_every_event_has_required_fields_and_validates(self):
        tel = self.tel()
        with tel.bind(campaign_id="camp_x", job_id="job_y"):
            tel.emit("scenario.step", {"k": 1}, message="hello")
        tel.end_process(0)
        evs = self.events()
        self.assertEqual([e["event_type"] for e in evs], ["run.start", "process.start", "scenario.step", "process.end"])
        for ev in evs:
            self.assertEqual(validate_event(ev), [], ev)
            for k in SCHEMA["required"]:
                self.assertIn(k, ev)
            self.assertTrue(ev["ts"].endswith("Z"))
        step = evs[2]
        self.assertEqual((step["campaign_id"], step["job_id"]), ("camp_x", "job_y"))
        self.assertEqual(step["host"], tel.host)
        self.assertEqual(step["pid"], os.getpid())
        self.assertLogsValid()

    def test_unknown_event_type_and_correlation_field_rejected(self):
        tel = self.tel()
        with self.assertRaises(ValueError):
            tel.emit("not.a.type", {})
        with self.assertRaises(ValueError):
            tel.emit("scenario.step", {}, bogus_id="x")

    def test_schema_file_is_the_published_event_schema(self):
        import fwspider_telemetry
        pkg_schema = Path(fwspider_telemetry.__file__).parent / "event-schema.json"
        self.assertEqual(json.loads(pkg_schema.read_text()), SCHEMA)
        published = ROOT / "EVENT-SCHEMA.json"
        if published.exists():  # repo checkout (absent when tests run against an installed wheel)
            self.assertEqual(json.loads(published.read_text()), SCHEMA)
        for name, spec in TAXONOMY.items():
            self.assertRegex(name, r"^[a-z_]+\.[a-z_]+$")
            self.assertIn(spec["level"], SCHEMA["levels"])

    def test_debug_mode_adds_detail_only_when_enabled(self):
        tel = self.tel()
        tel.emit("telemetry.debug", {"x": 1})
        tel.artifact("note", "hello")
        self.assertNotIn("telemetry.debug", self.types())
        self.assertNotIn("artifact.write", self.types())
        dbg = self.tel(debug=True, run_id=tel.run_id)
        dbg.emit("telemetry.debug", {"x": 2})
        dbg.artifact("note", "hello")
        self.assertIn("telemetry.debug", self.types())
        self.assertIn("artifact.write", self.types())


class OrderingAndConcurrencyTests(TelCase):
    def test_seq_monotonic_and_reconstructable_in_order(self):
        tel = self.tel()
        for i in range(50):
            tel.emit("scenario.step", {"i": i})
        evs = [e for e in self.events() if e["event_type"] == "scenario.step"]
        self.assertEqual([e["data"]["i"] for e in evs], list(range(50)))
        seqs = [e["seq"] for e in self.events()]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))

    def test_threads_share_one_run_without_duplicate_seq(self):
        tel = self.tel()

        def work(t: int) -> None:
            for i in range(60):
                tel.emit("scenario.step", {"t": t, "i": i})
        ths = [threading.Thread(target=work, args=(t,)) for t in range(8)]
        for t in ths:
            t.start()
        for t in ths:
            t.join()
        evs = self.events()
        seqs = [e["seq"] for e in evs]
        self.assertEqual(len(seqs), len(set(seqs)))
        self.assertEqual(sorted(seqs), list(range(1, len(seqs) + 1)))
        self.assertEqual(len({e["event_id"] for e in evs}), len(evs))
        for t in range(8):  # per-thread order preserved
            mine = [e["data"]["i"] for e in evs if e["data"].get("t") == t]
            self.assertEqual(mine, list(range(60)))
        self.assertLogsValid()

    def test_concurrent_processes_same_run_valid_jsonl_unique_seq_with_rotation(self):
        run_id = "run_concurrent_test"
        ctx = multiprocessing.get_context("spawn")
        procs = [ctx.Process(target=_proc_writer, args=(str(self.log_dir), run_id, 80, f"w{i}")) for i in range(6)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(120)
            self.assertEqual(p.exitcode, 0)
        evs = list(iter_events(self.log_dir))  # strict JSON parse of every line in every segment
        mine = [e for e in evs if e["run_id"] == run_id]
        seqs = [e["seq"] for e in mine]
        self.assertEqual(len(seqs), len(set(seqs)), "duplicate seq across processes")
        self.assertEqual(sorted(seqs), list(range(1, len(seqs) + 1)))
        self.assertEqual(len([e for e in mine if e["event_type"] == "scenario.step"]), 6 * 80)
        self.assertEqual(len({e["event_id"] for e in evs}), len(evs))
        self.assertGreater(len(read_index(self.log_dir)), 1, "rotation should have happened")
        # rotation preserved file order == seq order
        self.assertEqual(seqs, sorted(seqs))
        self.assertLogsValid()

    def test_restart_resume_continues_sequence_and_correlation(self):
        a = self.tel(run_id="run_restart_test")
        with a.bind(campaign_id="camp_r"):
            a.emit("scenario.step", {"phase": "before-crash"})
        last_a = max(e["seq"] for e in self.events())
        # simulated crash: process A never emits process.end; process B resumes the same run
        b = Telemetry("test", config=self.cfg(), env={"FIRMWARE_SPIDER_RUN_ID": "run_restart_test",
                                                      "FIRMWARE_SPIDER_CAMPAIGN_ID": "camp_r"})
        b.emit("scenario.step", {"phase": "after-restart"})
        b.end_process(0)
        evs = self.events()
        self.assertEqual({e["run_id"] for e in evs}, {"run_restart_test"})
        resumed = [e for e in evs if e["event_type"] == "process.resume"]
        self.assertEqual(len(resumed), 1)
        self.assertEqual(resumed[0]["seq"], last_a + 1)
        self.assertEqual(resumed[0]["data"]["prior_events_in_run"], last_a)
        after = [e for e in evs if e["data"].get("phase") == "after-restart"][0]
        self.assertEqual(after["campaign_id"], "camp_r")
        self.assertNotEqual(after["process_id"], a.process_id)
        seqs = [e["seq"] for e in evs]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))
        man = json.loads((self.log_dir / "runs" / "run_restart_test" / "manifest.json").read_text())
        self.assertEqual(len(man["processes"]), 2)
        self.assertEqual(man["status"], "running", "process A never ended (crash) -> run not reported complete")

    def test_child_process_joins_run_via_env_propagation(self):
        tel = self.tel()
        code = ("from fwspider_telemetry import get_telemetry; t=get_telemetry('child'); "
                "t.emit('scenario.step', {'from':'child'}); t.end_process(0)")
        env = dict(os.environ, PYTHONPATH=str(ROOT))
        with tel.bind(campaign_id="camp_c", job_id="job_c"):
            tel.run_subprocess([sys.executable, "-c", code], tool="child-python", env=env)
        evs = self.events()
        start = next(e for e in evs if e["event_type"] == "tool.start")
        child = next(e for e in evs if e["data"].get("from") == "child")
        cstart = next(e for e in evs if e["event_type"] == "process.start" and e["component"] == "child")
        self.assertEqual(child["run_id"], tel.run_id)
        self.assertEqual((child["campaign_id"], child["job_id"]), ("camp_c", "job_c"))
        self.assertEqual(child["tool_call_id"], start["tool_call_id"])
        self.assertEqual(cstart["parent_event_id"], start["event_id"])
        self.assertLogsValid()


class RotationTests(TelCase):
    def test_rotation_preserves_order_checksums_manifests_and_references(self):
        tel = self.tel(rotate_bytes=4096)
        art = tel.artifact("note", "body that is referenced across rotation")
        for i in range(120):
            tel.emit("scenario.step", {"i": i, "ref": art, "pad": "y" * 100})
        tel.end_process(0)
        idx = read_index(self.log_dir)
        self.assertGreater(len(idx), 3)
        for e in idx:
            self.assertTrue(e["compressed"])
            self.assertTrue((self.log_dir / "events" / e["file"]).exists())
            self.assertTrue((self.log_dir / "human" / e["human"]["file"]).exists())
        self.assertTrue(verify_segments(self.log_dir)["ok"])
        evs = self.events()
        self.assertEqual([e["seq"] for e in evs if e["run_id"] == tel.run_id],
                         sorted(e["seq"] for e in evs if e["run_id"] == tel.run_id))
        steps = [e["data"]["i"] for e in evs if e["event_type"] == "scenario.step"]
        self.assertEqual(steps, list(range(120)))
        rot = [e for e in evs if e["event_type"] == "log.rotate"]
        self.assertEqual(len(rot), len(idx))
        self.assertEqual([r["data"]["sha256"] for r in rot], [e["sha256"] for e in idx])
        man = json.loads((self.log_dir / "runs" / tel.run_id / "manifest.json").read_text())
        self.assertEqual(len(man["segments"]), len(idx) + 1)
        res = self.assertLogsValid()  # manifest segment refs + artifact refs resolve
        self.assertGreater(res["artifact_refs"], 100)
        # Startup size depends on argv/install paths; the first segment may contain only startup.
        # Verify every derived human segment against its matching canonical event segment.
        for entry in idx:
            with gzip.open(self.log_dir / "events" / entry["file"], "rt") as events:
                expected = "".join(format_human(json.loads(line)) for line in events)
            with gzip.open(self.log_dir / "human" / entry["human"]["file"], "rt") as human:
                self.assertEqual(human.read(), expected)

    def test_retention_deletes_oldest_but_keeps_tombstone_checksums(self):
        tel = self.tel(rotate_bytes=2048, retention_segments=2)
        for i in range(100):
            tel.emit("scenario.step", {"i": i, "pad": "z" * 100})
        idx = read_index(self.log_dir)
        deleted = [e for e in idx if e["status"] == "deleted"]
        self.assertTrue(deleted)
        for d in deleted:
            self.assertEqual(len(d["sha256"]), 64)
            self.assertFalse((self.log_dir / "events" / d["file"]).exists())
        self.assertIn("log.retention_delete", self.types())
        self.assertTrue(verify_segments(self.log_dir)["ok"])
        self.assertLogsValid()

    def test_uncompressed_rotation(self):
        tel = self.tel(rotate_bytes=2048, compress=False)
        for i in range(40):
            tel.emit("scenario.step", {"i": i, "pad": "q" * 100})
        self.assertTrue(all(not e["compressed"] and e["file"].endswith(".jsonl") for e in read_index(self.log_dir)))
        self.assertLogsValid()


class PermissionsAndHumanLogTests(TelCase):
    def test_files_0600_dirs_0700(self):
        tel = self.tel(rotate_bytes=2048)
        tel.artifact("note", "x")
        for i in range(30):
            tel.emit("scenario.step", {"i": i, "pad": "p" * 100})
        for p in self.log_dir.rglob("*"):
            mode = stat.S_IMODE(p.stat().st_mode)
            self.assertEqual(mode, 0o700 if p.is_dir() else 0o600, p)

    def test_human_log_is_derived_from_jsonl(self):
        tel = self.tel()
        tel.emit("scenario.step", {"i": 1}, message="a human line")
        human = (self.log_dir / "human" / "current.log").read_text()
        self.assertEqual(human, "".join(render(self.log_dir)))
        self.assertIn("a human line", human)
        long = format_human({"ts": "t", "level": "info", "event_type": "x", "data": {"v": "a" * 2000}, "event_id": "ev_1"})
        self.assertIn("full data in event ev_1", long)


class ArtifactTests(TelCase):
    def test_bounded_artifact_states_lengths_hash_and_truncation(self):
        tel = self.tel(max_artifact_bytes=1024)
        body = "line of response text\n" * 500
        ref = tel.artifact("model-response", body)
        env = json.loads((self.log_dir / ref["path"]).read_text())
        self.assertTrue(env["truncated"])
        self.assertEqual(env["original_length"], len(body.encode()))
        self.assertLessEqual(env["stored_length"], 1024)
        self.assertEqual(len(env["body"].encode()), env["stored_length"])
        import hashlib
        self.assertEqual(env["sha256"], hashlib.sha256(body.encode()).hexdigest())
        small = tel.artifact("note", "tiny")
        self.assertFalse(json.loads((self.log_dir / small["path"]).read_text())["truncated"])

    def test_oversized_event_data_moves_to_artifact_never_silently(self):
        tel = self.tel(max_inline_bytes=512)
        ev = tel.emit("scenario.step", {"blob": "b" * 5000})
        self.assertTrue(ev["data"]["_bounded"])
        self.assertIn(ev["data"]["artifact_ref"], ev["log_artifacts"])
        env = json.loads((self.log_dir / "runs" / tel.run_id / "artifacts" / f"{ev['data']['artifact_ref']}.json").read_text())
        self.assertIn("b" * 100, env["body"])
        self.assertLogsValid()

    def test_binary_described_not_stored(self):
        tel = self.tel()
        fw = self.root / "fw.bin"
        payload = b"hsqs" + bytes(range(256)) * 400
        fw.write_bytes(payload)
        d = tel.describe_binary(fw)
        self.assertEqual(d["type"], "squashfs-le")
        self.assertEqual(d["size"], len(payload))
        self.assertEqual(len(d["preview_hex"]), 128)
        ref = tel.artifact("stdout", payload)
        env = json.loads((self.log_dir / ref["path"]).read_text())
        self.assertIsNone(env["body"])
        self.assertTrue(env["truncated"])
        raw_hex = payload[200:400].hex()
        for p in self.log_dir.rglob("*"):
            if p.is_file():
                self.assertNotIn(raw_hex, p.read_text(errors="ignore"))


class ExceptionAndSubprocessTests(TelCase):
    def test_forced_exception_has_stack_cause_and_correlation(self):
        tel = self.tel()
        try:
            try:
                raise KeyError("inner-cause")
            except KeyError as inner:
                raise RuntimeError("outer failure") from inner
        except RuntimeError as exc:
            with tel.bind(campaign_id="camp_e", job_id="job_e", model_call_id="mc_e", tool_call_id="tc_e"):
                tel.exception(exc, retry={"will_retry": False}, finding_id="fnd_e")
        ev = next(e for e in self.events() if e["event_type"] == "error.exception")
        x = ev["data"]["exception"]
        self.assertEqual(x["type"], "builtins.RuntimeError")
        self.assertTrue(any("raise RuntimeError" in ln for ln in x["stack"]))
        self.assertEqual([c["relation"] for c in x["cause_chain"]], ["raised", "cause"])
        self.assertIn("inner-cause", x["cause_chain"][1]["message"])
        for k, v in {"campaign_id": "camp_e", "job_id": "job_e", "model_call_id": "mc_e", "tool_call_id": "tc_e",
                     "finding_id": "fnd_e"}.items():
            self.assertEqual(ev[k], v)
            self.assertEqual(ev["data"]["affected_ids"][k], v)

    def test_subprocess_envelope(self):
        tel = self.tel()
        p = tel.run_subprocess([sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)"],
                               tool="pyexit", cwd=str(self.root))
        self.assertEqual((p.returncode, p.stdout.strip(), p.stderr.strip()), (3, "out", "err"))
        evs = self.events()
        s = next(e for e in evs if e["event_type"] == "tool.start")
        e = next(e for e in evs if e["event_type"] == "tool.end")
        self.assertEqual(s["tool_call_id"], e["tool_call_id"])
        self.assertEqual(e["parent_event_id"], s["event_id"])
        self.assertEqual(s["data"]["cwd"], str(self.root))
        self.assertTrue(s["data"]["env"]["digest"].startswith("sha256:"))
        self.assertNotIn("count_of_everything", s["data"]["env"])
        self.assertEqual(e["data"]["exit_code"], 3)
        self.assertEqual(e["level"], "warning")
        self.assertGreaterEqual(e["data"]["duration_ms"], 0)
        for stream, text in (("stdout", "out\n"), ("stderr", "err\n")):
            ref = e["data"][stream]
            env = json.loads((self.log_dir / ref["path"]).read_text())
            self.assertEqual(env["body"], text)
            self.assertFalse(env["truncated"])
        self.assertLogsValid()

    def test_subprocess_timeout_recorded_then_raised(self):
        tel = self.tel()
        with self.assertRaises(subprocess.TimeoutExpired):
            tel.run_subprocess([sys.executable, "-c", "import time; print('started', flush=True); time.sleep(5)"],
                               tool="sleeper", timeout=0.5)
        t = next(e for e in self.events() if e["event_type"] == "tool.timeout")
        self.assertEqual(t["data"]["timeout_s"], 0.5)
        self.assertIn("artifact_ref", t["data"]["stdout"])

    def test_subprocess_missing_binary_is_tool_error(self):
        tel = self.tel()
        with self.assertRaises(OSError):
            tel.run_subprocess([str(self.root / "no-such-binary")], tool="missing")
        self.assertIn("tool.error", self.types())

    def test_chain_query_follows_parents(self):
        tel = self.tel()
        with tel.span("api.call", "api.result", "api.error", {"operation": "outer"}, campaign_id="camp_q"):
            tel.run_subprocess([sys.executable, "-c", "print(1)"], tool="one")
        ch = chain(self.log_dir, tool_call_id=next(e["tool_call_id"] for e in self.events() if e.get("tool_call_id")))
        self.assertEqual([e["event_type"] for e in ch], ["api.call", "tool.start", "tool.end"])


class FailureBehaviourTests(TelCase):
    def test_strict_startup_failure_refuses(self):
        blocker = self.root / "blocker"
        blocker.write_text("not a directory")
        tel = Telemetry("t", config=self.cfg(log_dir=blocker / "log"), env={})
        with self.assertRaises(ObservabilityError):
            tel.start_process(["x"])
        dead = list(self.dead_dir.glob("deadletter-*.jsonl"))
        self.assertTrue(dead, "failure must be dead-lettered, not silently lost")

    def test_degrade_policy_dead_letters_and_continues(self):
        blocker = self.root / "blocker"
        blocker.write_text("x")
        tel = Telemetry("t", config=self.cfg(log_dir=blocker / "log", policy="degrade"), env={})
        tel.start_process(["x"])
        self.assertIsNone(tel.emit("scenario.step", {"i": 1}, critical=True))
        self.assertGreaterEqual(tel.failures, 2)
        recs = [json.loads(ln) for f in self.dead_dir.glob("deadletter-*.jsonl") for ln in f.read_text().splitlines()]
        self.assertTrue(any((r.get("event") or {}).get("event_type") == "scenario.step" for r in recs))

    def test_mid_run_failure_then_recovery_preserves_events(self):
        tel = self.tel()
        tel.emit("scenario.step", {"i": 0})
        events_dir = self.log_dir / "events"
        os.chmod(events_dir, 0o500)  # current.jsonl append still works on existing file; break the human log dir too
        os.chmod(self.log_dir / "events" / "current.jsonl", 0o400)
        try:
            self.assertIsNone(tel.emit("scenario.step", {"i": 1}))  # post-commit style: never raises
            with self.assertRaises(ObservabilityError):
                tel.emit("scenario.step", {"i": 2}, critical=True)  # pre-operation under strict: refuse
        finally:
            os.chmod(events_dir, 0o700)
            os.chmod(self.log_dir / "events" / "current.jsonl", 0o600)
        self.assertEqual(tel.failures, 2)
        res = recover_deadletter(tel, self.dead_dir)
        self.assertEqual(res["events"], 2)
        evs = self.events()
        recovered = [e for e in evs if "_deadletter" in e["data"]]
        self.assertEqual(sorted(e["data"]["i"] for e in recovered), [1, 2])
        self.assertIn("telemetry.deadletter_recovered", self.types())
        seqs = [e["seq"] for e in evs]
        self.assertEqual(len(seqs), len(set(seqs)), "recovery must not reuse a sequence number")
        self.assertLogsValid()

    def test_stale_lock_from_dead_process_is_broken(self):
        tel = self.tel()
        tel.emit("scenario.step", {"i": 0})
        lock = self.log_dir / ".lock"
        lock.mkdir(mode=0o700)
        p = subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"], capture_output=True, text=True)
        (lock / "owner.json").write_text(json.dumps({"host": tel.host, "pid": int(p.stdout), "ts": 0}))
        tel.emit("scenario.step", {"i": 1})
        self.assertFalse(lock.exists())
        self.assertEqual([e["data"].get("i") for e in self.events() if e["event_type"] == "scenario.step"], [0, 1])


class ConfigTests(TelCase):
    def test_log_dir_resolution_order(self):
        self.assertEqual(resolve_log_dir(None, {"FIRMWARE_SPIDER_LOG_DIR": "/x/y"})[:2], (Path("/x/y"), "env:FIRMWARE_SPIDER_LOG_DIR"))
        p, src, prof = resolve_log_dir(None, {"FIRMWARE_SPIDER_PROFILE": "spark"})
        self.assertEqual((str(p), prof), ("/home/dsr/firmware-spider/logs", "spark"))
        p, src, prof = resolve_log_dir(None, {}, platform="linux", exists=lambda d: d == "/home/dsr/firmware-spider")
        self.assertEqual((str(p), src), ("/home/dsr/firmware-spider/logs", "profile:spark(detected)"))
        p, src, prof = resolve_log_dir(None, {}, platform="darwin", exists=lambda d: d.startswith("/Users/dsr"))
        self.assertEqual(str(p), "/Users/dsr/firmware-spider/var/log")
        # the spark path existing on a mac does not select spark
        p, src, prof = resolve_log_dir(None, {}, platform="darwin", exists=lambda d: d == "/home/dsr/firmware-spider")
        self.assertEqual(src, "fallback")
        with self.assertRaises(ObservabilityError):
            resolve_log_dir(None, {"FIRMWARE_SPIDER_PROFILE": "nope"})

    def test_env_config(self):
        cfg = TelemetryConfig.from_env({"FIRMWARE_SPIDER_LOG_DIR": str(self.log_dir), "FIRMWARE_SPIDER_DEBUG": "1",
                                        "FIRMWARE_SPIDER_LOG_BODIES": "0", "FIRMWARE_SPIDER_LOG_ROTATE_BYTES": "4096",
                                        "FIRMWARE_SPIDER_LOG_RETENTION_SEGMENTS": "3",
                                        "FIRMWARE_SPIDER_TELEMETRY_POLICY": "degrade"})
        self.assertEqual((cfg.debug, cfg.log_bodies, cfg.rotate_bytes, cfg.retention_segments, cfg.policy),
                         (True, False, 4096, 3, "degrade"))
        with self.assertRaises(ObservabilityError):
            TelemetryConfig(log_dir=self.log_dir, policy="yolo")
