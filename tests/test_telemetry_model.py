"""Model-call envelopes through the REFALL worker seam, with a deterministic mock model (no network, no Qwen)."""
from __future__ import annotations

import json
import sys

from fwspider_telemetry import MockModelClient, instrumented_model_invoke
from fwspider_telemetry.query import chain, load_artifact
from refall_lite import RefallLite
from refall_lite.model_worker import ModelWorker, subprocess_tool
from refall_lite.worker import render_submission, result_payload, run_one

from .helpers import base_config, members
from .tel_helpers import TelCase


def submission(summary="mock triage") -> str:
    return "analysis...\n" + render_submission({**result_payload(
        summary=summary, evidence=[{"kind": "tool", "ref": "synthetic:tool", "claim": summary}], confidence="medium",
        artifact_refs=["synthetic:tool"], limitations=["mock model"]), "schema": "refall-lite.submit.v1"})


class ModelEnvelopeTests(TelCase):
    def setUp(self) -> None:
        super().setUp()
        self.t = self.tel("refall-lite")
        self.lite = RefallLite(self.root / "s.sqlite", telemetry=self.t)
        self.lite.register_actor("hermes", "supervisor")
        self.lite.register_actor("qwen-mock", "model")
        self.cid = self.lite.create_campaign("m", config=base_config(), actor="hermes")["id"]
        self.lite.ingest_image(self.cid, family="f", name="i1", image_sha256="a" * 64, members=members("httpd"), actor="hermes")
        self.lite.enqueue_image_jobs(self.cid, stage="inventory", kind="inventory", actor="hermes")

    def tearDown(self) -> None:
        self.lite.close()
        super().tearDown()

    def test_mock_model_call_full_envelope_with_tool_retry_and_parse(self):
        tool = subprocess_tool(self.t, lambda a: [sys.executable, "-c", f"print('strings for {a['target']}')"], tool="strings")
        script = [
            TimeoutError("mock provider timeout"),                                               # retry 1: transport
            {"content": "let me look", "tool_calls": [{"id": "call-1", "name": "strings", "arguments": {"target": "httpd"}}]},
            {"content": "no fenced block here"},                                                 # retry 2: parse
            {"content": submission()},
        ]
        client = MockModelClient(script)
        res = run_one(self.lite, self.cid, ModelWorker("qwen-mock", client, tools={"strings": tool}, telemetry=self.t))
        self.assertTrue(res["accepted"], res)
        evs = self.events()
        mcid = next(e["model_call_id"] for e in evs if e["event_type"] == "model.call_start")
        mine = [e for e in evs if e.get("model_call_id") == mcid]
        types = [e["event_type"] for e in mine]
        start = mine[0]
        self.assertEqual(start["data"]["template_version"], "1.0.0")
        self.assertEqual(start["data"]["provider"], "mock")
        self.assertEqual(start["data"]["endpoint_alias"], "mock://local")
        self.assertTrue(start["data"]["context_refs"])
        self.assertEqual(types.count("model.request"), 4)
        self.assertEqual(types.count("model.response"), 4)
        self.assertEqual(types.count("model.retry"), 2)
        self.assertEqual([e["data"]["reason"] for e in mine if e["event_type"] == "model.retry"],
                         ["provider_timeout", "missing_terminal_submit"])
        self.assertEqual([e["data"]["ok"] for e in mine if e["event_type"] == "model.parse"], [False, True])
        for e in mine:
            if e["event_type"] == "model.request":
                self.assertEqual(len(e["data"]["request_sha256"]), 64)
                body = load_artifact(self.log_dir, e["run_id"], e["data"]["request_body"]["artifact_ref"])
                self.assertIn("refall-lite.job.v1", body["body"])
                self.assertEqual(body["sha256"], e["data"]["request_body"]["sha256"])
            if e["event_type"] == "model.response" and e["data"]["status"] == "ok":
                self.assertEqual(len(e["data"]["response_sha256"]), 64)
                self.assertIsNotNone(e["data"]["latency_ms"])
                self.assertGreater(e["data"]["tokens"]["total"], 0)
        # tool call <-> tool execution <-> tool result linkage
        tc = next(e for e in mine if e["event_type"] == "model.tool_call")
        tr = next(e for e in mine if e["event_type"] == "model.tool_result")
        self.assertEqual(tc["tool_call_id"], tr["tool_call_id"])
        execs = [e for e in evs if e.get("tool_call_id") == tc["tool_call_id"] and e["event_type"].startswith("tool.")]
        self.assertEqual([e["event_type"] for e in execs], ["tool.start", "tool.end"])
        sub_start = next(e for e in evs if e["event_type"] == "tool.start" and e["parent_event_id"] == execs[0]["event_id"])
        self.assertEqual(sub_start["data"]["tool"], "strings")
        self.assertFalse(sub_start["data"].get("in_process"))
        sub_end = next(e for e in evs if e["event_type"] == "tool.end" and e["tool_call_id"] == sub_start["tool_call_id"])
        self.assertEqual(sub_end["data"]["exit_code"], 0)
        self.assertEqual(sub_start["job_id"], tc["job_id"])
        end = next(e for e in mine if e["event_type"] == "model.call_end")
        self.assertEqual((end["data"]["status"], end["data"]["attempts"]), ("ok", 3))
        self.assertEqual(end["data"]["tool_calls"], [tc["tool_call_id"]])
        # the job, model call and tool call form one reconstructable chain
        job_id = tc["job_id"]
        ch = [e["event_type"] for e in chain(self.log_dir, job_id=job_id)]
        for t in ("api.call", "job.claim", "worker.run_start", "model.call_start", "model.tool_call", "tool.end",
                  "model.parse", "model.call_end", "job.succeed", "worker.run_end"):
            self.assertIn(t, ch)
        self.assertLess(ch.index("job.claim"), ch.index("model.call_start"))
        self.assertLess(ch.index("model.call_end"), ch.index("job.succeed"))
        self.assertLogsValid()

    def test_model_failure_is_job_failure_with_correlated_exception(self):
        client = MockModelClient([ConnectionError("down"), ConnectionError("still down")])
        res = run_one(self.lite, self.cid, ModelWorker("qwen-mock", client, telemetry=self.t, max_attempts=2))
        self.assertFalse(res["accepted"])
        self.assertTrue(res["failure_recorded"])
        evs = self.events()
        err = next(e for e in evs if e["event_type"] == "worker.run_error")
        self.assertEqual(err["data"]["exception"]["type"], "builtins.ConnectionError")
        self.assertTrue(err["data"]["exception"]["stack"])
        self.assertEqual(err["data"]["retry"]["failure_class"], "transport_error")
        self.assertTrue(err["campaign_id"] and err["job_id"])
        fail = next(e for e in evs if e["event_type"] == "job.fail")
        self.assertEqual(fail["job_id"], err["job_id"])
        end = next(e for e in evs if e["event_type"] == "model.call_end")
        self.assertEqual(end["data"]["status"], "error")

    def test_bodies_can_be_disabled_but_hashes_remain(self):
        t = self.tel("refall-lite", run_id=self.t.run_id, log_bodies=False)
        self.lite.telemetry = t
        self.lite.store.tel = t
        run_one(self.lite, self.cid, ModelWorker("qwen-mock", MockModelClient([{"content": submission()}]), telemetry=t))
        reqs = [e for e in self.events() if e["event_type"] in {"model.request", "model.response"}]
        self.assertTrue(reqs)
        for e in reqs:
            self.assertFalse(e["data"]["body_logged"])
            self.assertNotIn("artifact_ref", json.dumps(e["data"].get("request_body") or e["data"].get("response_body") or {}))
            self.assertEqual(len(e["data"].get("request_sha256") or e["data"].get("response_sha256")), 64)

    def test_text_seam_adapter_for_ara_model_invoke(self):
        invoke = instrumented_model_invoke(self.t, MockModelClient([{"content": "[]"}]), template_id="ara.pack-exhaust",
                                           template_version="ara-export@01d5b34")
        self.assertEqual(invoke("system", "user element text"), "[]")
        types = [e["event_type"] for e in self.events() if e.get("model_call_id")]
        self.assertEqual(types, ["model.call_start", "model.request", "model.response", "model.parse", "model.call_end"])
