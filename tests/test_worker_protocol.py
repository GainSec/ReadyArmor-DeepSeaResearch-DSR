"""Provider-neutral worker seam (Hermes/Qwen/Claude/Codex-style)."""
from __future__ import annotations

import json
import unittest

from refall_lite.worker import (
    CallableWorker,
    backfill_envelope,
    classify_failure,
    parse_submission,
    result_payload,
    run_one,
)
from tests.helpers import LiteTestCase, good_result, members, sha


class ParseTests(unittest.TestCase):
    def test_fenced_block_parsed(self):
        text = "notes...\n```refall-submit\n" + json.dumps(good_result()) + "\n```\ntrailing"
        payload, errors = parse_submission(text, defaults={"job_id": "j1", "produced_by": "qwen"})
        self.assertEqual(errors, [])
        self.assertEqual(payload["job_id"], "j1")

    def test_legacy_refall_schema_accepted(self):
        legacy = good_result()
        legacy.update({"schema": "refall.submit.v1", "type": "task_result_submit", "task_id": "j1", "produced_by": "qwen",
                       "created_at": "2026-01-01T00:00:00Z", "subject": "s", "source_anchors": ["a.c:1"]})
        payload, errors = parse_submission(legacy)
        self.assertEqual(errors, [])
        self.assertEqual(payload["type"], "job_result")

    def test_missing_block(self):
        payload, errors = parse_submission("I am done!")
        self.assertIsNone(payload)
        self.assertEqual(errors, ["missing refall-submit block"])

    def test_hex_literals_in_json_are_salvaged(self):
        # Models emit bare hex literals (0x105178) in xrefs/offsets, which is invalid
        # JSON; without salvage the whole (real-finding) submission is dropped.
        raw = (
            '```refall-submit\n'
            '{"schema":"refall-lite.submit.v1","type":"job_result","status":"done",'
            '"summary":"s","evidence":["e"],"confidence":"medium","source_anchors":["a:1"],'
            '"cost_units":3,"findings":[{"title":"t","severity":"medium","vuln_class":"oob",'
            '"confidence":0.7,"claim":{"facts":{"xrefs":[{"from":0x105178,"target":0x113568}]}}}]}'
            '\n```'
        )
        payload, _ = parse_submission(raw, defaults={"job_id": "j", "produced_by": "w"})
        self.assertIsNotNone(payload)
        self.assertEqual(payload["findings"][0]["claim"]["facts"]["xrefs"][0]["from"], "0x105178")
        self.assertEqual(payload["findings"][0]["claim"]["facts"]["xrefs"][0]["target"], "0x113568")

    def test_unsalvageable_json_still_reports_malformed(self):
        payload, errors = parse_submission("```refall-submit\n{\"broken\": }\n```")
        self.assertIsNone(payload)
        self.assertTrue(any("malformed" in e for e in errors))

    def test_backfill_never_fabricates_evidence(self):
        bare = {"schema": "refall-lite.submit.v1", "type": "job_result", "status": "done", "summary": "s"}
        out = backfill_envelope(bare, {"job_id": "j", "produced_by": "w"})
        self.assertNotIn("evidence", out)
        _, errors = parse_submission(bare, defaults={"job_id": "j", "produced_by": "w"})
        self.assertIn("evidence-bearing submission requires evidence", errors)
        anchored = dict(bare, source_anchors=["etc/init.d/rcS:4"])
        out = backfill_envelope(anchored, {"job_id": "j", "produced_by": "w"})
        self.assertEqual(out["evidence"][0]["ref"], "etc/init.d/rcS:4")
        self.assertEqual(out["confidence"], "low")

    def test_failure_classes(self):
        self.assertTrue(classify_failure("provider_timeout")["retryable"])
        self.assertTrue(classify_failure("rate limited 429")["retryable"])
        self.assertFalse(classify_failure("scope_blocked")["retryable"])
        self.assertFalse(classify_failure("capability missing")["retryable"])
        self.assertEqual(classify_failure("weird")["failure_class"], "unknown_failure")

    def test_payload_helper_is_valid(self):
        p = result_payload(summary="x", evidence=[{"kind": "k", "ref": "r", "claim": "c"}], artifact_refs=["r"], confidence="low")
        _, errors = parse_submission(p, defaults={"job_id": "j", "produced_by": "w"})
        self.assertEqual(errors, [])


class SeamTests(LiteTestCase):
    def setUp(self):
        super().setUp()
        self.cid = self.campaign()
        self.lite.ingest_image(self.cid, family="f", name="img", image_sha256=sha("img"), members=members("a"), actor="hermes",
                               )
        self.lite.enqueue_image_jobs(self.cid, stage="inventory", kind="inventory", actor="hermes")

    def test_packet_is_bounded_and_marks_conclusions_provisional(self):
        seen = {}

        def fn(packet):
            seen.update(packet)
            return "```refall-submit\n" + json.dumps(good_result()) + "\n```"

        out = run_one(self.lite, self.cid, CallableWorker("qwen", fn))
        self.assertTrue(out["accepted"], out)
        self.assertEqual(seen["protocol"], "refall-lite.job.v1")
        self.assertIn("budget_remaining", seen)
        self.assertLessEqual(seen["budget_remaining"]["run"]["claims_remaining"], 100)
        self.assertIn("provisional", " ".join(seen["rules"]).lower())
        self.assertEqual(seen["target"]["type"], "image")

    def test_adapter_exception_becomes_classified_failure(self):
        def boom(packet):
            raise TimeoutError("provider timeout")

        out = run_one(self.lite, self.cid, CallableWorker("qwen", boom))
        self.assertFalse(out["accepted"])
        self.assertEqual(out["job"]["failure_class"], "provider_timeout")
        self.assertEqual(out["job"]["status"], "queued")

    def test_nothing_to_claim(self):
        self.drain(self.cid, "inventory")
        out = run_one(self.lite, self.cid, CallableWorker("qwen", lambda p: ""))
        self.assertFalse(out["claimed"])
