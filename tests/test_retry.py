"""Retry ceilings, failure classification, stale tokens."""
from __future__ import annotations

from tests.helpers import LiteTestCase, good_result, members, sha


class RetryTests(LiteTestCase):
    def _one_job(self, **cfg):
        cid = self.campaign(**cfg)
        self.lite.ingest_image(cid, family="famA", name="imgA", image_sha256=sha("imgA"), members=members("a"), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        return cid

    def test_retryable_failure_until_ceiling_then_dead(self):
        cid = self._one_job(max_attempts=3)
        for attempt in (1, 2, 3):
            claim = self.lite.claim_job(cid, worker="qwen")
            self.assertTrue(claim["claimed"], claim)
            self.assertEqual(claim["job"]["attempts"], attempt)
            out = self.lite.fail_job(cid, claim["job"]["id"], claim["job"]["claim_token"], status="provider_timeout", error="t/o")
            self.reopen()
        self.assertEqual(out["outcome"]["state"], "dead")
        self.assertEqual(self.lite.get_job(claim["job"]["id"])["status"], "dead")
        self.assertFalse(self.lite.claim_job(cid, worker="qwen")["claimed"])
        actions = self.lite.list_pending_actions(cid)
        self.assertEqual([a["kind"] for a in actions], ["operator_attention"])

    def test_backoff_delays_requeue(self):
        cid = self._one_job(max_attempts=3, backoff_s=30)
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        self.lite.fail_job(cid, job["id"], job["claim_token"], status="provider_rate_limited", error="429")
        self.assertFalse(self.lite.claim_job(cid, worker="qwen")["claimed"])
        self.clock.advance(31)
        self.assertTrue(self.lite.claim_job(cid, worker="qwen")["claimed"])

    def test_non_retryable_failure_blocks_with_pending_action(self):
        cid = self._one_job(max_attempts=5)
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        out = self.lite.fail_job(cid, job["id"], job["claim_token"], status="scope_blocked", error="needs scope")
        self.assertEqual(out["outcome"]["state"], "blocked")
        self.assertFalse(out["outcome"]["retryable"])
        self.assertEqual(self.lite.get_job(job["id"])["status"], "blocked")
        self.assertFalse(self.lite.claim_job(cid, worker="qwen")["claimed"])
        self.assertIn("operator_attention", [a["kind"] for a in self.lite.list_pending_actions(cid)])

    def test_malformed_submission_counts_as_failed_attempt(self):
        cid = self._one_job(max_attempts=2)
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        bad = good_result()
        bad.pop("evidence")
        res = self.lite.submit_result(cid, job["id"], job["claim_token"], bad)
        self.assertFalse(res["accepted"])
        self.assertEqual(res["job"]["failure_class"], "malformed_terminal_submit")
        self.assertEqual(res["job"]["status"], "queued")
        job2 = self.lite.claim_job(cid, worker="qwen")["job"]
        res2 = self.lite.submit_result(cid, job2["id"], job2["claim_token"], "no fenced block here")
        self.assertFalse(res2["accepted"])
        self.assertEqual(res2["job"]["status"], "dead")
        self.assertEqual(res2["job"]["failure_class"], "missing_terminal_submit")

    def test_consecutive_failure_ceiling_stops_campaign(self):
        cid = self.campaign(max_consecutive_failures=2, max_attempts=10)
        for name in ("imgA", "imgB", "imgC"):
            self.lite.ingest_image(cid, family="famA", name=name, image_sha256=sha(name), members=members(name), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        for _ in range(2):
            job = self.lite.claim_job(cid, worker="qwen")["job"]
            self.lite.fail_job(cid, job["id"], job["claim_token"], status="provider_unavailable", error="down")
        camp = self.lite.get_campaign(cid)
        self.assertEqual(camp["status"], "stopped")
        self.assertEqual(camp["stop_reason"], "consecutive_failures")
        self.assertFalse(self.lite.claim_job(cid, worker="qwen")["claimed"])

    def test_success_resets_consecutive_failures(self):
        cid = self.campaign(max_consecutive_failures=2, max_attempts=10)
        for name in ("imgA", "imgB"):
            self.lite.ingest_image(cid, family="famA", name=name, image_sha256=sha(name), members=members(name), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        self.lite.fail_job(cid, job["id"], job["claim_token"], status="provider_unavailable", error="down")
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        self.lite.submit_result(cid, job["id"], job["claim_token"], good_result())
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        self.lite.fail_job(cid, job["id"], job["claim_token"], status="provider_unavailable", error="down")
        self.assertEqual(self.lite.get_campaign(cid)["status"], "active")

    def test_wrong_token_refused(self):
        cid = self._one_job()
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        res = self.lite.submit_result(cid, job["id"], "not-the-token", good_result())
        self.assertFalse(res["accepted"])
        self.assertIn("claim token", res["errors"][0])
        self.assertEqual(self.lite.get_job(job["id"])["status"], "claimed")

    def test_supervisor_and_unknown_actors_cannot_claim(self):
        cid = self._one_job()
        with self.assertRaises(PermissionError):
            self.lite.claim_job(cid, worker="hermes")
        with self.assertRaises(KeyError):
            self.lite.claim_job(cid, worker="nobody")


class ConcurrencyAndHygieneTests(LiteTestCase):
    def test_two_processes_never_claim_the_same_job(self):
        from refall_lite import RefallLite
        cid = self.campaign()
        for name in ("i1", "i2", "i3"):
            self.lite.ingest_image(cid, family="f", name=name, image_sha256=sha(name), members=members(name), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        other = RefallLite(self.db, clock=self.clock)
        try:
            claims = [self.lite.claim_job(cid, worker="qwen"), other.claim_job(cid, worker="claude"),
                      self.lite.claim_job(cid, worker="qwen"), other.claim_job(cid, worker="claude")]
        finally:
            other.close()
        ids = [c["job"]["id"] for c in claims if c["claimed"]]
        self.assertEqual(len(ids), 3)
        self.assertEqual(len(set(ids)), 3)

    def test_submit_after_deadline_refused(self):
        cid = self.campaign(deadline_at=self.clock.now + 100)
        self.lite.ingest_image(cid, family="f", name="i", image_sha256=sha("i"), members=members("a"), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        self.clock.advance(200)
        self.assertFalse(self.lite.submit_result(cid, job["id"], job["claim_token"], good_result())["accepted"])
        self.assertEqual(self.lite.get_campaign(cid)["stop_reason"], "deadline")

    def test_secrets_in_worker_output_are_redacted_before_persistence(self):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="f", name="i", image_sha256=sha("i"), members=members("a"), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        leak = good_result(summary="found password=hunter2secret and AKIAABCDEFGHIJKLMNOP in nvram")
        self.assertTrue(self.lite.submit_result(cid, job["id"], job["claim_token"], leak)["accepted"])
        stored = self.lite.get_job(job["id"])["result"]["summary"]
        self.assertNotIn("hunter2secret", stored)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", stored)
        self.assertIn("password=[REDACTED]", stored)
        raw = self.db.read_bytes() + (self.db.with_name(self.db.name + "-wal").read_bytes() if self.db.with_name(self.db.name + "-wal").exists() else b"")
        self.assertNotIn(b"hunter2secret", raw)

    def test_deep_jobs_only_via_selection(self):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="f", name="i", image_sha256=sha("i"), members=members("a"), actor="hermes")
        with self.assertRaises(ValueError):
            self.lite.enqueue_job(cid, stage="deep", kind="deep", target_type="member", target_ref=sha("a"), actor="hermes")
