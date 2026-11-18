"""Boundedness: budgets and hard stop conditions."""
from __future__ import annotations

from tests.helpers import LiteTestCase, good_result, members, sha


class BudgetTests(LiteTestCase):
    def _ingest(self, cid, family, name, labels):
        return self.lite.ingest_image(cid, family=family, name=name, image_sha256=sha(name), members=members(*labels), actor="hermes")

    def test_campaign_requires_bounded_run_budget(self):
        with self.assertRaises(ValueError):
            self.lite.create_campaign("unbounded", config={"budgets": {}}, actor="hermes")
        with self.assertRaises(ValueError):
            self.lite.create_campaign("half", config={"budgets": {"run": {"max_claims": 5}}}, actor="hermes")

    def test_run_claim_budget_exhaustion_stops_campaign_and_survives_restart(self):
        cid = self.campaign(budgets={"run": {"max_claims": 2, "max_cost": 100}})
        self._ingest(cid, "famA", "imgA", ["a"])
        self._ingest(cid, "famA", "imgB", ["b"])
        self._ingest(cid, "famA", "imgC", ["c"])
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        for _ in range(2):
            job = self.lite.claim_job(cid, worker="qwen")["job"]
            self.assertTrue(self.lite.submit_result(cid, job["id"], job["claim_token"], good_result())["accepted"])
        self.reopen()
        third = self.lite.claim_job(cid, worker="qwen")
        self.assertFalse(third["claimed"])
        self.assertIn("budget_exhausted:run", third["reason"])
        camp = self.lite.get_campaign(cid)
        self.assertEqual(camp["status"], "stopped")
        self.assertEqual(camp["stop_reason"], "budget_exhausted:run")
        self.reopen()
        self.assertFalse(self.lite.claim_job(cid, worker="qwen")["claimed"])
        # queued work was cancelled by the hard stop, not left dangling
        self.assertEqual(self.lite.status(cid)["jobs"].get("queued", 0), 0)

    def test_run_cost_budget_exhaustion(self):
        cid = self.campaign(budgets={"run": {"max_claims": 100, "max_cost": 5}})
        self._ingest(cid, "famA", "imgA", ["a"])
        self._ingest(cid, "famA", "imgB", ["b"])
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        self.lite.submit_result(cid, job["id"], job["claim_token"], good_result(cost_units=5))
        res = self.lite.claim_job(cid, worker="qwen")
        self.assertFalse(res["claimed"])
        self.assertEqual(self.lite.get_campaign(cid)["stop_reason"], "budget_exhausted:run")

    def test_family_budget_blocks_only_that_family(self):
        cid = self.campaign(budgets={"family:famA": {"max_claims": 1, "max_cost": 100}})
        self._ingest(cid, "famA", "imgA1", ["a1"])
        self._ingest(cid, "famA", "imgA2", ["a2"])
        self._ingest(cid, "famB", "imgB1", ["b1"])
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        families = []
        while True:
            c = self.lite.claim_job(cid, worker="qwen")
            if not c["claimed"]:
                break
            families.append(c["job"]["family"])
            self.lite.submit_result(cid, c["job"]["id"], c["job"]["claim_token"], good_result())
        self.assertEqual(sorted(families), ["famA", "famB"])
        st = self.lite.status(cid)
        self.assertEqual(st["jobs"].get("budget_blocked"), 1)
        self.assertEqual(self.lite.get_campaign(cid)["status"], "active")
        kinds = [a["kind"] for a in self.lite.list_pending_actions(cid)]
        self.assertIn("budget_decision", kinds)

    def test_artifact_cost_budget(self):
        cid = self.campaign(budgets={"artifact:*": {"max_claims": 10, "max_cost": 3}}, max_attempts=5)
        img = self._ingest(cid, "famA", "imgA", ["a"])
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        self.lite.fail_job(cid, job["id"], job["claim_token"], status="provider_timeout", error="slow", cost_units=3)
        res = self.lite.claim_job(cid, worker="qwen")
        self.assertFalse(res["claimed"])
        self.assertEqual(self.lite.get_job(job["id"])["status"], "budget_blocked")
        self.assertEqual(self.lite.budget_usage(cid)[f"artifact:{img['image_id']}"]["cost_used"], 3)

    def test_model_cannot_raise_budget_but_supervisor_can(self):
        cid = self.campaign(budgets={"family:famA": {"max_claims": 1, "max_cost": 100}})
        self._ingest(cid, "famA", "imgA1", ["a1"])
        self._ingest(cid, "famA", "imgA2", ["a2"])
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        self.drain(cid, "inventory")
        with self.assertRaises(PermissionError):
            self.lite.raise_budget(cid, "family:famA", actor="qwen", max_claims=5)
        self.lite.raise_budget(cid, "family:famA", actor="hermes", max_claims=2, reason="operator extends famA")
        self.assertEqual(len(self.drain(cid, "inventory")), 1)

    def test_enqueue_ceiling(self):
        cid = self.campaign(max_jobs=2)
        self._ingest(cid, "famA", "imgA", ["a", "b", "c"])
        self.to_middle(cid)  # 1 inventory job
        res = self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        self.assertEqual(res["enqueued"], 1)
        self.assertEqual(res["refused"], 2)
        self.assertIn("max_jobs", res["reasons"][0])

    def test_deadline_hard_stop(self):
        cid = self.campaign(deadline_at=self.clock.now + 100)
        self._ingest(cid, "famA", "imgA", ["a"])
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        self.clock.advance(101)
        res = self.lite.claim_job(cid, worker="qwen")
        self.assertFalse(res["claimed"])
        self.assertEqual(self.lite.get_campaign(cid)["stop_reason"], "deadline")

    def test_operator_stop_cancels_and_refuses_late_submissions(self):
        cid = self.campaign()
        self._ingest(cid, "famA", "imgA", ["a"])
        self._ingest(cid, "famA", "imgB", ["b"])
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        with self.assertRaises(PermissionError):
            self.lite.stop_campaign(cid, actor="qwen", reason="worker wants out")
        self.lite.stop_campaign(cid, actor="hermes", reason="operator stop")
        late = self.lite.submit_result(cid, job["id"], job["claim_token"], good_result())
        self.assertFalse(late["accepted"])
        st = self.lite.status(cid)
        self.assertEqual(st["jobs"].get("cancelled"), 2)
        self.assertFalse(self.lite.claim_job(cid, worker="qwen")["claimed"])
        with self.assertRaises(ValueError):
            self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory2", actor="hermes")
        kinds = [e["kind"] for e in self.lite.ledger(cid)]
        self.assertIn("runtime-event", kinds)  # late submission recorded for audit
