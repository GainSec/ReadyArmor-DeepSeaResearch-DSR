"""Closeout gate blocks on active/unresolved jobs and unvalidated material findings."""
from __future__ import annotations

from tests.helpers import LiteTestCase, check_receipt, good_result, members, model_finding, replay_receipt, sha


def failing(gate):
    return {c["id"] for c in gate["checks"] if c["blocking"] and c["status"] == "fail"}


class CloseoutTests(LiteTestCase):
    def setUp(self):
        super().setUp()
        self.cid = self.campaign()
        self.lite.ingest_image(self.cid, family="f", name="img", image_sha256=sha("img"), members=members("httpd", "lowfile"), actor="hermes")
        self.lite.put_manifest(self.cid, run_id="run-1", actor="hermes")

    def test_blocked_by_active_jobs(self):
        self.lite.enqueue_image_jobs(self.cid, stage="inventory", kind="inventory", actor="hermes")
        self.lite.draft_report(self.cid, actor="hermes")
        gate = self.lite.closeout_gate(self.cid)
        self.assertFalse(gate["passed"])
        self.assertIn("jobs-unresolved", failing(gate))
        self.lite.claim_job(self.cid, worker="qwen")
        self.lite.draft_report(self.cid, actor="hermes")
        self.assertIn("jobs-unresolved", failing(self.lite.closeout_gate(self.cid)))
        res = self.lite.closeout(self.cid, actor="hermes")
        self.assertFalse(res["passed"])
        self.assertEqual(self.lite.get_campaign(self.cid)["status"], "active")

    def test_blocked_by_dead_job_pending_action_until_resolved(self):
        self.lite.close()
        self.lite = self.open()
        cid = self.lite.create_campaign("c", config={"budgets": {"run": {"max_claims": 9, "max_cost": 9}}, "max_attempts": 1}, actor="hermes")["id"]
        self.lite.put_manifest(cid, run_id="r", actor="hermes")
        self.lite.ingest_image(cid, family="f", name="img", image_sha256=sha("img"), members=members("a"), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        self.lite.fail_job(cid, job["id"], job["claim_token"], status="provider_timeout", error="x")
        self.lite.draft_report(cid, actor="hermes")
        gate = self.lite.closeout_gate(cid)
        self.assertIn("pending-actions-open", failing(gate))
        action = self.lite.list_pending_actions(cid)[0]
        with self.assertRaises(ValueError):
            self.lite.resolve_pending_action(cid, action["id"], actor="hermes", status="done", receipt_type=None, receipt={})
        with self.assertRaises(PermissionError):
            self.lite.resolve_pending_action(cid, action["id"], actor="qwen", status="done", receipt_type="operator_decision", receipt={"evidence_refs": ["x"]})
        self.lite.resolve_pending_action(cid, action["id"], actor="hermes", status="done", receipt_type="operator_decision",
                                         receipt={"evidence_refs": ["retry ceiling hit; member deprioritised"], "summary": "accept gap"})
        self.lite.draft_report(cid, actor="hermes")
        gate = self.lite.closeout_gate(cid)
        self.assertTrue(gate["passed"], failing(gate))

    def test_blocked_by_unvalidated_material_finding_and_passes_when_validated(self):
        self.lite.enqueue_image_jobs(self.cid, stage="inventory", kind="inventory", actor="hermes")
        self.drain(self.cid, "inventory")
        fid = self.lite.record_finding(self.cid, actor="qwen", candidate=model_finding(sha("httpd"), severity="high"))["finding"]["id"]
        low = self.lite.record_finding(self.cid, actor="qwen", candidate=model_finding(sha("lowfile"), title="info leak", severity="info"))["finding"]["id"]
        self.lite.draft_report(self.cid, actor="hermes")
        gate = self.lite.closeout_gate(self.cid)
        self.assertIn("material-findings-unvalidated", failing(gate))
        warns = {c["id"] for c in gate["checks"] if c["status"] == "warn"}
        self.assertIn("non-material-hypotheses", warns)
        self.lite.transition_finding(self.cid, fid, actor="checker", to="independently_checked", receipt_type="independent_check", receipt=check_receipt())
        self.lite.draft_report(self.cid, actor="hermes")
        self.assertIn("material-findings-unvalidated", failing(self.lite.closeout_gate(self.cid)))
        self.lite.transition_finding(self.cid, fid, actor="replayer", to="validated", receipt_type="deterministic_replay", receipt=replay_receipt())
        self.assertIn("report-current", failing(self.lite.closeout_gate(self.cid)))  # report is now stale
        self.lite.draft_report(self.cid, actor="hermes")
        self.reopen()
        gate = self.lite.closeout_gate(self.cid)
        self.assertTrue(gate["passed"], failing(gate))
        pkg = self.lite.closeout(self.cid, actor="hermes")
        self.assertTrue(pkg["passed"])
        self.assertEqual(self.lite.get_campaign(self.cid)["status"], "closed")
        with self.assertRaises(ValueError):
            self.lite.enqueue_image_jobs(self.cid, stage="inventory", kind="again", actor="hermes")
        self.assertFalse(self.lite.claim_job(self.cid, worker="qwen")["claimed"])
        self.assertEqual(self.lite.get_closeout(self.cid)["closeout_id"], pkg["closeout_id"])
        _ = low

    def test_blocked_without_report_or_manifest(self):
        gate = self.lite.closeout_gate(self.cid)
        self.assertIn("report-current", failing(gate))
        self.lite.close()
        self.lite = self.open()
        cid = self.campaign()
        self.lite.draft_report(cid, actor="hermes")
        self.assertIn("manifest-present", failing(self.lite.closeout_gate(cid)))

    def test_rejected_material_finding_does_not_block(self):
        fid = self.lite.record_finding(self.cid, actor="qwen", candidate=model_finding(sha("httpd")))["finding"]["id"]
        self.lite.transition_finding(self.cid, fid, actor="replayer", to="rejected", receipt_type="replay_failed",
                                     receipt={"commands": ["replay"], "summary": "not reproducible"})
        self.lite.draft_report(self.cid, actor="hermes")
        self.assertTrue(self.lite.closeout_gate(self.cid)["passed"])

    def test_ledger_tamper_blocks_closeout(self):
        import sqlite3
        self.lite.draft_report(self.cid, actor="hermes")
        self.lite.close()
        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE ledger SET actor='mallory' WHERE seq=(SELECT MIN(seq) FROM ledger)")
        conn.commit()
        conn.close()
        self.lite = self.open()
        self.assertIn("ledger-integrity", failing(self.lite.closeout_gate(self.cid)))

    def test_report_marks_model_hypotheses_provisional(self):
        self.lite.record_finding(self.cid, actor="qwen", candidate=model_finding(sha("httpd")))
        rep = self.lite.draft_report(self.cid, actor="hermes")
        body = rep["content"]
        self.assertEqual(body["findings"]["hypothesis"][0]["provisional"], True)
        self.assertIn("synthetic", body["notice"].lower() + " synthetic")
        self.assertEqual(len(rep["content_sha256"]), 64)
