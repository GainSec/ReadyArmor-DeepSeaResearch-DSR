"""Stage gates: inventory -> middle -> deep (selective) -> fuzz_ready (escalation)."""
from __future__ import annotations

from tests.helpers import LiteTestCase, check_receipt, members, model_finding, sha

HARNESS = {"artifact_refs": ["harness:httpd-parse-header.c", "build-log:ok"], "summary": "harness builds and runs on corpus"}


class StageTests(LiteTestCase):
    def setUp(self):
        super().setUp()
        self.cid = self.campaign()
        self.lite.ingest_image(self.cid, family="routerX", name="rx", image_sha256=sha("rx"), members=members("httpd", "busybox"), actor="hermes")
        self.lite.ingest_image(self.cid, family="camY", name="cy", image_sha256=sha("cy"), members=members("rtspd"), actor="hermes")

    def test_cannot_enqueue_ahead_of_stage(self):
        with self.assertRaises(ValueError):
            self.lite.enqueue_member_jobs(self.cid, stage="middle", kind="triage", actor="hermes")
        with self.assertRaises(ValueError):
            self.lite.select_for_deep(self.cid, sha("httpd"), actor="hermes", reason="looks juicy")

    def test_inventory_gate_requires_inventory_jobs_terminal(self):
        self.lite.enqueue_image_jobs(self.cid, stage="inventory", kind="inventory", actor="hermes")
        res = self.lite.advance_stage(self.cid, actor="hermes")
        self.assertFalse(res["advanced"])
        self.assertIn("active inventory jobs", " ".join(res["reasons"]))

    def test_model_cannot_advance_stage(self):
        self.lite.enqueue_image_jobs(self.cid, stage="inventory", kind="inventory", actor="hermes")
        self.drain(self.cid, "inventory")
        with self.assertRaises(PermissionError):
            self.lite.advance_stage(self.cid, actor="qwen")

    def test_middle_gate_requires_every_family_covered(self):
        self.to_middle(self.cid)
        self.lite.enqueue_job(self.cid, stage="middle", kind="triage", target_type="member", target_ref=sha("httpd"), actor="hermes")
        self.drain(self.cid, "middle")
        res = self.lite.advance_stage(self.cid, actor="hermes")
        self.assertFalse(res["advanced"])
        self.assertIn("camY", " ".join(res["reasons"]))
        self.lite.enqueue_member_jobs(self.cid, stage="middle", kind="triage", actor="hermes")
        self.drain(self.cid, "middle")
        self.assertTrue(self.lite.advance_stage(self.cid, actor="hermes")["advanced"])
        self.assertEqual(self.lite.get_campaign(self.cid)["current_stage"], "deep")

    def _to_deep(self):
        self.to_middle(self.cid)
        self.lite.enqueue_member_jobs(self.cid, stage="middle", kind="triage", actor="hermes")
        done = self.drain(self.cid, "middle", findings_for={sha("httpd"): model_finding(sha("httpd"))})
        self.assertTrue(self.lite.advance_stage(self.cid, actor="hermes")["advanced"])
        return [fid for d in done for fid in d["finding_ids"]][0]

    def test_selective_deep_requires_supervisor_reason_and_middle_success(self):
        self._to_deep()
        with self.assertRaises(PermissionError):
            self.lite.select_for_deep(self.cid, sha("httpd"), actor="qwen", reason="I want it")
        self.assertFalse(self.lite.select_for_deep(self.cid, sha("httpd"), actor="hermes", reason="")["accepted"])
        self.assertFalse(self.lite.select_for_deep(self.cid, sha("never-seen"), actor="hermes", reason="x")["accepted"])
        ok = self.lite.select_for_deep(self.cid, sha("httpd"), actor="hermes", reason="finding hypothesis on parser")
        self.assertTrue(ok["accepted"], ok)
        self.assertEqual(ok["job"]["stage"], "deep")
        dup = self.lite.select_for_deep(self.cid, sha("httpd"), actor="hermes", reason="again")
        self.assertTrue(dup["deduplicated"])

    def test_deep_selection_cap(self):
        self.lite.close()
        self.lite = self.open()
        cid = self.lite.create_campaign("capped", config={"budgets": {"run": {"max_claims": 50, "max_cost": 50}}, "max_deep_selections": 1}, actor="hermes")["id"]
        self.lite.ingest_image(cid, family="f", name="i", image_sha256=sha("i"), members=members("p", "q"), actor="hermes")
        self.to_middle(cid)
        self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        self.drain(cid, "middle")
        self.lite.advance_stage(cid, actor="hermes")
        self.assertTrue(self.lite.select_for_deep(cid, sha("p"), actor="hermes", reason="r")["accepted"])
        res = self.lite.select_for_deep(cid, sha("q"), actor="hermes", reason="r")
        self.assertFalse(res["accepted"])
        self.assertIn("max_deep_selections", " ".join(res["reasons"]))

    def test_fuzz_escalation_gate(self):
        fid = self._to_deep()
        self.lite.select_for_deep(self.cid, sha("httpd"), actor="hermes", reason="parser")
        self.drain(self.cid, "deep")
        # hypothesis-tier finding cannot justify escalation
        res = self.lite.request_escalation(self.cid, sha("httpd"), actor="qwen", finding_id=fid, receipt=HARNESS)
        self.assertFalse(res["accepted"])
        self.lite.transition_finding(self.cid, fid, actor="checker", to="independently_checked",
                                     receipt_type="independent_check", receipt=check_receipt())
        no_harness = self.lite.request_escalation(self.cid, sha("httpd"), actor="qwen", finding_id=fid, receipt={"summary": "trust me"})
        self.assertFalse(no_harness["accepted"])
        req = self.lite.request_escalation(self.cid, sha("httpd"), actor="qwen", finding_id=fid, receipt=HARNESS)
        self.assertTrue(req["accepted"], req)
        action_id = req["action"]["id"]
        self.assertFalse(self.lite.approve_escalation(self.cid, action_id, actor="claude", receipt={"summary": "ok"})["accepted"])
        self.reopen()
        appr = self.lite.approve_escalation(self.cid, action_id, actor="hermes", receipt={"summary": "harness ready; OSS-CRS optional", "evidence_refs": ["harness:httpd-parse-header.c"]})
        self.assertTrue(appr["accepted"], appr)
        self.assertEqual(appr["job"]["stage"], "fuzz_ready")
        self.assertEqual(appr["job"]["payload"]["lane_hint"], "oss-crs-optional")
        self.assertTrue(self.lite.advance_stage(self.cid, actor="hermes")["advanced"])

    def test_requester_cannot_self_approve_escalation(self):
        fid = self._to_deep()
        self.lite.transition_finding(self.cid, fid, actor="checker", to="independently_checked",
                                     receipt_type="independent_check", receipt=check_receipt())
        req = self.lite.request_escalation(self.cid, sha("httpd"), actor="hermes", finding_id=fid, receipt=HARNESS)
        res = self.lite.approve_escalation(self.cid, req["action"]["id"], actor="hermes", receipt={"summary": "self"})
        self.assertFalse(res["accepted"])
        self.assertIn("requester", " ".join(res["reasons"]))
        self.assertTrue(self.lite.approve_escalation(self.cid, req["action"]["id"], actor="analyst", receipt={"summary": "ok", "evidence_refs": ["h"]})["accepted"])
