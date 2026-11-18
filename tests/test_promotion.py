"""Evidence promotion: model hypothesis -> independently checked -> validated."""
from __future__ import annotations

from tests.helpers import LiteTestCase, check_receipt, good_result, members, model_finding, replay_receipt, sha


class PromotionTests(LiteTestCase):
    def setUp(self):
        super().setUp()
        self.cid = self.campaign()
        self.lite.ingest_image(self.cid, family="f", name="img", image_sha256=sha("img"), members=members("httpd"), actor="hermes")
        self.m = sha("httpd")

    def _finding(self, actor="qwen", **extra):
        res = self.lite.record_finding(self.cid, actor=actor, candidate=model_finding(self.m, **extra))
        self.assertTrue(res["accepted"], res)
        return res["finding"]["id"]

    def _check(self, fid, actor="checker"):
        return self.lite.transition_finding(self.cid, fid, actor=actor, to="independently_checked",
                                            receipt_type="independent_check", receipt=check_receipt())

    def _validate(self, fid, actor="replayer", receipt=None):
        return self.lite.transition_finding(self.cid, fid, actor=actor, to="validated",
                                            receipt_type="deterministic_replay", receipt=receipt or replay_receipt())

    def test_worker_claim_of_validated_is_downgraded_to_hypothesis(self):
        fid = self._finding(tier="validated", status="VALID", quality_tier="LIVE_CONFIRMED")
        f = self.lite.get_finding(fid)
        self.assertEqual(f["tier"], "hypothesis")
        self.assertTrue(any("provisional" in lim for lim in f["limitations"]))
        self.assertEqual(f["origin_kind"], "model")

    def test_model_only_finding_cannot_reach_validated(self):
        fid = self._finding()
        # model tries to check its own and another model's work
        for actor in ("qwen", "claude", "hermes"):
            res = self._check(fid, actor=actor)
            self.assertFalse(res["accepted"], actor)
            res = self._validate(fid, actor=actor)
            self.assertFalse(res["accepted"], actor)
        # even with a perfect replay receipt, validated cannot be reached from hypothesis directly
        res = self._validate(fid, actor="replayer")
        self.assertFalse(res["accepted"])
        self.assertIn("independently_checked", " ".join(res["reasons"]))
        self.reopen()
        self.assertEqual(self.lite.get_finding(fid)["tier"], "hypothesis")
        refused = [t for t in self.lite.list_transitions(self.cid, fid) if t["status"] == "refused"]
        self.assertEqual(len(refused), 7)

    def test_model_claimed_checker_kind_refused(self):
        fid = self._finding()
        res = self.lite.transition_finding(self.cid, fid, actor="checker", to="independently_checked",
                                           receipt_type="independent_check", receipt=check_receipt(checker_kind="model"))
        self.assertFalse(res["accepted"])

    def test_full_promotion_path_preserves_limitations_and_anchors(self):
        fid = self._finding()
        self.assertTrue(self._check(fid)["accepted"])
        self.reopen()
        self.assertTrue(self._validate(fid)["accepted"])
        f = self.lite.get_finding(fid)
        self.assertEqual(f["tier"], "validated")
        self.assertIn("static strings only", f["limitations"])
        self.assertIn("etc/passwd:3", f["source_anchors"])
        self.assertIn(f"member:{self.m}", f["artifact_refs"])
        self.assertEqual(len(f["receipts"]), 2)

    def test_validated_requires_two_matching_replays(self):
        fid = self._finding()
        self._check(fid)
        res = self._validate(fid, receipt=replay_receipt(out_a=sha("one"), out_b=sha("two")))
        self.assertFalse(res["accepted"])
        self.assertIn("replay outputs differ", " ".join(res["reasons"]))
        single = replay_receipt()
        single["replays"] = single["replays"][:1]
        self.assertFalse(self._validate(fid, receipt=single)["accepted"])
        no_cmd = replay_receipt(commands=[])
        self.assertFalse(self._validate(fid, receipt=no_cmd)["accepted"])

    def test_checker_cannot_be_finding_creator(self):
        fid = self._finding(actor="checker")
        res = self._check(fid, actor="checker")
        self.assertFalse(res["accepted"])
        self.assertIn("creator", " ".join(res["reasons"]))

    def test_candidate_without_anchors_or_evidence_refused(self):
        bad = model_finding(self.m)
        bad["artifact_refs"] = []
        bad["source_anchors"] = []
        res = self.lite.record_finding(self.cid, actor="qwen", candidate=bad)
        self.assertFalse(res["accepted"])
        bad2 = model_finding(self.m, evidence=[], confidence="")
        bad2["source_anchors"] = []
        res2 = self.lite.record_finding(self.cid, actor="qwen", candidate=bad2)
        self.assertFalse(res2["accepted"])
        self.assertIn("missing confidence", res2["reasons"])

    def test_candidate_for_unknown_member_refused(self):
        res = self.lite.record_finding(self.cid, actor="qwen", candidate=model_finding(sha("not-ingested")))
        self.assertFalse(res["accepted"])

    def test_reject_requires_typed_receipt_and_non_model(self):
        fid = self._finding()
        self.assertFalse(self.lite.transition_finding(self.cid, fid, actor="hermes", to="rejected", receipt_type=None, receipt={})["accepted"])
        self.assertFalse(self.lite.transition_finding(self.cid, fid, actor="qwen", to="rejected", receipt_type="replay_failed",
                                                      receipt={"commands": ["x"]})["accepted"])
        ok = self.lite.transition_finding(self.cid, fid, actor="hermes", to="rejected", receipt_type="replay_failed",
                                          receipt={"commands": ["python3 replay.py"], "summary": "did not reproduce"})
        self.assertTrue(ok["accepted"], ok)
        self.assertEqual(self.lite.get_finding(fid)["tier"], "rejected")

    def test_duplicate_requires_target(self):
        fid = self._finding()
        other = self._finding(title="Different root cause")
        self.assertFalse(self.lite.transition_finding(self.cid, fid, actor="hermes", to="duplicate", receipt_type="duplicate_evidence",
                                                      receipt={"evidence_refs": ["x"]})["accepted"])
        ok = self.lite.transition_finding(self.cid, fid, actor="hermes", to="duplicate", receipt_type="duplicate_evidence",
                                          receipt={"evidence_refs": ["same sink"]}, duplicate_of=other)
        self.assertTrue(ok["accepted"], ok)

    def test_findings_via_worker_submission_are_hypotheses(self):
        self.to_middle(self.cid)
        self.lite.enqueue_member_jobs(self.cid, stage="middle", kind="triage", actor="hermes")
        job = self.lite.claim_job(self.cid, worker="qwen")["job"]
        sub = good_result(findings=[model_finding(self.m, tier="validated")])
        res = self.lite.submit_result(self.cid, job["id"], job["claim_token"], sub)
        self.assertTrue(res["accepted"], res)
        f = self.lite.get_finding(res["finding_ids"][0])
        self.assertEqual(f["tier"], "hypothesis")
        self.assertEqual(f["job_id"], job["id"])
