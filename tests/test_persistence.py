"""Restart/resume: every assertion here closes and reopens the ArcticBase store."""
from __future__ import annotations

import sqlite3

from tests.helpers import LiteTestCase, good_result, members, sha


class PersistenceTests(LiteTestCase):
    def test_campaign_and_config_survive_reopen(self):
        cid = self.campaign()
        self.reopen()
        camp = self.lite.get_campaign(cid)
        self.assertEqual(camp["status"], "active")
        self.assertEqual(camp["current_stage"], "inventory")
        self.assertEqual(camp["config"]["budgets"]["run"]["max_claims"], 100)

    def test_claim_close_reopen_then_submit(self):
        cid = self.campaign()
        img = self.lite.ingest_image(cid, family="famA", name="imgA", image_sha256=sha("imgA"), members=members("busybox"), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        claim = self.lite.claim_job(cid, worker="qwen")
        self.assertTrue(claim["claimed"])
        job_id, token = claim["job"]["id"], claim["job"]["claim_token"]
        self.reopen()
        self.assertEqual(self.lite.get_job(job_id)["status"], "claimed")
        res = self.lite.submit_result(cid, job_id, token, good_result())
        self.assertTrue(res["accepted"], res)
        self.reopen()
        self.assertEqual(self.lite.get_job(job_id)["status"], "succeeded")
        self.assertEqual(self.lite.get_job(job_id)["target_ref"], img["image_id"])

    def test_lease_expiry_reclaimed_on_resume_after_crash(self):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="famA", name="imgA", image_sha256=sha("imgA"), members=members("busybox"), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        job = self.lite.claim_job(cid, worker="qwen")["job"]
        # simulate crash: worker vanishes, store closed without submit
        self.clock.advance(61)
        self.reopen()
        res = self.lite.resume(cid, actor="hermes")
        self.assertIn(job["id"], res["reclaimed"])
        again = self.lite.get_job(job["id"])
        self.assertEqual(again["status"], "queued")
        self.assertEqual(again["attempts"], 1)
        self.assertEqual(again["failure_class"], "lease_expired")
        # old token is dead
        late = self.lite.submit_result(cid, job["id"], job["claim_token"], good_result())
        self.assertFalse(late["accepted"])

    def test_checkpoint_resume_preflight_detects_drift(self):
        cid = self.campaign()
        self.lite.put_manifest(cid, run_id="run-1", actor="hermes", provider_roles={"supervisor": "hermes", "worker": "qwen"})
        self.lite.checkpoint(cid, stage="inventory", key="inventory:imgA", input_hashes={"image:imgA": sha("imgA")}, actor="hermes")
        self.reopen()
        ok = self.lite.resume(cid, actor="hermes", current_hashes={"image:imgA": sha("imgA")})
        self.assertTrue(ok["preflight"]["accepted"])
        self.assertEqual(ok["manifest"]["run_id"], "run-1")
        self.reopen()
        drift = self.lite.resume(cid, actor="hermes", current_hashes={"image:imgA": sha("imgA-v2")})
        self.assertFalse(drift["preflight"]["accepted"])
        self.assertEqual(drift["preflight"]["changes"][0]["reason"], "changed")
        kinds = [a["kind"] for a in self.lite.list_pending_actions(cid)]
        self.assertIn("resume_drift_decision", kinds)

    def test_ledger_hash_chain_survives_reopen_and_detects_tamper(self):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="famA", name="imgA", image_sha256=sha("imgA"), members=members("a", "b"), actor="hermes")
        self.reopen()
        self.assertTrue(self.lite.verify_ledger(cid)["ok"])
        self.assertGreaterEqual(len(self.lite.ledger(cid)), 2)
        self.lite.close()
        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE ledger SET payload='{\"forged\":true}' WHERE seq=(SELECT MIN(seq) FROM ledger)")
        conn.commit()
        conn.close()
        self.lite = self.open()
        self.assertFalse(self.lite.verify_ledger(cid)["ok"])

    def test_store_identifies_as_arcticbase_lite(self):
        meta = self.lite.store_info()
        self.assertEqual(meta["layer"], "ArcticBase REFALL state layer")
        self.assertEqual(meta["profile"], "lite")
