"""Member SHA-256 dedup and occurrence propagation across images/families."""
from __future__ import annotations

from tests.helpers import LiteTestCase, check_receipt, members, model_finding, sha


class DedupTests(LiteTestCase):
    def test_identical_member_analyzed_once_with_all_occurrences(self):
        cid = self.campaign()
        a = self.lite.ingest_image(cid, family="routerX", name="rx-1.0", image_sha256=sha("rx-1.0"), members=members("busybox", "httpd"), actor="hermes")
        b = self.lite.ingest_image(cid, family="routerX", name="rx-1.1", image_sha256=sha("rx-1.1"), members=members("busybox", "httpd2"), actor="hermes")
        c = self.lite.ingest_image(cid, family="camY", name="cy-2.0", image_sha256=sha("cy-2.0"),
                                   members=[{"path": "/bin/busybox", "sha256": sha("busybox"), "size_bytes": 100}], actor="hermes")
        self.assertEqual(a["new_members"], 2)
        self.assertEqual(b["new_members"], 1)
        self.assertEqual(b["duplicate_members"], 1)
        self.assertEqual(c["duplicate_members"], 1)
        self.to_middle(cid)
        first = self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        self.assertEqual(first["enqueued"], 3)  # busybox, httpd, httpd2
        again = self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        self.assertEqual(again["enqueued"], 0)
        self.assertEqual(again["deduplicated"], 3)
        done = self.drain(cid, "middle")
        busybox_jobs = [d for d in done if d["job"]["target_ref"] == sha("busybox")]
        self.assertEqual(len(busybox_jobs), 1)
        self.reopen()
        occ = self.lite.member_occurrences(cid, sha("busybox"))
        self.assertEqual(len(occ), 3)
        self.assertEqual(sorted({o["family"] for o in occ}), ["camY", "routerX"])
        self.assertEqual(sorted(o["path"] for o in occ), ["/bin/busybox", "/usr/bin/busybox", "/usr/bin/busybox"])
        member = self.lite.get_member(cid, sha("busybox"))
        self.assertEqual(member["occurrence_count"], 3)
        self.assertEqual(member["primary_family"], "routerX")

    def test_same_image_reingest_is_idempotent(self):
        cid = self.campaign()
        first = self.lite.ingest_image(cid, family="f", name="img", image_sha256=sha("img"), members=members("a"), actor="hermes")
        second = self.lite.ingest_image(cid, family="f", name="img", image_sha256=sha("img"), members=members("a"), actor="hermes")
        self.assertEqual(first["image_id"], second["image_id"])
        self.assertEqual(second["occurrences_added"], 0)
        self.assertEqual(len(self.lite.member_occurrences(cid, sha("a"))), 1)

    def test_bad_sha_rejected(self):
        cid = self.campaign()
        with self.assertRaises(ValueError):
            self.lite.ingest_image(cid, family="f", name="img", image_sha256=sha("img"),
                                   members=[{"path": "/x", "sha256": "abc"}], actor="hermes")

    def test_finding_propagates_to_occurrences_ingested_later(self):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="routerX", name="rx-1.0", image_sha256=sha("rx-1.0"), members=members("httpd"), actor="hermes")
        self.to_middle(cid)
        self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        done = self.drain(cid, "middle", findings_for={sha("httpd"): model_finding(sha("httpd"))})
        fid = done[0]["finding_ids"][0]
        self.assertEqual(len(self.lite.finding_occurrences(fid)), 1)
        # a later image in a different family ships the identical httpd
        self.lite.ingest_image(cid, family="camY", name="cy-2.0", image_sha256=sha("cy-2.0"), members=members("httpd"), actor="hermes")
        self.reopen()
        occ = self.lite.finding_occurrences(fid)
        self.assertEqual(sorted(o["image_name"] for o in occ), ["cy-2.0", "rx-1.0"])
        self.assertEqual(sorted({o["family"] for o in occ}), ["camY", "routerX"])
        # and no re-analysis job was created for the duplicate member
        res = self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        self.assertEqual(res["enqueued"], 0)

    def test_finding_dedup_merges_evidence_and_limitations(self):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="f", name="img", image_sha256=sha("img"), members=members("httpd"), actor="hermes")
        f1 = self.lite.record_finding(cid, actor="qwen", candidate=model_finding(sha("httpd")))
        f2 = self.lite.record_finding(cid, actor="claude", candidate=model_finding(
            sha("httpd"), limitations=["second model, same root cause"],
            evidence=[{"kind": "xref", "ref": "fn:check_auth", "claim": "compared against constant"}]))
        self.assertEqual(f1["finding"]["id"], f2["finding"]["id"])
        self.assertTrue(f2["merged"])
        merged = self.lite.get_finding(f1["finding"]["id"])
        self.assertIn("static strings only", merged["limitations"])
        self.assertIn("second model, same root cause", merged["limitations"])
        self.assertEqual(len(merged["evidence"]), 2)
        self.assertEqual(len(self.lite.list_findings(cid)), 1)
        self.assertEqual(sorted(merged["contributors"]), ["claude", "qwen"])

    def test_merge_does_not_reset_promoted_tier(self):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="f", name="img", image_sha256=sha("img"), members=members("httpd"), actor="hermes")
        fid = self.lite.record_finding(cid, actor="qwen", candidate=model_finding(sha("httpd")))["finding"]["id"]
        self.assertTrue(self.lite.transition_finding(cid, fid, actor="checker", to="independently_checked",
                                                     receipt_type="independent_check", receipt=check_receipt())["accepted"])
        self.lite.record_finding(cid, actor="claude", candidate=model_finding(sha("httpd")))
        self.assertEqual(self.lite.get_finding(fid)["tier"], "independently_checked")
