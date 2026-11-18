"""The ``known_cve`` disposition: when a finding's vuln is an already-disclosed
CVE in a known component, it is saved as an actionable *lead* (a terminal,
receipted disposition carrying the CVE refs) instead of being promoted as novel.

Parallel to the existing ``rejected``/``duplicate`` dispositions: a non-model
actor, a typed receipt (``prior_art_cve``), and receipt material are required.
"""
from __future__ import annotations

from tests.helpers import LiteTestCase, members, model_finding, sha


def prior_art_receipt(**extra) -> dict:
    receipt = {
        "checker_kind": "deterministic_tool",
        "component": "busybox",
        "version": "1.31.0",
        "evidence_refs": ["CVE-2021-28831 https://nvd.nist.gov/vuln/detail/CVE-2021-28831"],
        "commands": [
            "GET https://hashlookup.circl.lu/lookup/sha256/<member>",
            "GET https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:busybox:busybox:1.31.0",
        ],
        "summary": "member sha256 == busybox 1.31.0 (CIRCL); CVE-2021-28831 covers the decompress primitive",
    }
    receipt.update(extra)
    return receipt


class KnownCveDispositionTests(LiteTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.cid = self.campaign()
        self.lite.ingest_image(self.cid, family="f", name="img", image_sha256=sha("img"),
                               members=members("busybox"), actor="hermes")
        self.m = sha("busybox")

    def _finding(self, actor: str = "qwen", **extra) -> str:
        res = self.lite.record_finding(self.cid, actor=actor, candidate=model_finding(self.m, **extra))
        self.assertTrue(res["accepted"], res)
        return res["finding"]["id"]

    def _dispose(self, fid, *, actor="checker", receipt_type="prior_art_cve", receipt=None):
        return self.lite.transition_finding(self.cid, fid, actor=actor, to="known_cve",
                                            receipt_type=receipt_type, receipt=receipt or prior_art_receipt())

    def test_tool_disposes_hypothesis_to_known_cve_with_prior_art_receipt(self):
        fid = self._finding()
        res = self._dispose(fid)
        self.assertTrue(res["accepted"], res["reasons"])
        f = self.lite.get_finding(fid)
        self.assertEqual(f["tier"], "known_cve")
        # the CVE lead is preserved in a replayable receipt
        self.assertEqual(len(f["receipts"]), 1)
        self.assertIn("CVE-2021-28831", " ".join(f["receipts"][0]["receipt"]["evidence_refs"]))

    def test_known_cve_is_terminal_so_a_lead_is_never_later_promoted(self):
        fid = self._finding()
        self.assertTrue(self._dispose(fid)["accepted"])
        self.reopen()
        res = self.lite.transition_finding(self.cid, fid, actor="checker", to="independently_checked",
                                           receipt_type="independent_check", receipt=prior_art_receipt())
        self.assertFalse(res["accepted"])
        self.assertIn("terminal", " ".join(res["reasons"]))

    def test_model_actor_cannot_dispose_as_known_cve(self):
        fid = self._finding()
        res = self._dispose(fid, actor="qwen")
        self.assertFalse(res["accepted"])
        self.assertIn("model actors cannot dispose", " ".join(res["reasons"]))

    def test_known_cve_requires_prior_art_cve_receipt_type(self):
        fid = self._finding()
        res = self._dispose(fid, receipt_type="independent_check")
        self.assertFalse(res["accepted"])
        self.assertIn("prior_art_cve", " ".join(res["reasons"]))

    def test_known_cve_requires_receipt_material(self):
        fid = self._finding()
        res = self._dispose(fid, receipt=prior_art_receipt(evidence_refs=[], commands=[]))
        self.assertFalse(res["accepted"])
        self.assertIn("suppressive transition requires receipt", " ".join(res["reasons"]))

    def test_status_and_report_bucket_count_the_lead(self):
        # engine.status() and closeout.draft_report() both enumerate dispositions;
        # a known_cve finding must land in its own bucket, not KeyError or vanish.
        fid = self._finding()
        self.assertTrue(self._dispose(fid)["accepted"])
        self.reopen()
        self.assertEqual(self.lite.status(self.cid)["findings"].get("known_cve"), 1)
        rep = self.lite.draft_report(self.cid, actor="hermes")
        self.assertIn(fid, [x["id"] for x in rep["content"]["findings"]["known_cve"]])
