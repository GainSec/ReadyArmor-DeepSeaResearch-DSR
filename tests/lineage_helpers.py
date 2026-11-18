"""Fixtures for lineage tests. Synthetic observations only."""
from __future__ import annotations

from tests.helpers import LiteTestCase, check_receipt, good_result, model_finding, replay_receipt, sha

ALG = "lite-fp-v1"


def obs(kind, value, **kw):
    item = {"kind": kind, "value": value, "analyzer": "synthetic-fp", "analyzer_version": "1"}
    item.update(kw)
    return item


FUNCS = [f"fn{i:03d}" for i in range(20)]


def strong_obs(build: str, func_drop: int = 0, extra_funcs: tuple = ()):
    """Multi-signal lineage evidence for an httpd-3.2 build variant."""
    funcs = FUNCS[func_drop:] + list(extra_funcs)
    return [
        obs("package_version", "acme-httpd@3.2"),
        obs("function_hashes", funcs),
        obs("source_paths", ["src/httpd/main.c", "src/httpd/auth.c", "src/httpd/cgi.c"]),
        obs("language", "C"), obs("isa", "mips32"), obs("compiler", "gcc-9.3"),
        obs("version_string", f"acme-httpd 3.2 build {build}"),
    ]


class LineageCase(LiteTestCase):
    """Three products, an httpd lineage (A, B variant; C variant in another family)."""

    def setUp(self):
        super().setUp()
        self.lite.register_actor("fp-tool", kind="tool", provider="synthetic-fingerprinter")

    def lineage_campaign(self, **cfg):
        cid = self.campaign(**cfg)
        self.A, self.B, self.C = sha("httpd-buildA"), sha("httpd-buildB"), sha("httpd-buildC")
        self.U = sha("unrelated-webd")
        self.lite.ingest_image(cid, family="router", name="r-1.0", image_sha256=sha("r-1.0"), actor="hermes", members=[
            {"path": "/usr/sbin/httpd", "sha256": self.A, "size_bytes": 1000},
            {"path": "/bin/busybox", "sha256": sha("busybox"), "size_bytes": 500}])
        self.lite.ingest_image(cid, family="router", name="r-1.1", image_sha256=sha("r-1.1"), actor="hermes", members=[
            {"path": "/usr/sbin/httpd", "sha256": self.B, "size_bytes": 1010},
            {"path": "/bin/busybox", "sha256": sha("busybox"), "size_bytes": 500}])
        self.lite.ingest_image(cid, family="cam", name="c-2.0", image_sha256=sha("c-2.0"), actor="hermes", members=[
            {"path": "/usr/bin/httpd", "sha256": self.C, "size_bytes": 990},
            {"path": "/usr/bin/webd", "sha256": self.U, "size_bytes": 700}])
        return cid

    def fingerprint_all(self, cid, actor="fp-tool"):
        self.lite.ingest_fingerprints(cid, actor=actor, content_sha256=self.A, observations=strong_obs("A"))
        self.lite.ingest_fingerprints(cid, actor=actor, content_sha256=self.B, observations=strong_obs("B", func_drop=1, extra_funcs=("fnB",)))
        self.lite.ingest_fingerprints(cid, actor=actor, content_sha256=self.C, observations=strong_obs("C", func_drop=1, extra_funcs=("fnC1",)))
        self.lite.ingest_fingerprints(cid, actor=actor, content_sha256=self.U, observations=[
            obs("language", "C"), obs("isa", "mips32"), obs("compiler", "gcc-9.3"), obs("package_name", "httpd")])

    def unit(self, cid, content):
        return self.lite.list_code_units(cid, content_sha256=content)[0]["id"]

    def to_deep_with_family(self, cid, drain_rep=True, rep_result=None):
        """inventory -> middle -> fingerprints -> lineage pass -> approve -> deep -> plan (-> rep receipt)."""
        self.to_middle(cid)
        self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        self.drain(cid, "middle")
        self.fingerprint_all(cid)
        res = self.lite.run_lineage_pass(cid, actor="hermes")
        fam = res["families_proposed"][0]
        self.assertTrue(self.lite.approve_cluster(cid, fam, actor="hermes")["accepted"])
        self.assertTrue(self.lite.advance_stage(cid, actor="hermes")["advanced"])
        plan = self.lite.plan_lineage_work(cid, actor="hermes")
        if drain_rep:
            claim = self.lite.claim_job(cid, worker="claude", stage="deep")
            job = claim["job"]
            sub = rep_result or good_result(summary="representative deep analysis")
            self.assertTrue(self.lite.submit_result(cid, job["id"], job["claim_token"], sub)["accepted"])
        return fam, plan
