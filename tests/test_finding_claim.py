from tests.helpers import LiteTestCase, members, model_finding, sha

CLAIM = {"bytes": [{"offset": 0, "hex": "7f45"}], "call_path": [["main", "parse"]],
         "xrefs": [{"target": "strcpy", "from": "parse"}]}


class FindingClaimTests(LiteTestCase):
    def _fid(self, **extra):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="f", name="img", image_sha256=sha("img"),
                               members=members("httpd"), actor="hermes")
        res = self.lite.record_finding(cid, actor="qwen", candidate=model_finding(sha("httpd"), **extra))
        assert res["accepted"], res
        return res["finding"]["id"]

    def test_claim_round_trips(self):
        fid = self._fid(claim=CLAIM)
        assert self.lite.get_finding(fid)["claim"] == CLAIM

    def test_missing_claim_defaults_empty(self):
        assert self.lite.get_finding(self._fid())["claim"] == {}

    def test_finding_persists_technique_id(self):
        fid = self._fid(technique_id="cmd_injection_sink_reachability")
        assert self.lite.get_finding(fid)["technique_id"] == "cmd_injection_sink_reachability"
        assert self.lite.get_finding(self._fid())["technique_id"] == ""
