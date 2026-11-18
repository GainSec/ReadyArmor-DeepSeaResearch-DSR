from refall_lite.opencode_run import OpenCodeResult
from refall_lite.verify import (VerifyWorker, check_consistency, promote_or_hold,
                                rederive_prompt)
from refall_lite.worker import WorkerAdapter, parse_submission
from tests.helpers import LiteTestCase, members, model_finding, sha

CLAIM = {
    "bytes": [{"offset": 0x100, "hex": "41424344"}],
    "call_path": [["main", "parse"], ["parse", "strcpy"]],
    "xrefs": [{"target": "strcpy", "from": "parse"}],
}
REDERIVED_MATCHING = {
    "bytes": [{"offset": 0x100, "hex": "41424344"}],
    "call_path": [["main", "parse"], ["parse", "strcpy"]],
    "xrefs": [{"target": "strcpy", "from": "parse"}],
}
REA_FACTS_SUPPORTING = {
    "bytes": {0x100: "4142434445"},
    "call_graph": [["main", "parse"], ["parse", "strcpy"], ["x", "y"]],
    "xrefs": [{"target": "strcpy", "from": "parse"}],
}
REDERIVED_MISSING_EDGE = {**REDERIVED_MATCHING, "call_path": [["main", "parse"]]}
REA_FACTS_NO_EDGE = {**REA_FACTS_SUPPORTING, "call_graph": [["main", "parse"]]}


def test_consistency_passes_when_rederivation_matches():
    v = check_consistency(CLAIM, REDERIVED_MATCHING, REA_FACTS_SUPPORTING)
    assert v.ok, v.reasons


def test_consistency_fails_when_callpath_absent():
    v = check_consistency(CLAIM, REDERIVED_MISSING_EDGE, REA_FACTS_NO_EDGE)
    assert not v.ok and v.reasons


def test_consistency_fails_on_wrong_byte_and_missing_xref():
    facts = {**REA_FACTS_SUPPORTING, "bytes": {0x100: "ffffffff"}, "xrefs": []}
    v = check_consistency(CLAIM, REDERIVED_MATCHING, facts)
    assert not v.ok and len(v.reasons) >= 2


def test_rederive_prompt_has_claim_but_no_narrative():
    finding = {"id": "f1", "description": "SECRET NARRATIVE", "member_sha256": "abc",
               "claim": CLAIM, "evidence": [{"claim": "SECRET NARRATIVE"}]}
    prompt, claim = rederive_prompt(finding)
    assert claim == CLAIM and "SECRET NARRATIVE" not in prompt
    assert "strcpy" in prompt


def test_verify_worker_returns_payload_and_is_adapter():
    submit = {"summary": "rederived", "bytes": REDERIVED_MATCHING["bytes"]}
    w = VerifyWorker("verify-spark", model="m", base_url="u", api_key="k", rea_command=["rea"], rea_env={},
                     workdir_for=lambda p: "/w",
                     runner=lambda prompt, **kw: OpenCodeResult(0, False, "", [], submit, []))
    assert isinstance(w, WorkerAdapter)
    out = w.run({"finding": {"claim": CLAIM, "member_sha256": "abc"}, "target": {}})
    payload, _ = parse_submission(out)
    assert payload["status"] == "done"
    assert payload["findings"][0]["rederived"]["bytes"] == REDERIVED_MATCHING["bytes"]


class PromoteTests(LiteTestCase):
    def _fid(self):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="f", name="img", image_sha256=sha("img"),
                               members=members("httpd"), actor="hermes")
        res = self.lite.record_finding(cid, actor="qwen", candidate=model_finding(sha("httpd")))
        assert res["accepted"], res
        return cid, res["finding"]["id"]

    def _promote(self, cid, fid, actor="verifier", claim=CLAIM, rederived=REDERIVED_MATCHING,
                 facts=REA_FACTS_SUPPORTING):
        return promote_or_hold(self.lite, cid, fid, actor=actor, claim=claim, rederived=rederived,
                               rea_facts=facts)

    def _tier(self, fid):
        return self.lite.get_finding(fid)["tier"]

    def test_end_to_end_matching_promotes_with_receipt_from_facts(self):
        self.lite.register_actor("verifier", kind="tool", provider="deterministic")
        cid, fid = self._fid()
        out = self._promote(cid, fid)
        assert out["promoted"], out
        assert self._tier(fid) == "independently_checked"
        assert "bytes:0x100:41424344" in out["receipt"]["evidence_refs"]
        assert "call_edge:parse->strcpy" in out["receipt"]["evidence_refs"]

    def test_mismatch_holds(self):
        self.lite.register_actor("verifier", kind="tool", provider="deterministic")
        cid, fid = self._fid()
        out = self._promote(cid, fid, rederived=REDERIVED_MISSING_EDGE, facts=REA_FACTS_NO_EDGE)
        assert out["held"] and not out["promoted"] and out["reasons"]
        assert self._tier(fid) == "hypothesis"

    def test_empty_rederivation_or_empty_claim_cannot_promote(self):
        self.lite.register_actor("verifier", kind="tool", provider="deterministic")
        cid, fid = self._fid()
        assert self._promote(cid, fid, rederived={})["held"]
        assert self._promote(cid, fid, claim={}, rederived={}, facts={})["held"]
        assert self._promote(cid, fid, claim={"bytes": []}, rederived=REDERIVED_MATCHING)["held"]
        assert self._tier(fid) == "hypothesis"

    def test_malformed_entries_hold_not_raise(self):
        self.lite.register_actor("verifier", kind="tool", provider="deterministic")
        cid, fid = self._fid()
        bad = {"bytes": [{"offset": "zz", "hex": "41"}], "xrefs": [["a", "b"]]}
        assert not check_consistency(bad, bad, REA_FACTS_SUPPORTING).ok
        assert self._promote(cid, fid, claim=bad, rederived=bad)["held"]
        assert self._tier(fid) == "hypothesis"

    def test_creator_cannot_promote_own_finding(self):
        cid, fid = self._fid()
        out = self._promote(cid, fid, actor="qwen")
        assert not out["promoted"] and out["reasons"]
        assert self._tier(fid) == "hypothesis"

    def test_model_actor_cannot_promote(self):
        cid, fid = self._fid()
        out = self._promote(cid, fid, actor="claude")
        assert not out["promoted"]
        assert self._tier(fid) == "hypothesis"


def test_vacuous_claim_never_verifies():
    v = check_consistency({}, {}, {})
    assert not v.ok and v.reasons == ["no mechanical facts to verify"]


def _captured_cfg(finding):
    seen = {}

    def runner(prompt, *, workdir, config, timeout_s):
        seen["cfg"] = config
        return OpenCodeResult(0, False, "", [], {"summary": "x"}, [])

    w = VerifyWorker("v", model="m", base_url="u", api_key="k", rea_command=["rea"], rea_env={},
                     workdir_for=lambda p: "/w", runner=runner)
    w.run({"finding": finding, "target": {}})
    return repr(seen["cfg"])


def test_verifier_uses_general_hunt_tools_regardless_of_technique():
    from refall_lite.rea_toolmap import MAX_REA_TOOLS, hunt_tools
    for f in ({"claim": CLAIM, "technique_id": "fstm_elf_mitigation_inventory"}, {"claim": CLAIM}):
        cfg = _captured_cfg(f)
        for t in hunt_tools():
            assert f"rea_{t}" in cfg
        assert "read_bytes" in cfg and "build_call_path" in cfg and "xrefs" in cfg
    assert len(hunt_tools()) <= MAX_REA_TOOLS
