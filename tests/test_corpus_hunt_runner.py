from refall_lite import RefallLite
from refall_lite.corpus_hunt import advance_to_middle, enqueue_hunt
from refall_lite.corpus_hunt_runner import brain_available, run_slice
from refall_lite.verify import host_rea_facts
from refall_lite.worker import CallableWorker
from tests.helpers import FakeClock, base_config, good_result, members, model_finding, sha

STUB_PACK = {"methods": [{"id": "t1", "label": "t", "ordered_steps": ["a"]}]}
CLAIM = {"bytes": [{"offset": 0x100, "hex": "41424344"}], "call_path": [["main", "parse"]],
         "xrefs": [{"target": "strcpy", "from": "parse"}]}
FACTS = {"bytes": {0x100: "4142434445"}, "call_graph": [["main", "parse"]],
         "xrefs": [{"target": "strcpy", "from": "parse"}]}


def _setup():
    lite = RefallLite(":memory:", clock=FakeClock())
    lite.register_actor("supervisor", kind="supervisor", provider="hermes")
    lite.register_actor("qwen", kind="model", provider="qwen-spark")
    lite.register_actor("verifier", kind="tool")
    cid = lite.create_campaign("s", config=base_config(methodology_bundle=STUB_PACK), actor="supervisor")["id"]
    ms = members("httpd")
    img = lite.ingest_image(cid, family="f", name="img", image_sha256=sha("img"), members=ms, actor="supervisor")
    advance_to_middle(lite, cid, img["image_id"], actor="supervisor")
    enqueue_hunt(lite, cid, ms[0]["sha256"], actor="supervisor")
    return lite, cid, ms[0]["sha256"]


class Spy:
    def __init__(self, calls, wid):
        self.calls, self.worker_id = calls, wid

    def run(self, packet):
        self.calls.append(self.worker_id)
        return good_result()


def test_brain_available_status():
    assert brain_available("http://x", probe=lambda url, t: 200)
    assert not brain_available("http://x", probe=lambda url, t: 503)

    def boom(url, t):
        raise OSError("down")
    assert not brain_available("http://x", probe=boom)


def test_brain_down_flags_and_idles_without_starting_spark():
    lite, cid, _ = _setup()
    calls = []
    out = run_slice(lite, cid, hunt_worker=Spy(calls, "qwen"), verify_worker=Spy(calls, "v"),
                    base_url="u", verifier_actor="verifier", probe=lambda url, t: 503)
    assert out["brain_unavailable"] is True and out["hunted"] == 0
    assert calls == []
    assert lite.list_findings(cid) == []


def fake_rea(drop_edge=False):
    """Fake REA: answers from FACTS; optionally omits the claimed call edge."""
    def q(op, args):
        if op == "read_bytes":
            return FACTS["bytes"].get(args["offset"])
        if op == "build_call_path":
            return None if drop_edge else [list(e) for e in FACTS["call_graph"] if list(e) == list(args["edge"])]
        if op == "xrefs":
            return [x for x in FACTS["xrefs"] if x["from"] == args["from"] and x["target"] == args["target"]]
        return None
    return q


def _run(rea_facts_fn, verify_extra=None):
    lite, cid, msha = _setup()
    finding = model_finding(msha, claim=CLAIM)
    hunt = CallableWorker("qwen", lambda p: good_result(summary="cand", findings=[finding]))
    verify = CallableWorker("v", lambda p: good_result(
        summary="rederived",
        findings=[{"claim": p["finding"]["claim"], "rederived": CLAIM, **(verify_extra or {})}]))
    out = run_slice(lite, cid, hunt_worker=hunt, verify_worker=verify, base_url="u",
                    verifier_actor="verifier", probe=lambda url, t: 200, rea_facts_fn=rea_facts_fn)
    return out, lite.list_findings(cid)[0]["tier"]


def test_full_cycle_candidate_then_verified_with_stubs():
    fn = lambda lite, cid, finding: host_rea_facts(finding, rea_query=fake_rea())
    out, tier = _run(fn)
    assert out["brain_unavailable"] is False and out["hunted"] == 1
    assert out["promoted"] == 1 and out["held"] == 0
    assert tier == "independently_checked"


def test_model_selfreport_facts_never_promote():
    out, tier = _run(None, verify_extra={"rea_facts": FACTS})
    assert out["promoted"] == 0 and out["held"] == 1
    assert tier == "hypothesis"


def test_host_extractor_promotes_on_matching_rea_facts():
    fn = lambda lite, cid, finding: host_rea_facts(finding, rea_query=fake_rea())
    out, tier = _run(fn)
    assert out["promoted"] == 1 and tier == "independently_checked"


def test_host_extractor_holds_on_rea_mismatch():
    fn = lambda lite, cid, finding: host_rea_facts(finding, rea_query=fake_rea(drop_edge=True))
    out, tier = _run(fn)
    assert out["promoted"] == 0 and out["held"] == 1 and tier == "hypothesis"


def test_host_rea_facts_shape_only_what_rea_returned():
    calls = []

    def q(op, args):
        calls.append((op, args))
        if op == "read_bytes":
            return "4142434445"
        return None  # no edge, no xref
    facts = host_rea_facts({"claim": CLAIM}, rea_query=q)
    assert facts == {"bytes": {0x100: "4142434445"}}
    assert [c[0] for c in calls] == ["read_bytes", "build_call_path", "xrefs"]
    assert host_rea_facts({"claim": {}}, rea_query=q) == {}
    assert host_rea_facts({"claim": CLAIM}, rea_query=lambda o, a: (_ for _ in ()).throw(OSError())) == {}
