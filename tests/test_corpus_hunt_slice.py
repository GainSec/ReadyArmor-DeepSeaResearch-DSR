import os
import tempfile
import unittest
from pathlib import Path

from refall_lite import RefallLite
from refall_lite.corpus_hunt import advance_to_middle, enqueue_hunt, ingest_firmware, run_hunt_once
from refall_lite.worker import CallableWorker
from tests.helpers import FakeClock, base_config, good_result

STUB_PACK = {"methods": [{"id": "cmd_injection_sink_reachability", "label": "cmd injection sink reachability",
                          "ordered_steps": ["find sinks", "trace reachability"]}]}
ELF = Path(__file__).parent / "fixtures" / "stage0" / "tiny.elf"


class CorpusHuntSlice(unittest.TestCase):
    def test_hunt_lead_records_candidate_finding(self):
        lite = RefallLite(":memory:", clock=FakeClock())
        lite.register_actor("supervisor", kind="supervisor", provider="hermes")
        lite.register_actor("qwen", kind="model", provider="qwen-spark")
        cid = lite.create_campaign("slice", config=base_config(methodology_bundle=STUB_PACK), actor="supervisor")["id"]
        with tempfile.TemporaryDirectory() as out:
            ing = ingest_firmware(lite, cid, str(ELF), out, actor="supervisor")
            self.assertFalse(ing["escalation"])
            self.assertTrue(ing["members"])
            m = ing["members"][0]
            self.assertTrue(os.path.exists(os.path.join(out, m["path"])))
            advance_to_middle(lite, cid, ing["image_id"], actor="supervisor")
            jid = enqueue_hunt(lite, cid, m["sha256"], technique_id="cmd_injection_sink_reachability", actor="supervisor")
            self.assertTrue(jid)
            finding = {"title": "t", "vuln_class": "cmd-injection", "severity": "high", "member_sha256": m["sha256"],
                       "description": "cand", "evidence": [{"kind": "x", "ref": "r", "claim": "c"}],
                       "artifact_refs": [f"member:{m['sha256']}"], "source_anchors": ["tiny.elf:1"],
                       "confidence": "low", "limitations": ["stub"]}
            stub = CallableWorker("qwen", lambda packet: good_result(summary="cand", findings=[finding]))
            res = run_hunt_once(lite, cid, stub)
            self.assertTrue(res["accepted"], res)
            self.assertTrue(res["finding_ids"])
            f = lite.get_finding(res["finding_ids"][0])
            print("INITIAL TIER:", f["tier"])
            self.assertEqual(lite.list_findings(cid)[0]["tier"], f["tier"])
            self.assertEqual(f["tier"], "hypothesis")


if __name__ == "__main__":
    unittest.main()
