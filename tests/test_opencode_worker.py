import unittest

from refall_lite.opencode_run import OpenCodeResult
from refall_lite.opencode_worker import OpenCodeWorker, build_objective
from refall_lite.worker import WorkerAdapter, parse_submission
from tests.helpers import good_result


def sample_hunt_packet(technique_id=None):
    payload = {"technique_id": technique_id} if technique_id else {}
    return {
        "protocol": "refall-lite.job.v1",
        "submit_schema": "refall-lite.submit.v1",
        "job": {"id": "j1", "stage": "hunt", "kind": "hunt", "attempts": 1, "max_attempts": 3,
                "claim_token": "t", "lease_expires": "x", "payload": payload},
        "target": {"type": "member", "ref": "abc", "family": "fw",
                   "member": {"path": "/usr/bin/httpd", "sha256": "abc", "size_bytes": 10}},
        "methodology_bundle": {"methods": [
            {"id": "ghidra_initial_auto_analysis", "label": "Initial", "ordered_steps": ["open", "list"],
             "evidence_requirements": ["addr"], "reproduction_gate": "rerun"},
            {"id": "fstm_elf_mitigation_inventory", "label": "Mitig", "ordered_steps": ["checksec"],
             "evidence_requirements": ["flags"], "reproduction_gate": "rerun"}]},
    }


def engine_shaped_member_packet():
    """Mirrors a real engine packet: the member row carries no path (path lives in
    the occurrences table, surfaced as target.occurrences_sample)."""
    return {
        "protocol": "refall-lite.job.v1",
        "submit_schema": "refall-lite.submit.v1",
        "job": {"id": "j1", "stage": "middle", "kind": "hunt", "attempts": 1, "max_attempts": 3,
                "claim_token": "t", "lease_expires": "x", "payload": {}},
        "target": {"type": "member", "ref": "deadbeef", "family": "corpus",
                   "member": {"sha256": "deadbeef", "size_bytes": 10, "kind": "elf"},
                   "occurrences_sample": [{"member_sha256": "deadbeef", "path": "usr/sbin/httpd",
                                           "image_name": "fw.squashfs"}]},
        "methodology_bundle": {"methods": []},
    }


def make(runner):
    return OpenCodeWorker("opencode-spark", model="spark/Q", base_url="u", api_key="k",
                          rea_command=["rea", "mcp"], rea_env={}, workdir_for=lambda p: "/w", runner=runner)


class OpenCodeWorkerTests(unittest.TestCase):
    def test_run_returns_submission_from_agent_block(self):
        worker = make(lambda prompt, **kw: OpenCodeResult(0, False, "ok", ["rea_open_binary"],
                                                          good_result(summary="hunted"), []))
        self.assertIsInstance(worker, WorkerAdapter)
        out = worker.run(sample_hunt_packet())
        self.assertEqual(parse_submission(out)[0]["summary"], "hunted")

    def test_run_coerces_numeric_string_cost_units(self):
        # Models (esp. slow local ones) sometimes emit cost_units as a numeric
        # STRING ("6"); the strict D1 gate then rejects the whole submission and real
        # findings are lost. The worker must normalize it to a number at the boundary.
        payload = good_result(summary="hunted")
        payload["cost_units"] = "6"
        worker = make(lambda prompt, **kw: OpenCodeResult(0, False, "ok", ["rea_open_binary"], payload, []))
        out = worker.run(sample_hunt_packet())
        self.assertEqual(out["cost_units"], 6)
        self.assertIsInstance(out["cost_units"], (int, float))
        self.assertNotIsInstance(out["cost_units"], str)

    def test_run_drops_unparseable_cost_units(self):
        # A non-numeric cost_units ("lots") can't be salvaged; drop it rather than
        # let it sink the submission (cost_units is optional in the gate).
        payload = good_result(summary="hunted")
        payload["cost_units"] = "lots"
        worker = make(lambda prompt, **kw: OpenCodeResult(0, False, "ok", ["rea_open_binary"], payload, []))
        out = worker.run(sample_hunt_packet())
        self.assertNotIn("cost_units", out)

    def test_run_missing_submit_block_returns_nonaccepted_status(self):
        worker = make(lambda prompt, **kw: OpenCodeResult(0, False, "no block", [], None, []))
        payload, errors = parse_submission(worker.run(sample_hunt_packet()))
        self.assertNotEqual(payload["status"], "done")
        self.assertEqual(payload["status"], "missing_terminal_submit")
        self.assertIn("agent produced no refall-submit block", payload["limitations"])

    def test_run_timeout_returns_provider_timeout_status(self):
        worker = make(lambda prompt, **kw: OpenCodeResult(124, True, "", [], None, []))
        self.assertEqual(parse_submission(worker.run(sample_hunt_packet()))[0]["status"], "provider_timeout")

    def test_objective_is_free_form_with_priorities_and_optional_pack(self):
        prompt, tech = build_objective(sample_hunt_packet("fstm_elf_mitigation_inventory"))
        self.assertEqual(tech["id"], "fstm_elf_mitigation_inventory")
        self.assertIn("/usr/bin/httpd", prompt)
        self.assertIn("NOVEL security vulnerabilities", prompt)
        self.assertIn("however you judge best", prompt)
        self.assertIn("Priority, highest first: (1) remote command/code/terminal injection; "
                      "(2) remotely-ingested injection (file received, file upload, parsing of received data); "
                      "(3) services exposed over the internet or LAN; (4) other memory-safety or logic bugs.", prompt)
        hdr = ("Optional reference ideas from the methodology pack (use if relevant to THIS target, "
               "otherwise ignore and use your own judgment):")
        self.assertIn(hdr, prompt)
        self.assertGreater(prompt.index("checksec"), prompt.index(hdr))
        self.assertNotIn("must follow", prompt)
        self.assertIn("refall-lite.submit.v1", prompt)
        self.assertIn("claim", prompt)
        for k in ("bytes", "call_path", "xrefs"):
            self.assertIn(k, prompt)
        self.assertEqual(build_objective(sample_hunt_packet())[1]["id"], "ghidra_initial_auto_analysis")

    def test_objective_requires_top_level_findings_array(self):
        # the engine only records entries in payload["findings"]; the prompt must demand that array.
        prompt, _ = build_objective(sample_hunt_packet(), "/wd")
        self.assertIn("`findings` array", prompt)
        self.assertIn("NOT recorded", prompt)
        for sev in ("info", "low", "medium", "high", "critical"):
            self.assertIn(sev, prompt)

    def test_priorities_override_replaces_default_framing(self):
        # non-Linux targets (e.g. bare-metal firmware) need a different threat model than
        # the default command-injection priorities.
        custom = "Priority: (1) protocol-parser memory corruption; (2) authentication bypass."
        prompt, _ = build_objective(sample_hunt_packet(), "/wd", priorities=custom)
        self.assertIn("protocol-parser memory corruption", prompt)
        self.assertNotIn("remote command/code/terminal injection", prompt)

    def test_objective_pins_canonical_claim_shapes(self):
        # the agent must emit claim facts in the exact shapes the D1 gate parses,
        # or they cannot be mechanically re-derived (prior run freelanced them).
        prompt, _ = build_objective(sample_hunt_packet(), "/wd")
        self.assertIn('"offset"', prompt)          # bytes entry shape
        self.assertIn('"hex"', prompt)
        self.assertIn("[from, to]", prompt)        # call_path edge shape
        self.assertIn('"target"', prompt)          # xref shape {from, target}
        self.assertIn("actual bytes", prompt.lower())   # hex must be real bytes, not prose
        self.assertIn("omit call_path", prompt.lower())  # source files: byte anchors only

    def test_target_path_resolves_from_occurrence_when_member_lacks_path(self):
        # engine packets have no member.path; the real relpath lives in occurrences_sample.
        prompt, _ = build_objective(engine_shaped_member_packet(), "/wd")
        self.assertIn("/wd/usr/sbin/httpd", prompt)
        self.assertNotIn("/wd/deadbeef", prompt)  # must not fall back to the sha ref

    def test_objective_without_methods_is_valid_free_form(self):
        pkt = sample_hunt_packet()
        pkt["methodology_bundle"] = {"methods": []}
        prompt, tech = build_objective(pkt)
        self.assertEqual(tech, {})
        self.assertNotIn("Optional reference ideas", prompt)
        self.assertIn("Priority, highest first", prompt)
        self.assertIn("refall-lite.submit.v1", prompt)

    def test_run_enables_general_hunt_tools_not_technique_pinned(self):
        from refall_lite.rea_toolmap import MAX_REA_TOOLS
        seen = {}

        def runner(prompt, **kw):
            seen.update(kw)
            return OpenCodeResult(0, False, "", [], good_result(), [])
        make(runner).run(sample_hunt_packet("fstm_elf_mitigation_inventory"))
        enabled = [k for k, v in seen["config"]["tools"].items() if v and k != "rea_*"]
        self.assertIn("rea_xrefs", enabled)
        self.assertIn("rea_procedure_pseudo_code", enabled)
        self.assertLessEqual(len(enabled), MAX_REA_TOOLS)
        self.assertFalse(seen["config"]["tools"]["rea_*"])

    def test_runner_receives_workdir_and_timeout(self):
        seen = {}

        def runner(prompt, **kw):
            seen.update(kw)
            return OpenCodeResult(0, False, "", [], good_result(), [])
        make(runner).run(sample_hunt_packet("fstm_elf_mitigation_inventory"))
        self.assertEqual(seen["workdir"], "/w")
        self.assertEqual(seen["timeout_s"], 1800)
