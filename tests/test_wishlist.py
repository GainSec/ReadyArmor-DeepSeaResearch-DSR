"""Single-supervisor wishlist contracts: identity/dedup, authority + legal transitions, capability secrecy,
scoped packet injection + isolation, dependent-only blockers, investment triage + revisit triggers, CLI."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from refall_lite import RefallLite

from .helpers import LiteTestCase, base_config, members, sha
from .tel_helpers import TelCase, make_canaries

ROOT = Path(__file__).resolve().parents[1]
CAP = {"provider": "NationalSecurityAgency/ghidra", "project": "ghidra", "version": "11.1.2", "transport": "mcp_stdio",
       "invocation_ref": "dsr-catalog:ghidra-mcp", "config_ref": "supervisor-config:ghidra-mcp",
       "provenance_url": "https://github.com/NationalSecurityAgency/ghidra", "health_status": "healthy",
       "health_checked_at": 1_000_000.0, "supported_inputs": ["elf"], "supported_outputs": ["decompilation"]}
SEARCH_CAP = {"provider": "dsr-supervisor", "version": "adapter-0.1", "transport": "http_api",
              "invocation_ref": "supervisor-tool:web_search", "config_ref": "supervisor-secret-store:web-search",
              "provenance_url": "internal:dsr-supervisor/web-search-adapter"}
PROVIDED = {"evidence_refs": ["catalog:ghidra-mcp@11.1.2", "healthcheck:ok"], "summary": "provisioned by supervisor"}
ASSESS = {"expected_value": "high", "time_cost": "low", "storage_cost": "low", "risk": "low", "maintenance": "medium"}


def decision(**extra) -> dict:
    return {"rationale": "weighed campaign value against cost/storage/risk/maintenance", "assessment": ASSESS, **extra}


class WishCase(LiteTestCase):
    def fleet(self, cid: str, *labels: str) -> None:
        self.lite.ingest_image(cid, family="acme", name=f"img-{labels[0]}", image_sha256=sha(f"img-{labels}"),
                               members=members(*labels), actor="hermes")

    def ask(self, cid: str, item: str = "Ghidra MCP", *, actor: str = "qwen", kind: str = "mcp", **kw) -> dict:
        return self.lite.request_wish(cid, actor=actor, kind=kind, item=item, reason="need decompilation",
                                      required_for="middle triage of httpd", **kw)

    def provide(self, cid: str, wish_id: str, capability: dict | None = CAP) -> dict:
        return self.lite.resolve_wish(cid, wish_id, actor="hermes", status="provided", receipt=PROVIDED,
                                      capability=capability, decision=decision())

    def actions(self, cid: str) -> list[str]:
        return [e["action"] for e in self.lite.ledger(cid, "wishlist")]

    def middle_jobs(self, cid: str) -> dict[str, dict]:
        self.to_middle(cid)
        self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        return {j["target_ref"]: j for j in self.lite.list_jobs(cid, stage="middle")}


class WishlistTests(WishCase):
    def test_request_identity_dedups_per_scope_and_isolates_campaigns(self):
        a, b = self.campaign(), self.campaign()
        self.fleet(a, "httpd")
        self.fleet(b, "busybox")
        first = self.ask(a)
        again = self.ask(a, "  ghidra_mcp ", actor="claude", blocking=False)
        self.assertEqual((first["outcome"], again["outcome"]), ("created", "deduplicated"))
        self.assertEqual(again["wish"]["id"], first["wish"]["id"])
        self.assertEqual(again["wish"]["request_count"], 2)
        scoped = self.ask(a, member_sha256=sha("httpd"), scope="member")
        other = self.ask(b)
        self.assertEqual((scoped["outcome"], other["outcome"]), ("created", "created"))
        self.assertEqual(len(self.lite.list_wishes(a)), 2)
        self.assertEqual([w["id"] for w in self.lite.list_wishes(b)], [other["wish"]["id"]])
        self.assertEqual(self.actions(a), ["request", "dedup", "request"])
        before = len(self.lite.ledger(a))
        with self.assertRaises(ValueError):  # a link into another campaign is rejected, nothing written
            self.ask(a, member_sha256=sha("busybox"), scope="member")
        with self.assertRaises(ValueError):  # blockers must name the dependent scope
            self.ask(a, "operator approval", kind="operator_input", blocking=True)
        self.assertEqual(len(self.lite.ledger(a)), before)

    def test_supervisor_authority_legal_transitions_and_recurrence(self):
        cid = self.campaign()
        self.fleet(cid, "httpd")
        wid = self.ask(cid)["wish"]["id"]
        by_model = self.lite.resolve_wish(cid, wid, actor="qwen", status="provided", receipt=PROVIDED, capability=CAP,
                                          decision=decision())
        self.assertFalse(by_model["accepted"])
        self.assertTrue(any("cannot resolve" in r for r in by_model["reasons"]))
        illegal = self.lite.resolve_wish(cid, wid, actor="hermes", status="consumed", receipt={"summary": "x"})
        self.assertIn("illegal wishlist transition open -> consumed", illegal["reasons"])
        no_cap = self.provide(cid, wid, capability=None)
        self.assertTrue(any("requires capability metadata" in r for r in no_cap["reasons"]))
        thin_denial = self.lite.resolve_wish(cid, wid, actor="analyst", status="denied", receipt={"summary": "no"},
                                             decision=decision())
        self.assertFalse(thin_denial["accepted"])  # denial needs evidence, not just a summary
        self.assertEqual(self.lite.get_wish(wid)["status"], "open")
        ok = self.provide(cid, wid)
        self.assertTrue(ok["accepted"], ok)
        self.assertEqual((ok["wish"]["status"], ok["wish"]["disposition"]), ("provided", "provide_now"))
        # a provided capability is reused, not re-requested -- at its own or any narrower scope
        self.assertEqual(self.ask(cid)["outcome"], "refused")
        self.assertEqual(self.ask(cid, scope="member", member_sha256=sha("httpd"))["outcome"], "refused")
        used = self.lite.resolve_wish(cid, wid, actor="hermes", status="consumed", receipt={"summary": "job done"})
        self.assertTrue(used["accepted"], used)
        back = self.ask(cid)
        self.assertEqual((back["outcome"], back["wish"]["status"], back["wish"]["request_count"]), ("reopened", "open", 2))
        self.assertIsNone(back["wish"]["disposition"])
        self.assertEqual([h["event"] for h in back["wish"]["history"]], ["resolve", "resolve", "reopen"])
        self.assertEqual(self.actions(cid), ["request", "resolve_refused", "resolve_refused", "resolve_refused",
                                             "resolve_refused", "resolve", "request_refused", "request_refused",
                                             "resolve", "reopen"])
        self.assertTrue(self.lite.verify_ledger(cid)["ok"])

    def test_packet_injects_scoped_capabilities_web_search_and_isolates_campaigns(self):
        cid, other = self.campaign(), self.campaign()
        self.fleet(cid, "httpd", "busybox")
        self.fleet(other, "dropbear")
        jobs = self.middle_jobs(cid)
        ja, jb = jobs[sha("httpd")], jobs[sha("busybox")]
        tool = self.ask(cid)["wish"]["id"]
        self.provide(cid, tool)
        art = self.ask(cid, "unpacked httpd config", kind="artifact", scope="member", member_sha256=sha("httpd"))["wish"]["id"]
        self.assertTrue(self.lite.resolve_wish(cid, art, actor="hermes", status="provided", decision=decision(),
                                               receipt={"artifact_refs": ["corpus:httpd.conf"]})["accepted"])
        search = self.ask(cid, "web search", kind="web_search")["wish"]["id"]
        pa, pb = self.lite.job_packet(cid, ja["id"])["capabilities"], self.lite.job_packet(cid, jb["id"])["capabilities"]
        self.assertEqual(sorted(e["id"] for e in pa["provided"]), sorted([tool, art]))
        self.assertEqual([e["id"] for e in pb["provided"]], [tool])
        self.assertEqual(pa["provided"][0 if pa["provided"][0]["id"] == tool else 1]["capability"]["version"], "11.1.2")
        self.assertEqual(pa["web_search"], {"available": False, "requested": True})
        self.assertTrue(any("Do not install packages" in r for r in pa["rules"]))
        self.assertTrue(self.provide(cid, search, SEARCH_CAP)["accepted"])
        ws = self.lite.job_packet(cid, jb["id"])["capabilities"]["web_search"]
        self.assertEqual((ws["available"], ws["wish_id"], ws["capability"]["invocation_ref"]),
                         (True, search, "supervisor-tool:web_search"))
        # campaign isolation: another campaign's packet carries none of these, and packets cannot mix campaigns
        self.lite.enqueue_image_jobs(other, stage="inventory", kind="inventory", actor="hermes")
        oj = self.lite.list_jobs(other)[0]
        oc = self.lite.job_packet(other, oj["id"])["capabilities"]
        self.assertEqual((oc["provided"], oc["requested"], oc["web_search"]["available"]), ([], [], False))
        with self.assertRaises(ValueError):
            self.lite.job_packet(other, ja["id"])

    def test_blocking_wish_pauses_only_dependent_jobs(self):
        cid = self.campaign()
        self.fleet(cid, "httpd", "busybox")
        jobs = self.middle_jobs(cid)
        ja, jb = jobs[sha("httpd")], jobs[sha("busybox")]
        wid = self.ask(cid, "board UART access", kind="access", scope="member", member_sha256=sha("httpd"),
                       blocking=True)["wish"]["id"]
        first = self.lite.claim_job(cid, worker="qwen", stage="middle")
        self.assertEqual(first["job"]["id"], jb["id"])  # unrelated work continues
        idle = self.lite.claim_job(cid, worker="claude", stage="middle")
        self.assertEqual((idle["claimed"], idle["wishlist_blocked"]), (False, [ja["id"]]))
        self.assertEqual(self.lite.job_packet(cid, ja["id"])["capabilities"]["blockers"], [wid])
        self.assertEqual(self.lite.status(cid)["wishlist"]["open_blocking"], 1)
        declined = self.lite.resolve_wish(cid, wid, actor="hermes", status="denied", decision=decision(disposition="decline"),
                                          receipt={"evidence_refs": ["hardware-inventory:no-board"], "summary": "no board"})
        self.assertTrue(declined["accepted"], declined)
        claim = self.lite.claim_job(cid, worker="claude", stage="middle")
        self.assertEqual(claim["job"]["id"], ja["id"])  # declined => dependent work resumes with a limitation
        entry = self.lite.job_packet(cid, ja["id"])["capabilities"]["declined"][0]
        self.assertEqual((entry["id"], entry["disposition"]), (wid, "decline"))

    def test_investment_dispositions_and_revisit_triggers_survive_restart(self):
        cid = self.campaign()
        self.fleet(cid, "httpd")
        wid = self.ask(cid, "BinDiff", kind="analyzer")["wish"]["id"]
        note = {"summary": "triage"}
        refusals = [
            dict(),                                                       # no decision record
            dict(decision=decision()),                                    # deferral without trigger
            dict(decision=decision(revisit_trigger={"stage_reached": "inventory"})),  # already satisfied
            dict(decision=decision(revisit_trigger={"when_convenient": True})),       # not objective
            dict(decision={**decision(revisit_trigger={"stage_reached": "middle"}), "assessment": {"risk": "low"}}),
            dict(decision=decision(disposition="provide_now", revisit_trigger={"stage_reached": "middle"})),
        ]
        for kw in refusals:
            self.assertFalse(self.lite.resolve_wish(cid, wid, actor="hermes", status="deferred", receipt=note, **kw)["accepted"], kw)
        defer = self.lite.resolve_wish(cid, wid, actor="hermes", status="deferred", receipt=note,
                                       decision=decision(revisit_trigger={"stage_reached": "middle", "request_count_at_least": 5}))
        self.assertTrue(defer["accepted"], defer)
        self.assertEqual(self.ask(cid, "bindiff", kind="analyzer")["outcome"], "deduplicated")  # stays deferred
        self.reopen()
        kept = self.lite.get_wish(wid)
        self.assertEqual((kept["status"], kept["disposition"], kept["request_count"]), ("deferred", "defer_with_trigger", 2))
        self.assertEqual(kept["decision"]["revisit_trigger"], {"stage_reached": "middle", "request_count_at_least": 5})
        self.to_middle(cid)  # stage transition re-evaluates triggers
        revisited = self.lite.get_wish(wid)
        self.assertEqual((revisited["status"], revisited["disposition"]), ("open", None))
        rev = self.lite.ledger(cid, "wishlist")[-1]
        self.assertEqual((rev["action"], rev["payload"]["fired"]), ("revisit", ["stage_reached=middle"]))
        self.assertEqual(rev["payload"]["receipt"]["evidence_refs"], ["trigger:stage_reached=middle"])
        # use_existing_alternative with a recurrence trigger: the 3rd request reopens it
        alt = self.lite.resolve_wish(cid, wid, actor="hermes", status="superseded", receipt=note,
                                     decision=decision(alternative_ref="dsr-catalog:radiff2",
                                                       revisit_trigger={"request_count_at_least": 3}))
        self.assertTrue(alt["accepted"], alt)
        self.assertEqual(self.lite.job_packet(cid, self.middle_job(cid))["capabilities"]["declined"][0]["alternative_ref"],
                         "dsr-catalog:radiff2")
        self.assertEqual(self.ask(cid, "BinDiff", kind="analyzer")["outcome"], "reopened")
        # decline without trigger: recurrence is counted but refused; mismatched disposition is refused
        mismatch = self.lite.resolve_wish(cid, wid, actor="hermes", status="denied", receipt=PROVIDED,
                                          decision=decision(disposition="provide_now"))
        self.assertFalse(mismatch["accepted"])
        self.assertTrue(self.lite.resolve_wish(cid, wid, actor="hermes", status="denied", receipt=PROVIDED,
                                               decision=decision())["accepted"])
        self.assertEqual(self.ask(cid, "BinDiff", kind="analyzer")["outcome"], "refused")
        self.assertEqual(self.lite.get_wish(wid)["request_count"], 4)
        # time trigger fires only on an explicit supervisor revisit pass
        self.lite.resolve_wish(cid, wid, actor="hermes", status="open", receipt={"summary": "operator priority change"})
        self.lite.resolve_wish(cid, wid, actor="hermes", status="deferred", receipt=note,
                               decision=decision(revisit_trigger={"after": self.clock.now + 100}))
        with self.assertRaises(PermissionError):
            self.lite.revisit_wishes(cid, actor="qwen")
        self.assertEqual(self.lite.revisit_wishes(cid, actor="hermes")["reopened"], [])
        self.clock.advance(200)
        self.assertEqual(self.lite.revisit_wishes(cid, actor="hermes")["reopened"], [wid])
        self.assertTrue(self.lite.verify_ledger(cid)["ok"])

    def middle_job(self, cid: str) -> str:
        self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        return self.lite.list_jobs(cid, stage="middle")[0]["id"]

    def test_cli_request_resolve_show_revisit_json_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1", FIRMWARE_SPIDER_LOG_DIR=str(t / "logs"),
                       FIRMWARE_SPIDER_DEADLETTER_DIR=str(t / "dead"))

            def run(*a: str) -> tuple[int, Any]:
                p = subprocess.run([sys.executable, "-m", "refall_lite", "--db", str(t / "s.sqlite"), *a],
                                   capture_output=True, text=True, env=env)
                return p.returncode, json.loads(p.stdout)  # stdout is always one JSON document

            def put(name: str, obj: dict) -> str:
                (t / name).write_text(json.dumps(obj))
                return str(t / name)

            run("actor", "add", "hermes", "--kind", "supervisor")
            run("actor", "add", "qwen", "--kind", "model")
            cid = run("campaign", "create", "c", "--config", put("cfg.json", base_config()), "--actor", "hermes")[1]["id"]
            code, req = run("wishlist", "request", cid, "--actor", "qwen", "--kind", "web_search", "--item", "web search",
                            "--reason", "vendor advisory lookup", "--required-for", "CVE correlation")
            self.assertEqual((code, req["outcome"]), (0, "created"))
            wid = req["wish"]["id"]
            args = ["wishlist", "resolve", cid, wid, "--status", "provided", "--receipt", put("r.json", PROVIDED),
                    "--capability", put("cap.json", SEARCH_CAP), "--decision", put("d.json", decision())]
            code, refused = run(*args, "--actor", "qwen")
            self.assertEqual((code, refused["accepted"]), (0, False))  # policy refusal: recorded, exit 0
            code, ok = run(*args, "--actor", "hermes")
            self.assertEqual((code, ok["wish"]["status"], ok["wish"]["capability"]["transport"]), (0, "provided", "http_api"))
            self.assertEqual(run("wishlist", "show", wid)[1]["disposition"], "provide_now")
            self.assertEqual([w["id"] for w in run("wishlist", "list", cid, "--status", "provided")[1]], [wid])
            self.assertEqual(run("wishlist", "revisit", cid, "--actor", "hermes")[1], {"evaluated": 0, "reopened": []})
            code, err = run("wishlist", "request", cid, "--actor", "qwen", "--kind", "telepathy", "--item", "x",
                            "--reason", "r", "--required-for", "y")
            self.assertEqual(code, 2)
            self.assertIn("ValueError", err["error"])
            self.assertEqual([e["action"] for e in RefallLite(t / "s.sqlite", telemetry=False).ledger(cid, "wishlist")],
                             ["request", "resolve_refused", "resolve"])


class WishlistSecrecyTelemetryTests(TelCase):
    def test_capability_is_closed_bounded_secret_free_and_ledgered_after_commit(self):
        c = make_canaries()
        db = self.root / "s.sqlite"
        lite = RefallLite(db, telemetry=self.tel("refall-lite"))
        try:
            lite.register_actor("hermes", "supervisor")
            lite.register_actor("qwen", "model")
            cid = lite.create_campaign("c", config=base_config(), actor="hermes")["id"]
            wid = lite.request_wish(cid, actor="qwen", kind="tool", item="binwalk", reason="unpack firmware",
                                    required_for=f"inventory; api_key={c['api_key']}")["wish"]["id"]
            self.assertNotIn(c["api_key"], lite.get_wish(wid)["required_for"])  # request text is redacted
            bad = [{**CAP, "config_ref": f"password={c['password']}"},
                   {**CAP, "provenance_url": c["conn"]},
                   {**CAP, "api_key": c["api_key"]},
                   {**CAP, "supported_inputs": [c["github"]]},
                   {**CAP, "notes": "x" * 501},
                   {**CAP, "transport": "carrier-pigeon"}]
            for cap in bad:
                res = lite.resolve_wish(cid, wid, actor="hermes", status="provided", receipt=PROVIDED, capability=cap,
                                        decision=decision())
                self.assertFalse(res["accepted"], cap)
            ok = lite.resolve_wish(cid, wid, actor="hermes", status="provided", receipt=PROVIDED, capability=CAP,
                                   decision=decision())
            self.assertTrue(ok["accepted"], ok)
            self.assertEqual(ok["wish"]["capability"], CAP)
        finally:
            lite.close()
        self.assertNoNeedles(c, db, Path(f"{db}-wal"))  # neither canonical state, ledger, nor telemetry hold secrets
        evs = self.events()
        types = [e["event_type"] for e in evs if e["event_type"].startswith("wishlist.")]
        self.assertEqual(types, ["wishlist.request"] + ["wishlist.resolve_refused"] * 6 + ["wishlist.resolve"])
        calls = {e["event_id"] for e in evs if e["event_type"] == "api.call"}
        self.assertTrue(all(e["parent_event_id"] in calls for e in evs if e["event_type"].startswith("wishlist.")))
        self.assertEqual({e["level"] for e in evs if e["event_type"] == "wishlist.resolve_refused"}, {"warning"})
        self.assertLogsValid()
