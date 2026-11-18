"""Secret canaries planted in every channel never reach any log, artifact, manifest or dead-letter file."""
from __future__ import annotations

import json
import os
import sys

from fwspider_telemetry import REDACTED, MockModelClient, Redactor
from fwspider_telemetry.redaction import luhn_ok
from refall_lite import RefallLite
from refall_lite.model_worker import ModelWorker, subprocess_tool
from refall_lite.worker import render_submission, result_payload, run_one

from .helpers import base_config, members
from .tel_helpers import TelCase, make_canaries


def plant_everywhere(case: TelCase, debug: bool) -> tuple[dict, list[dict]]:
    c = make_canaries()
    tel = case.tel("refall-lite", debug=debug, extra_redact_patterns=(r"INTERNAL-CANARY-[0-9A-F]{10}",))
    # config (nested JSON, connection string, key names)
    tel.record_config("canary-config", "test", {"db": {"url": c["conn"], "password": c["password"]},
                                                "providers": [{"name": "x", "api_key": c["api_key"]}],
                                                "note": "rotate " + c["custom"]})
    # headers / network
    tel.emit("net.request", {"method": "GET", "url": f"https://h.example/api?token={c['bearer']}&x=1",
                             "headers": {"Authorization": f"Bearer {c['bearer']}", "Cookie": f"sid={c['cookie']}",
                                         "X-Api-Key": c["api_key"]}})
    # nested JSON + JSON-in-string + free text
    tel.emit("scenario.step", {"deep": {"a": [{"b": {"credentials": {"user": "u", "pw": c["password"]}}}]},
                               "embedded": json.dumps({"password": c["password"], "otp": c["otp"]}),
                               "text": f"aws {c['aws']} gh {c['github']} jwt {c['jwt']} card {c['card']} / {c['card_compact']}",
                               "raw_headers": f"GET / HTTP/1.1\r\nSet-Cookie: sid={c['cookie']}; Path=/\r\n",
                               "pem": c["private_key"], "verification_code": c["otp"]},
             message=f"session_id={c['cookie']}")
    # exception message + cause chain
    try:
        try:
            raise ValueError(f"db connect failed {c['conn']}")
        except ValueError as inner:
            raise RuntimeError(f"auth_token={c['github']} rejected") from inner
    except RuntimeError as exc:
        tel.exception(exc)
    # subprocess argv / env / stdout / stderr
    env = dict(os.environ, GITHUB_TOKEN=c["github"], DB_PASSWORD=c["password"])
    script = ("import sys; print('Authorization: Bearer ' + sys.argv[2]); "
              "print('api_key=' + sys.argv[4], file=sys.stderr); print(sys.argv[5])")
    tel.run_subprocess([sys.executable, "-c", script, "--password", c["bearer"], "--token=" + c["github"], c["aws"]],
                       env=env, tool="canary-echo")
    # REFALL: model prompt/response, tool args/results, worker submission, ledger payloads
    lite = RefallLite(case.root / f"s{int(debug)}.sqlite", telemetry=tel)
    lite.register_actor("hermes", "supervisor")
    lite.register_actor("qwen", "model")
    cfg = base_config()
    cfg["methodology_bundle"] = f"bundle?token={c['bearer']}"
    cid = lite.create_campaign("c", config=cfg, actor="hermes")["id"]
    lite.ingest_image(cid, family="f", name="img", image_sha256="c" * 64, members=members("httpd"), actor="hermes",
                      metadata={"vendor_api_key": c["api_key"], "notes": f"password={c['password']}"})
    lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
    tool = subprocess_tool(tel, lambda a: [sys.executable, "-c", "import sys; print(sys.argv[1])", a["secret_arg"]],
                           tool="echo")
    sub = "found " + c["private_key"] + "\n" + render_submission(result_payload(
        summary=f"saw api_key={c['api_key']}", evidence=[{"kind": "x", "ref": "synthetic:x", "claim": f"bearer {c['bearer']}"}],
        confidence="low", artifact_refs=["synthetic:x"], limitations=[f"token: {c['github']}"]))
    model = MockModelClient([
        {"content": f"calling tool with password={c['password']}",
         "tool_calls": [{"id": "t1", "name": "echo", "arguments": {"secret_arg": f"Bearer {c['bearer']}", "api_key": c["api_key"]}}]},
        {"content": sub},
    ])
    res = run_one(lite, cid, ModelWorker("qwen", model, tools={"echo": tool}, telemetry=tel,
                                         sampling={"temperature": 0, "api_key": c["api_key"]}))
    case.assertTrue(res["accepted"], res)
    lite.close()
    tel.end_process(0)
    return c, case.events()


class SecretCanaryTests(TelCase):
    def check(self, debug: bool) -> None:
        c, evs = plant_everywhere(self, debug)
        self.assertNoNeedles(c, self.dead_dir)
        redacted = [e for e in evs if e.get("redaction")]
        self.assertGreater(len(redacted), 8)
        rules = set().union(*(set(e["redaction"]["rules"]) for e in redacted))
        for r in ("sensitive_key", "authorization_header", "private_key_block", "aws_access_key_id", "vendor_token_format",
                  "jwt", "url_userinfo_password", "secret_key_value", "payment_card_number", "custom_0", "cookie_header"):
            self.assertIn(r, rules)
        blob = "".join(p.read_text(errors="ignore") for p in self.log_dir.rglob("*") if p.is_file())
        self.assertIn(REDACTED, blob)
        # artifacts carry their own redaction metadata
        arts = [json.loads(p.read_text()) for p in self.log_dir.rglob("art_*.json")]
        self.assertTrue(any(a["redaction"].get("count") for a in arts))
        # full env is never logged: only allowlist + digest
        start = next(e for e in evs if e["event_type"] == "tool.start" and e["data"]["tool"] == "canary-echo")
        self.assertNotIn("GITHUB_TOKEN", start["data"]["env"]["allowlisted"])
        self.assertTrue(start["data"]["env"]["digest"].startswith("sha256:"))
        self.assertLogsValid()

    def test_canaries_never_on_disk(self):
        self.check(debug=False)

    def test_debug_mode_does_not_weaken_redaction(self):
        self.check(debug=True)


class RedactorUnitTests(TelCase):
    def test_token_counts_not_mistaken_for_secrets(self):
        r = Redactor()
        out = r.redact({"prompt_tokens": 12, "total_tokens": 20, "max_tokens": 5, "token_count": 3, "claim_token": "abc",
                        "PWD": "/tmp", "pwd": "hunter"})
        self.assertEqual((out["prompt_tokens"], out["total_tokens"], out["max_tokens"], out["token_count"]), (12, 20, 5, 3))
        self.assertEqual((out["claim_token"], out["PWD"], out["pwd"]), (REDACTED, "/tmp", REDACTED))

    def test_argv_sanitizer(self):
        r = Redactor()
        self.assertEqual(r.sanitize_argv(["x", "--api-key", "v1", "--token=v2", "--max-tokens", "9", "--receipt", "f.json"]),
                         ["x", "--api-key", REDACTED, f"--token={REDACTED}", "--max-tokens", "9", "--receipt", "f.json"])

    def test_luhn_guard_avoids_redacting_ordinary_numbers(self):
        self.assertTrue(luhn_ok("4111" + "1111" * 3))
        self.assertEqual(Redactor().redact_text("size 4111111111111112 bytes"), "size 4111111111111112 bytes")

    def test_rules_file_is_shared_with_node(self):
        from pathlib import Path
        import fwspider_telemetry
        root = Path(fwspider_telemetry.__file__).parent
        self.assertTrue((root / "node" / "fwspider-telemetry.mjs").read_text().count("redaction-rules.json") >= 1)
