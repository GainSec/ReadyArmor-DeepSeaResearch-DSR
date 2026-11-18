"""Telemetry test fixtures. Secret canaries are assembled at runtime so no secret-format literal
appears in the source tree (tools/verify.py scans it)."""
from __future__ import annotations

import json
import os
import random
import tempfile
import unittest
import uuid
from pathlib import Path

from fwspider_telemetry import Telemetry, TelemetryConfig
from fwspider_telemetry.query import events, scan_for, verify


def make_canaries() -> dict[str, str]:
    tag = uuid.uuid4().hex[:10].upper()
    rnd = random.Random(tag)
    otp = "".join(rnd.choice("0123456789") for _ in range(6)) + "7"
    c = {
        "password": f"pw{tag}CANARYzz",
        "api_key": "sk" + "-" + f"CANARYAPI{tag}abcdefghijklmnop",
        "github": "gh" + "p_" + f"CANARYGH{tag}" + "x" * 20,
        "aws": "AK" + "IA" + tag + "CANARY",
        "bearer": f"CANARYBEARER{tag}",
        "cookie": f"CANARYCOOKIE{tag}",
        "private_key_body": f"CANARYPK{tag}",
        "db_password": f"CANARYDB{tag}",
        "jwt_sig": f"CANARYJWT{tag}xx",
        "otp": f"CANARYOTP{otp}",
        "card": "4111" + " 1111" * 3,
        "card_compact": "4111" + "1111" * 3,
        "custom": f"INTERNAL-CANARY-{tag}",
        "claim_token_like": f"CANARYCLAIM{tag}",
    }
    c["private_key"] = ("-----BEGIN " + "RSA PRIVATE KEY-----\n" + c["private_key_body"] + "\n-----END " + "RSA PRIVATE KEY-----")
    c["conn"] = f"postgres://svc:{c['db_password']}@db.internal:5432/fw"
    c["jwt"] = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiJDQU5BUlkifQ" + "." + c["jwt_sig"]
    return c


def needles(c: dict[str, str]) -> list[str]:
    keys = ["password", "api_key", "github", "aws", "bearer", "cookie", "private_key_body", "db_password", "jwt_sig",
            "otp", "card", "card_compact", "custom", "claim_token_like"]
    return [c[k] for k in keys]


class TelCase(unittest.TestCase):
    """Fresh private log dir + dead-letter dir per test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="fwtel-")
        self.root = Path(self._tmp.name)
        self.log_dir = self.root / "log"
        self.dead_dir = self.root / "dead"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def cfg(self, **kw) -> TelemetryConfig:
        kw.setdefault("log_dir", self.log_dir)
        kw.setdefault("deadletter_dir", self.dead_dir)
        return TelemetryConfig(**kw)

    def tel(self, component: str = "test", run_id: str | None = None, **kw) -> Telemetry:
        return Telemetry(component, config=self.cfg(**kw), run_id=run_id, env={})

    def events(self) -> list[dict]:
        return events(self.log_dir)

    def types(self) -> list[str]:
        return [e["event_type"] for e in self.events()]

    def assertLogsValid(self) -> dict:
        res = verify(self.log_dir)
        self.assertTrue(res["ok"], json.dumps(res["problems"][:10], indent=1))
        return res

    def assertNoNeedles(self, c: dict[str, str], *extra_paths) -> None:
        hits = scan_for([self.log_dir, *[p for p in extra_paths if p and os.path.exists(p)]], needles(c))
        self.assertEqual(hits, [], "secret canary leaked to disk")
