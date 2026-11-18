"""Shared test fixtures. Synthetic metadata only — no real firmware."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from refall_lite import RefallLite


def sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


class FakeClock:
    def __init__(self, start: float = 1_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def base_config(**overrides) -> dict:
    cfg = {
        "budgets": {"run": {"max_claims": 100, "max_cost": 10_000}},
        "max_attempts": 2,
        "lease_s": 60,
        "backoff_s": 0,
        "max_consecutive_failures": 50,
        "max_jobs": 500,
    }
    for key, value in overrides.items():
        if key == "budgets":
            cfg["budgets"].update(value)
        else:
            cfg[key] = value
    return cfg


def members(*labels: str) -> list[dict]:
    return [{"path": f"/usr/bin/{label}", "sha256": sha(label), "size_bytes": 100 + i} for i, label in enumerate(labels)]


def good_result(summary: str = "triaged", **extra) -> dict:
    payload = {
        "schema": "refall-lite.submit.v1",
        "type": "job_result",
        "status": "done",
        "summary": summary,
        "evidence": [{"kind": "metadata", "ref": "synthetic:member-metadata", "claim": summary}],
        "artifact_refs": ["synthetic:member-metadata"],
        "confidence": "medium",
        "limitations": ["synthetic metadata only"],
        "cost_units": 1,
    }
    payload.update(extra)
    return payload


def model_finding(member_sha: str, title: str = "Hardcoded credential pattern", severity: str = "high", **extra) -> dict:
    item = {
        "title": title,
        "vuln_class": "hardcoded-credential",
        "severity": severity,
        "member_sha256": member_sha,
        "description": "model hypothesis over synthetic metadata",
        "evidence": [{"kind": "string-hit", "ref": "strings:0x100", "claim": "credential-like string"}],
        "artifact_refs": [f"member:{member_sha}"],
        "source_anchors": ["etc/passwd:3"],
        "confidence": "low",
        "limitations": ["static strings only"],
    }
    item.update(extra)
    return item


def check_receipt(**extra) -> dict:
    receipt = {
        "checker_kind": "deterministic_tool",
        "commands": ["python3 tools/synthetic_check.py --member X"],
        "artifact_refs": ["check-output:abc"],
        "summary": "independent non-model check reproduced string hit",
    }
    receipt.update(extra)
    return receipt


def replay_receipt(out_a: str | None = None, out_b: str | None = None, **extra) -> dict:
    out_a = out_a or sha("replay-output")
    out_b = out_b or out_a
    receipt = {
        "checker_kind": "deterministic_replay",
        "commands": ["python3 tools/synthetic_replay.py --member X"],
        "artifact_refs": ["replay-log:1", "replay-log:2"],
        "replays": [{"run_id": "r1", "output_sha256": out_a}, {"run_id": "r2", "output_sha256": out_b}],
        "summary": "deterministic replay twice, identical output",
    }
    receipt.update(extra)
    return receipt


class LiteTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "arcticbase.sqlite"
        self.clock = FakeClock()
        self.lite = self.open()
        self.lite.register_actor("hermes", kind="supervisor", provider="hermes")
        self.lite.register_actor("qwen", kind="model", provider="qwen-spark")
        self.lite.register_actor("claude", kind="model", provider="anthropic")
        self.lite.register_actor("replayer", kind="tool", provider="deterministic")
        self.lite.register_actor("checker", kind="tool", provider="deterministic")
        self.lite.register_actor("analyst", kind="human")

    def tearDown(self) -> None:
        self.lite.close()
        self._tmp.cleanup()

    def open(self) -> RefallLite:
        return RefallLite(self.db, clock=self.clock)

    def reopen(self) -> RefallLite:
        self.lite.close()
        self.lite = self.open()
        return self.lite

    def campaign(self, **cfg) -> str:
        return self.lite.create_campaign("synthetic-fleet", config=base_config(**cfg), actor="hermes")["id"]

    def to_middle(self, cid: str) -> None:
        """Run inventory jobs for every image to completion and advance to middle."""
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        self.drain(cid, "inventory")
        res = self.lite.advance_stage(cid, actor="hermes")
        self.assertTrue(res["advanced"], res)

    def drain(self, cid: str, stage: str, worker: str = "qwen", findings_for: dict | None = None) -> list[dict]:
        done = []
        while True:
            claim = self.lite.claim_job(cid, worker=worker, stage=stage)
            if not claim["claimed"]:
                return done
            job = claim["job"]
            extra = {}
            if findings_for and job["target_ref"] in findings_for:
                extra["findings"] = [findings_for[job["target_ref"]]]
            res = self.lite.submit_result(cid, job["id"], job["claim_token"], good_result(**extra))
            self.assertTrue(res["accepted"], res)
            done.append(res)
