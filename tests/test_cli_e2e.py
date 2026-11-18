"""End-to-end: drive the CLI as separate processes (each call reopens the store)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CliE2ETests(unittest.TestCase):
    def test_synthetic_campaign_example(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, PYTHONPATH=str(ROOT))
            proc = subprocess.run(
                [sys.executable, str(ROOT / "examples" / "run_synthetic_campaign.py"), "--workdir", tmp],
                capture_output=True, text=True, env=env, timeout=300,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            summary = json.loads((Path(tmp) / "summary.json").read_text())
            self.assertTrue(summary["closeout"]["passed"], summary)
            self.assertGreater(summary["cli_invocations"], 20)
            self.assertEqual(summary["unique_members"], summary["middle_jobs_succeeded"])
            self.assertGreater(summary["member_occurrences"], summary["unique_members"])
            self.assertTrue(summary["checks"]["model_only_promotion_refused"])
            self.assertTrue(summary["checks"]["closeout_blocked_before_validation"])
            self.assertTrue(summary["checks"]["budget_stop_observed"])
            self.assertTrue(summary["checks"]["ledger_ok"])
            self.assertTrue(summary["synthetic_only"])

    def test_cli_status_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "s.sqlite")
            env = dict(os.environ, PYTHONPATH=str(ROOT))
            run = lambda *a: subprocess.run([sys.executable, "-m", "refall_lite", "--db", db, *a], capture_output=True, text=True, env=env)
            self.assertEqual(run("actor", "add", "hermes", "--kind", "supervisor").returncode, 0)
            cfg = Path(tmp) / "cfg.json"
            cfg.write_text(json.dumps({"budgets": {"run": {"max_claims": 3, "max_cost": 3}}}))
            out = run("campaign", "create", "c1", "--config", str(cfg), "--actor", "hermes")
            self.assertEqual(out.returncode, 0, out.stderr)
            cid = json.loads(out.stdout)["id"]
            st = run("status", cid)
            self.assertEqual(json.loads(st.stdout)["campaign"]["status"], "active")
            bad = run("campaign", "create", "c2", "--config", str(cfg), "--actor", "ghost")
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("error", json.loads(bad.stdout))
