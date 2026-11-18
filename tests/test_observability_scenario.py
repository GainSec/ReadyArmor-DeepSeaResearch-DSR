"""End-to-end observability scenario: one run across three processes reconstructed in exact order from JSONL alone."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ObservabilityScenarioTests(unittest.TestCase):
    def test_observability_scenario_reconstructable(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {**os.environ, "PYTHONPATH": str(ROOT)}
            p = subprocess.run([sys.executable, str(ROOT / "examples" / "run_observability_scenario.py"), "--workdir", tmp],
                               capture_output=True, text=True, env=env, timeout=300)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr[-3000:])
            s = json.loads((Path(tmp) / "observability-summary.json").read_text())
            self.assertTrue(s["passed"], s["checks"])
            self.assertGreaterEqual(len(s["checks"]), 22)
            self.assertGreaterEqual(s["segments"], 1)
            self.assertTrue(s["synthetic_only"])
