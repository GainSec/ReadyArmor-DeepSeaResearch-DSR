"""Lineage end-to-end: CLI processes over synthetic lineage fixtures (store reopened every step)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class LineageE2ETests(unittest.TestCase):
    def test_synthetic_lineage_campaign_example(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1")
            proc = subprocess.run([sys.executable, str(ROOT / "examples" / "run_lineage_campaign.py"), "--workdir", tmp],
                                  capture_output=True, text=True, env=env, timeout=600)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            summary = json.loads((Path(tmp) / "lineage-summary.json").read_text())
            self.assertTrue(summary["synthetic_only"])
            self.assertTrue(summary["closeout"]["passed"], summary)
            for name, ok in summary["checks"].items():
                self.assertTrue(ok, name)
            self.assertGreaterEqual(len(summary["checks"]), 20)
            self.assertEqual(sorted(summary["family"]["product_families"]), ["cam", "router"])
