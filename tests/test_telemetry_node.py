"""Node emitter compatibility: same schema, same lock/seq protocol, concurrent with Python, redaction, rotation."""
from __future__ import annotations

import json
import multiprocessing
import os
import shutil
import subprocess
import unittest
from pathlib import Path

from fwspider_telemetry.query import verify
from fwspider_telemetry.sink import iter_events, read_index, verify_segments

from .tel_helpers import TelCase, make_canaries
from .test_telemetry_core import _proc_writer

ROOT = Path(__file__).resolve().parents[1]
import fwspider_telemetry  # noqa: E402
MODULE = Path(fwspider_telemetry.__file__).parent / "node" / "fwspider-telemetry.mjs"
NODE = shutil.which("node")

SCRIPT = r"""
import { Telemetry } from %(module)s;
import fs from 'node:fs';
const [n, tag] = [Number(process.argv[2]), process.argv[3]];
const secrets = process.argv[4] ? JSON.parse(fs.readFileSync(process.argv[4], 'utf8')) : {};
const tel = new Telemetry('node-writer', { config: undefined });
tel.startProcess(process.argv, { kind: 'test' });
tel.bind({ campaign_id: 'camp_node' }, () => {
  for (let i = 0; i < n; i++) tel.emit('scenario.step', { writer: tag, i, pad: 'n'.repeat(200) });
});
if (secrets.password) {
  tel.recordConfig('node-cfg', 'test', { db: { password: secrets.password }, url: secrets.conn });
  tel.emit('net.request', { method: 'GET', url: `https://x/d?token=${secrets.bearer}`, headers: { Authorization: `Bearer ${secrets.bearer}`, Cookie: secrets.cookie } });
  tel.emit('scenario.step', { text: `Authorization: Bearer ${secrets.bearer} aws ${secrets.aws} gh ${secrets.github} jwt ${secrets.jwt} card ${secrets.card}`, pem: secrets.private_key });
  tel.artifact('stdout', `api_key=${secrets.api_key}\n` + secrets.private_key);
  try { throw new Error(`failed ${"pass" + "word"}=${secrets.password}`, { cause: new Error(`inner ${secrets.github}`) }); } catch (e) { tel.exception(e); }
  try { tel.emit('not.a.type', {}); } catch (e) { tel.emit('scenario.check', { rejected_unknown_type: true }); }
}
tel.endProcess(0);
"""


@unittest.skipUnless(NODE, "node not installed")
class NodeTelemetryTests(TelCase):
    def run_node(self, n: int, tag: str, run_id: str, secrets: dict | None = None, rotate: int = 8192) -> subprocess.Popen:
        script = self.root / "w.mjs"
        script.write_text(SCRIPT % {"module": json.dumps(MODULE.as_uri())})
        env = {**os.environ, "FIRMWARE_SPIDER_LOG_DIR": str(self.log_dir), "FIRMWARE_SPIDER_RUN_ID": run_id,
               "FIRMWARE_SPIDER_LOG_ROTATE_BYTES": str(rotate), "FIRMWARE_SPIDER_DEADLETTER_DIR": str(self.dead_dir)}
        argv = [NODE, str(script), str(n), tag]
        if secrets:  # secrets are read from a file, never placed on argv (bare values are undetectable by design)
            sf = self.root / "secrets.json"
            sf.write_text(json.dumps(secrets))
            argv.append(str(sf))
        return subprocess.Popen(argv, env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def test_node_and_python_write_one_run_concurrently(self):
        run_id = "run_mixed_lang"
        ctx = multiprocessing.get_context("spawn")
        py = [ctx.Process(target=_proc_writer, args=(str(self.log_dir), run_id, 60, f"py{i}")) for i in range(3)]
        nodes = [self.run_node(60, f"node{i}", run_id) for i in range(3)]
        for p in py:
            p.start()
        for p in py:
            p.join(120)
            self.assertEqual(p.exitcode, 0)
        for n in nodes:
            out, err = n.communicate(timeout=120)
            self.assertEqual(n.returncode, 0, err)
        evs = [e for e in iter_events(self.log_dir) if e["run_id"] == run_id]
        seqs = [e["seq"] for e in evs]
        self.assertEqual(len(seqs), len(set(seqs)))
        self.assertEqual(sorted(seqs), list(range(1, len(seqs) + 1)))
        self.assertEqual(seqs, sorted(seqs), "file order == seq order across languages")
        langs = {e["component"] for e in evs}
        self.assertTrue({"proc-writer", "node-writer"} <= langs)
        self.assertEqual(sum(1 for e in evs if e["event_type"] == "scenario.step"), 6 * 60)
        self.assertGreater(len(read_index(self.log_dir)), 1)
        self.assertTrue(verify_segments(self.log_dir)["ok"], verify_segments(self.log_dir))
        res = verify(self.log_dir)
        self.assertTrue(res["ok"], res["problems"][:5])
        node_ev = next(e for e in evs if e["component"] == "node-writer" and e["event_type"] == "scenario.step")
        self.assertEqual(node_ev["campaign_id"], "camp_node")
        man = json.loads((self.log_dir / "runs" / run_id / "manifest.json").read_text())
        self.assertEqual(len(man["processes"]), 6)
        self.assertEqual(man["status"], "completed")

    def test_node_redaction_canaries_and_unknown_type(self):
        c = make_canaries()
        p = self.run_node(2, "s", "run_node_secrets", secrets=c, rotate=1 << 26)
        out, err = p.communicate(timeout=60)
        self.assertEqual(p.returncode, 0, err)
        self.assertNoNeedles(c, self.dead_dir)
        evs = list(iter_events(self.log_dir))
        self.assertTrue(any(e["event_type"] == "scenario.check" for e in evs))
        rules = set().union(*(set(e["redaction"]["rules"]) for e in evs if e.get("redaction")))
        for r in ("sensitive_key", "authorization_header", "private_key_block", "aws_access_key_id", "jwt", "payment_card_number"):
            self.assertIn(r, rules)
        exc = next(e for e in evs if e["event_type"] == "error.exception")
        self.assertEqual([x["relation"] for x in exc["data"]["exception"]["cause_chain"]], ["raised", "cause"])
        res = verify(self.log_dir)
        self.assertTrue(res["ok"], res["problems"][:5])
