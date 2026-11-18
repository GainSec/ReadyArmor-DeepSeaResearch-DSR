"""Forward migration of real baseline (schema v1/v2) stores; explicit compatibility errors."""
from __future__ import annotations

import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from refall_lite import RefallLite
from refall_lite.arcticbase.store import STORAGE_TABLES, IncompatibleStoreError, SCHEMA_VERSION
from tests.helpers import sha
from tests.lineage_helpers import obs, strong_obs

FIXTURE = Path(__file__).parent / "fixtures" / "baseline_v1.sqlite"
FIXTURE_V2 = Path(__file__).parent / "fixtures" / "baseline_v2.sqlite"
FIXTURE_V3 = Path(__file__).parent / "fixtures" / "baseline_v3.sqlite"


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Path(self._tmp.name) / "old.sqlite"
        shutil.copy(FIXTURE, self.db)

    def tearDown(self):
        self._tmp.cleanup()

    def test_baseline_v1_store_migrates_forward_without_data_loss(self):
        before = sqlite3.connect(self.db)
        self.assertEqual(before.execute("SELECT value FROM store_meta WHERE key='schema_version'").fetchone()[0], "1")
        counts = {t: before.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in ("campaigns", "jobs", "findings", "ledger", "occurrences")}
        before.close()
        lite = RefallLite(self.db)
        try:
            self.assertEqual(lite.store_info()["schema_version"], str(SCHEMA_VERSION))
            self.assertEqual(lite.store_info()["migrated_from"], "1")
            cid = lite.list_campaigns()[0]["id"]
            for t, n in counts.items():
                self.assertEqual(lite.store.scalar(f"SELECT COUNT(*) FROM {t}"), n + (1 if t == "ledger" else 0), t)
            self.assertTrue(lite.verify_ledger(cid)["ok"])
            self.assertIn("migrate", [e["action"] for e in lite.ledger(cid, "runtime-event")])
            # baseline data intact and usable; lineage defaults applied to the old campaign
            self.assertEqual(lite.list_findings(cid)[0]["title"], "v1 hypothesis")
            occ = lite.member_occurrences(cid, sha("v1-httpd"))
            self.assertEqual(occ[0]["container"], None)
            lite.register_actor("fp-tool", kind="tool")
            res = lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=sha("v1-httpd"), observations=[obs("build_id", "deadbeef")])
            self.assertEqual(res["accepted"], 1)
            self.assertEqual(lite.lineage_config(cid)["algorithm_version"], "lite-fp-v1")
        finally:
            lite.close()
        again = RefallLite(self.db)  # idempotent second open
        try:
            self.assertEqual(again.store_info()["schema_version"], str(SCHEMA_VERSION))
            self.assertEqual(again.list_wishes(cid), [])  # v3 wishlist table added in the same single migration
        finally:
            again.close()

    def test_baseline_v2_store_migrates_to_v3_wishlist_without_data_loss(self):
        """Real v2 store (written by pre-wishlist commit 4e23e0c) gains the wishlist table additively."""
        shutil.copy(FIXTURE_V2, self.db)
        before = sqlite3.connect(self.db)
        self.assertEqual(before.execute("SELECT value FROM store_meta WHERE key='schema_version'").fetchone()[0], "2")
        tables = ("campaigns", "jobs", "findings", "ledger", "occurrences", "code_units", "budget_usage")
        counts = {t: before.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
        before.close()
        with RefallLite(self.db) as lite:
            self.assertEqual((lite.store_info()["schema_version"], lite.store_info()["migrated_from"]), (str(SCHEMA_VERSION), "2"))
            cid = lite.list_campaigns()[0]["id"]
            for t, n in counts.items():
                self.assertEqual(lite.store.scalar(f"SELECT COUNT(*) FROM {t}"), n + (1 if t == "ledger" else 0), t)
            mig = lite.ledger(cid, "runtime-event")[-1]
            self.assertEqual((mig["action"], mig["payload"]["from_schema"], mig["payload"]["added"]),
                             ("migrate", 2, ["table:wishlist_items", *(f"table:{n}" for n in STORAGE_TABLES)]))
            self.assertTrue(lite.verify_ledger(cid)["ok"])
            lite.register_actor("qwen", "model")
            res = lite.request_wish(cid, actor="qwen", kind="mcp", item="ghidra mcp", reason="decompile",
                                    required_for="v2 finding triage", scope="finding",
                                    finding_id=lite.list_findings(cid)[0]["id"])
            self.assertEqual(res["outcome"], "created")
        with RefallLite(self.db) as again:  # reopen: no second migration, wish persisted
            self.assertEqual(len(again.ledger(cid, "runtime-event")), 1)
            self.assertEqual(again.get_wish(res["wish"]["id"])["scope_type"], "finding")

    def test_baseline_v3_store_migrates_to_v4_storage_registry_without_data_loss(self):
        """Real v3 store (written by pre-storage commit 3b2ad1b) gains the storage tables additively and stays usable."""
        shutil.copy(FIXTURE_V3, self.db)
        before = sqlite3.connect(self.db)
        self.assertEqual(before.execute("SELECT value FROM store_meta WHERE key='schema_version'").fetchone()[0], "3")
        tables = ("campaigns", "jobs", "findings", "ledger", "wishlist_items", "run_manifests", "finding_transitions")
        counts = {t: before.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] for t in tables}
        before.close()
        with RefallLite(self.db) as lite:
            self.assertEqual((lite.store_info()["schema_version"], lite.store_info()["migrated_from"]), ("4", "3"))
            cid = lite.list_campaigns()[0]["id"]
            for t, n in counts.items():
                self.assertEqual(lite.store.scalar(f"SELECT COUNT(*) FROM {t}"), n + (1 if t == "ledger" else 0), t)
            mig = lite.ledger(cid, "runtime-event")[-1]
            self.assertEqual((mig["action"], mig["payload"]["from_schema"], mig["payload"]["added"]),
                             ("migrate", 3, [f"table:{n}" for n in STORAGE_TABLES]))
            self.assertTrue(lite.verify_ledger(cid)["ok"])
            finding = lite.list_findings(cid)[0]
            self.assertEqual(finding["tier"], "validated")
            # the migrated store is immediately usable for the registry, and v3 evidence protects its artifact
            root = Path(self._tmp.name) / "work"
            root.mkdir()
            (root / "replay.log").write_bytes(b"v3 replay transcript")
            self.assertTrue(lite.configure_storage_root("work", str(root), actor="dsr-supervisor")["accepted"])
            art = lite.register_artifact(cid, actor="dsr-supervisor", root="work", path="replay.log", kind="log",
                                         retention_class="diagnostic", finding_id=finding["id"])["artifact"]
            plan = lite.plan_cleanup(cid, actor="dsr-supervisor", rationale="post-migration sweep",
                                     policy={"min_age_s": {"diagnostic": 0}, "evidence_diagnostic_min_age_s": 0})["plan"]
            self.assertEqual(plan["candidates"], [])
            self.assertIn("required by validated finding", " ".join(plan["exclusions"]["examples"][0]["reasons"]))
        with RefallLite(self.db) as again:  # reopen: no second migration; registry rows persisted
            self.assertEqual(len([e for e in again.ledger(cid, "runtime-event") if e["action"] == "migrate"]), 1)
            self.assertEqual(again.get_artifact(art["id"])["state"], "present")
            self.assertEqual(again.list_wishes(cid)[0]["item_key"], "ghidra-mcp")

    def test_future_schema_version_fails_explicitly(self):
        c = sqlite3.connect(self.db)
        c.execute("UPDATE store_meta SET value='99' WHERE key='schema_version'")
        c.commit()
        c.close()
        with self.assertRaises(IncompatibleStoreError) as ctx:
            RefallLite(self.db)
        self.assertIn("newer", str(ctx.exception))

    def test_foreign_database_fails_explicitly(self):
        foreign = Path(self._tmp.name) / "foreign.sqlite"
        c = sqlite3.connect(foreign)
        c.execute("CREATE TABLE store_meta(key TEXT PRIMARY KEY, value TEXT)")
        c.execute("INSERT INTO store_meta VALUES('layer','something else')")
        c.commit()
        c.close()
        with self.assertRaises(IncompatibleStoreError):
            RefallLite(foreign)
        other = Path(self._tmp.name) / "other.sqlite"
        c = sqlite3.connect(other)
        c.execute("CREATE TABLE unrelated(x)")
        c.commit()
        c.close()
        with self.assertRaises(IncompatibleStoreError):
            RefallLite(other)
