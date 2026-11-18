"""Artifact registry, retention/cleanup and disk-pressure control (schema v4).

Every test uses temporary managed/quarantine roots only; nothing touches a live corpus path.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from refall_lite import RefallLite

from .helpers import LiteTestCase, base_config, members, sha
from .tel_helpers import TelCase, make_canaries

ROOT = Path(__file__).resolve().parents[1]

PRODUCER = {"tool": "unblob", "version": "24.11.0", "config_ref": "dsr-config:extract-default",
            "config_sha256": "c" * 64, "rebuild_ref": "dsr-rebuild:extract --member {input}"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class StorageCase(LiteTestCase):
    def setUp(self) -> None:
        super().setUp()
        base = Path(self._tmp.name)
        self.mroot = base / "managed"
        self.qroot = base / "quarantine"
        self.mroot.mkdir()
        self.qroot.mkdir()
        self.assertTrue(self.lite.configure_storage_root("work", str(self.mroot), role="managed", actor="hermes")["accepted"])
        self.assertTrue(self.lite.configure_storage_root("quarantine", str(self.qroot), role="quarantine", actor="hermes")["accepted"])

    def write(self, rel: str, data: bytes = b"scratch-bytes") -> Path:
        p = self.mroot / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def reg(self, cid: str, rel: str, *, kind: str = "temp_workspace", cls: str = "ephemeral", **kw) -> dict:
        return self.lite.register_artifact(cid, actor=kw.pop("actor", "hermes"), root="work", path=rel, kind=kind,
                                           retention_class=cls, **kw)

    def storage_actions(self, cid: str) -> list[str]:
        return [e["action"] for e in self.lite.ledger(cid, "storage")]


class RegistryTests(StorageCase):
    def test_register_hashes_content_dedups_location_and_isolates_campaigns(self):
        a, b = self.campaign(), self.campaign()
        data = b"extracted squashfs listing"
        self.write("a/listing.txt", data)
        self.write("a/copy.txt", data)
        first = self.reg(a, "a/listing.txt", kind="extraction_tree", cls="ephemeral")
        self.assertEqual((first["accepted"], first["outcome"]), (True, "created"))
        art = first["artifact"]
        self.assertEqual((art["sha256"], art["size_bytes"], art["state"], art["campaign_id"]), (digest(data), len(data), "present", a))
        again = self.reg(a, "a/listing.txt", kind="extraction_tree", cls="ephemeral")
        self.assertEqual((again["outcome"], again["artifact"]["id"]), ("deduplicated", art["id"]))
        # same bytes at another location: a distinct registration that only *notes* the content twin
        twin = self.reg(a, "a/copy.txt", kind="extraction_tree", cls="ephemeral")
        self.assertEqual(twin["outcome"], "created")
        self.assertNotEqual(twin["artifact"]["id"], art["id"])
        self.assertEqual(twin["content_duplicates"], [art["id"]])
        # an expected hash that disagrees with the bytes is refused and ledgered, nothing registered
        bad = self.reg(a, "a/copy.txt", sha256="0" * 64)
        self.assertFalse(bad["accepted"])
        self.assertIn("sha256 mismatch", bad["reasons"][0])
        # campaign isolation: B sees none of A's artifacts and cannot reference them
        self.assertEqual(self.lite.list_artifacts(b), [])
        self.assertEqual(len(self.lite.list_artifacts(a)), 2)
        with self.assertRaises(ValueError):
            self.lite.reference_artifact(b, art["id"], actor="hermes", ref_type="report", ref_id="r1", reason="x")
        self.assertEqual(self.storage_actions(a), ["register", "dedup", "register", "register_refused"])
        self.assertTrue(self.lite.verify_ledger(a)["ok"])


class EligibilityTests(StorageCase):
    def test_protected_pinned_referenced_leased_active_and_evidence_artifacts_are_never_candidates(self):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="acme", name="img", image_sha256=sha("img"), members=members("httpd"), actor="hermes")
        self.lite.enqueue_image_jobs(cid, stage="inventory", kind="inventory", actor="hermes")
        job = self.lite.list_jobs(cid)[0]  # queued => unresolved work
        fid = self.lite.record_finding(cid, actor="qwen", candidate={
            "title": "cmd injection", "vuln_class": "cmdi", "severity": "high", "member_sha256": sha("httpd"),
            "evidence": [{"kind": "x", "ref": "r", "claim": "c"}], "artifact_refs": ["a"], "source_anchors": ["cgi:1"],
            "confidence": "low"})["finding"]["id"]
        made = {}
        for name, kind, cls in (("fw.bin", "firmware", "source"), ("state.sqlite", "state_db", "canonical"),
                                ("pinned.tmp", "scratch", "ephemeral"), ("ref.tmp", "scratch", "ephemeral"),
                                ("lease.tmp", "scratch", "ephemeral"), ("job.tmp", "scratch", "ephemeral"),
                                ("crash.log", "log", "diagnostic"), ("free.tmp", "scratch", "ephemeral")):
            self.write(name, name.encode() * 10)
            extra = {"job_id": job["id"]} if name == "job.tmp" else {"finding_id": fid} if name == "crash.log" else {}
            made[name] = self.reg(cid, name, kind=kind, cls=cls, **extra)["artifact"]["id"]
        # a firmware body can never be registered as cleanable scratch
        self.write("fw2.bin", b"firmware")
        weak = self.reg(cid, "fw2.bin", kind="firmware", cls="ephemeral")
        self.assertFalse(weak["accepted"])
        self.assertIn("must be registered as source", weak["reasons"][0])
        self.lite.pin_artifact(cid, made["pinned.tmp"], actor="hermes", reason="operator keep")
        self.lite.reference_artifact(cid, made["ref.tmp"], actor="hermes", ref_type="finding", ref_id=fid, reason="evidence")
        self.lite.hold_artifact(cid, made["lease.tmp"], actor="hermes", kind="lease", reason="worker reading",
                                expires_at=self.clock.now + 100 * 86400 + 3600)
        self.clock.advance(100 * 86400)
        # an over-broad request (all classes, zero ages) still cannot reach protected material
        plan = self.lite.plan_cleanup(cid, actor="hermes", rationale="broad sweep",
                                      policy={"classes": ["canonical", "source", "regenerable", "diagnostic", "ephemeral"],
                                              "min_age_s": {"ephemeral": 0, "diagnostic": 0}, "evidence_diagnostic_min_age_s": 0})
        self.assertTrue(plan["accepted"])
        plan = plan["plan"]
        self.assertEqual([c["artifact_id"] for c in plan["candidates"]], [made["free.tmp"]])
        self.assertEqual(plan["refused_classes"], ["canonical", "source"])
        why = {e["artifact_id"]: " ".join(e["reasons"]) for e in plan["exclusions"]["examples"]}
        self.assertIn("class source is protected", why[made["fw.bin"]])
        self.assertIn("class canonical is protected", why[made["state.sqlite"]])
        self.assertIn("pinned", why[made["pinned.tmp"]])
        self.assertIn(f"referenced by finding:{fid}", why[made["ref.tmp"]])
        self.assertIn("active lease", why[made["lease.tmp"]])
        self.assertIn(f"linked job {job['id']} is queued", why[made["job.tmp"]])
        self.assertIn(f"required by material finding {fid}", why[made["crash.log"]])
        # an expired lease no longer protects; a released reference no longer protects
        self.clock.advance(7200)
        ref = self.lite.get_artifact(made["ref.tmp"])["references"][0]["id"]
        self.lite.release_artifact(cid, actor="hermes", reference_id=ref, reason="evidence copied into report")
        again = self.lite.plan_cleanup(cid, actor="hermes", rationale="after release",
                                       policy={"min_age_s": {"ephemeral": 0}})["plan"]
        self.assertEqual(sorted(c["artifact_id"] for c in again["candidates"]),
                         sorted([made["free.tmp"], made["ref.tmp"], made["lease.tmp"]]))

    def test_regenerable_needs_complete_rebuild_provenance_and_live_inputs(self):
        cid = self.campaign()
        self.write("fw.bin", b"firmware image bytes")
        src = self.reg(cid, "fw.bin", kind="firmware", cls="source")["artifact"]
        self.write("x/full/a.txt", b"extracted a")
        self.write("x/partial/a.txt", b"extracted b")
        full = self.reg(cid, "x/full", kind="extraction_tree", cls="regenerable",
                        producer={**PRODUCER, "inputs": [{"artifact_id": src["id"], "sha256": src["sha256"]}]})
        partial = self.reg(cid, "x/partial", kind="extraction_tree", cls="regenerable",
                           producer={"tool": "unblob", "version": "24.11.0", "inputs": [{"sha256": src["sha256"]}]})
        self.assertEqual(full["artifact"]["object_type"], "dir")
        self.assertEqual(full["artifact"]["rebuild_missing"], [])
        self.assertEqual(partial["artifact"]["rebuild_missing"], ["config_sha256", "rebuild_ref"])
        self.clock.advance(2 * 86400)
        plan = self.lite.plan_cleanup(cid, actor="hermes", rationale="drop rebuildable trees",
                                      policy={"classes": ["regenerable"]})["plan"]
        self.assertEqual([c["artifact_id"] for c in plan["candidates"]], [full["artifact"]["id"]])
        why = {e["artifact_id"]: " ".join(e["reasons"]) for e in plan["exclusions"]["examples"]}
        self.assertIn("incomplete rebuild provenance: missing config_sha256, rebuild_ref", why[partial["artifact"]["id"]])
        # the source firmware is an input of a live artifact: protected twice over
        self.assertIn("rebuild input of live artifact", why[src["id"]])
        # a rebuild reference that carries a credential is refused, never stored
        self.write("x/secret/a.txt", b"c")
        bad = self.reg(cid, "x/secret", kind="extraction_tree", cls="regenerable",
                       producer={**PRODUCER, "rebuild_ref": "extract --token " + "gh" + "p_" + "A" * 36})
        self.assertFalse(bad["accepted"])
        self.assertNotIn("A" * 36, str(self.lite.ledger(cid, "storage")))


class PlanTests(StorageCase):
    def test_plan_is_immutable_dry_run_with_exact_reclaim_accounting(self):
        cid = self.campaign()
        sizes = {"a.tmp": 1000, "b.tmp": 2500, "d/c.bin": 4096}
        ids = {}
        for rel, n in sizes.items():
            self.write(rel, b"x" * n)
            ids[rel] = self.reg(cid, rel, kind="scratch")["artifact"]["id"]
        self.write("d/e.bin", b"y" * 300)
        tree = self.reg(cid, "d", kind="temp_workspace")["artifact"]  # directory: sum of member files
        self.assertEqual(tree["size_bytes"], 4096 + 300)
        os.link(self.mroot / "b.tmp", self.mroot / "b.hardlink")  # second link: deleting b frees nothing
        self.clock.advance(2 * 3600)
        before = sorted(str(p.relative_to(self.mroot)) for p in self.mroot.rglob("*"))
        res = self.lite.plan_cleanup(cid, actor="hermes", rationale="hourly scratch sweep")
        plan = res["plan"]
        self.assertEqual(plan["status"], "planned")
        recl = {c["artifact_id"]: c["reclaim_bytes"] for c in plan["candidates"]}
        # b.tmp drifted (nlink changed since registration) so it is refused, not reclaimed; a + dir tree remain
        self.assertNotIn(ids["b.tmp"], recl)
        self.assertEqual(recl[ids["a.tmp"]], 1000)
        self.assertEqual(plan["expected_reclaim_bytes"], sum(recl.values()))
        self.assertEqual(sorted(str(p.relative_to(self.mroot)) for p in self.mroot.rglob("*")), before)  # no FS mutation
        val = self.lite.validate_cleanup_plan(cid, plan["id"])
        self.assertTrue(val["plan_sha256_ok"])
        self.assertEqual(val["would_reclaim_bytes_on_purge"], plan["expected_reclaim_bytes"])
        dry = self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes")  # default: dry run
        self.assertFalse(dry["executed"])
        self.assertEqual(sorted(str(p.relative_to(self.mroot)) for p in self.mroot.rglob("*")), before)
        # new eligible material appearing after planning never expands the plan at apply time
        self.write("late.tmp", b"z" * 50)
        late = self.reg(cid, "late.tmp", kind="scratch")["artifact"]
        self.clock.advance(2 * 3600)
        out = self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        self.assertEqual(out["result"]["quarantined"], len(plan["candidates"]))
        self.assertEqual(self.lite.get_artifact(late["id"])["state"], "present")
        # tampering with the stored plan is detected and refused (no silent expansion)
        plan2 = self.lite.plan_cleanup(cid, actor="hermes", rationale="second")["plan"]
        self.lite.store.conn.execute("UPDATE cleanup_plans SET candidates='[]' WHERE id=?", (plan2["id"],))
        tampered = self.lite.apply_cleanup_plan(cid, plan2["id"], actor="hermes", execute=True)
        self.assertFalse(tampered["accepted"])
        self.assertIn("tampered", tampered["reasons"][0])
        self.assertEqual(self.lite.get_artifact(late["id"])["state"], "present")


class PathSafetyTests(StorageCase):
    def test_traversal_symlink_device_and_unsafe_roots_are_refused(self):
        cid = self.campaign()
        outside = Path(self._tmp.name) / "outside"
        outside.mkdir()
        (outside / "victim.bin").write_bytes(b"must survive")
        (self.mroot / "link_dir").symlink_to(outside, target_is_directory=True)
        (self.mroot / "link_file").symlink_to(outside / "victim.bin")
        os.mkfifo(self.mroot / "pipe")
        sock = socket.socket(socket.AF_UNIX)
        short = Path("/tmp") / f"dsr-sock-{os.getpid()}"
        short.mkdir(exist_ok=True)
        try:
            sock.bind(str(short / "s"))
            (self.mroot / "sockdir").symlink_to(short)  # reached only through a symlink: refused as such
            for rel, needle in (("../outside/victim.bin", "traversal"), ("/etc/hosts", "relative"),
                                ("link_dir/victim.bin", "symlink"), ("link_file", "symlink"), ("pipe", "fifo"),
                                ("sockdir/s", "symlink"), ("a/./b", "traversal")):
                res = self.reg(cid, rel)
                self.assertFalse(res["accepted"], rel)
                self.assertIn(needle, " ".join(res["reasons"]), rel)
        finally:
            sock.close()
            for p in short.iterdir():
                p.unlink()
            short.rmdir()
        self.assertEqual(self.lite.list_artifacts(cid), [])
        self.assertEqual((outside / "victim.bin").read_bytes(), b"must survive")
        # dangerous roots: the state database's directory, a symlinked root, an overlapping root
        for name, path, needle in (("statedir", str(self.db.parent), "overlaps configured root"),
                                   ("inner", str(self.mroot / "sub"), None)):
            if needle is None:
                (self.mroot / "sub").mkdir()
                needle = "overlaps configured root"
            res = self.lite.configure_storage_root(name, path, actor="hermes")
            self.assertFalse(res["accepted"])
            self.assertIn(needle, " ".join(res["reasons"]))
        other = Path(self._tmp.name) / "elsewhere"
        other.mkdir()
        self.assertIn("contains the canonical state database",
                      " ".join(self.lite.configure_storage_root("db", os.path.realpath(Path(self.db).parent.parent),
                                                               actor="hermes")["reasons"]))
        (Path(self._tmp.name) / "rootlink").symlink_to(other, target_is_directory=True)
        self.assertIn("symlink", " ".join(self.lite.configure_storage_root("lnk", str(Path(self._tmp.name) / "rootlink"),
                                                                             actor="hermes")["reasons"]))
        refused = [e for e in self.lite.ledger("host:storage", "storage") if e["action"] == "config_refused"]
        self.assertGreaterEqual(len(refused), 4)

    def test_root_swapped_for_symlink_after_configuration_is_refused(self):
        cid = self.campaign()
        self.write("scratch.tmp")
        art = self.reg(cid, "scratch.tmp")["artifact"]
        self.clock.advance(7200)
        plan = self.lite.plan_cleanup(cid, actor="hermes", rationale="sweep")["plan"]
        self.assertEqual(len(plan["candidates"]), 1)
        decoy = Path(self._tmp.name) / "decoy"
        decoy.mkdir()
        (decoy / "scratch.tmp").write_bytes(b"scratch-bytes")
        self.mroot.rename(Path(self._tmp.name) / "managed.orig")
        self.mroot.symlink_to(decoy, target_is_directory=True)
        out = self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        self.assertEqual(out["result"]["refused"], 1)
        self.assertIn("storage root", out["result"]["refusals"][0]["reason"])
        self.assertTrue((decoy / "scratch.tmp").exists())
        self.assertEqual(self.lite.get_artifact(art["id"])["state"], "present")
        # a different *real* directory at the same path (same realpath, same file layout) is caught by dev/inode identity
        self.mroot.unlink()
        self.mroot.mkdir()
        (self.mroot / "scratch.tmp").write_bytes(b"scratch-bytes")
        plan2 = self.lite.plan_cleanup(cid, actor="hermes", rationale="after swap")["plan"]
        self.assertEqual(plan2["candidates"], [])
        self.assertIn("storage root changed identity", " ".join(plan2["exclusions"]["examples"][0]["reasons"]))
        self.assertIn("storage root changed identity",
                      " ".join(self.reg(cid, "scratch.tmp")["reasons"]))
        self.assertTrue((self.mroot / "scratch.tmp").exists())


class DriftTests(StorageCase):
    def test_target_changed_between_plan_and_apply_is_refused_not_deleted(self):
        cid = self.campaign()
        for rel in ("same.tmp", "grown.tmp", "swapped.tmp", "rewritten.tmp", "gone.tmp"):
            self.write(rel, b"original!")
        ids = {rel: self.reg(cid, rel)["artifact"]["id"] for rel in ("same.tmp", "grown.tmp", "swapped.tmp", "rewritten.tmp", "gone.tmp")}
        self.clock.advance(7200)
        plan = self.lite.plan_cleanup(cid, actor="hermes", rationale="sweep")["plan"]
        self.assertEqual(len(plan["candidates"]), 5)
        (self.mroot / "grown.tmp").write_bytes(b"original! plus more")
        (self.mroot / "swapped.tmp").unlink()
        (self.mroot / "swapped.tmp").write_bytes(b"original!")  # same bytes, new inode
        p = self.mroot / "rewritten.tmp"
        st = p.stat()
        p.write_bytes(b"ORIGINAL!")  # same size; restore mtime: only the hash can tell
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        ino = p.stat().st_ino
        (self.mroot / "gone.tmp").unlink()
        val = self.lite.validate_cleanup_plan(cid, plan["id"])
        self.assertEqual((val["would_quarantine"], val["would_refuse"]), (1, 4))
        out = self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        self.assertEqual((out["plan"]["status"], out["result"]["quarantined"], out["result"]["refused"]), ("partial", 1, 4))
        reasons = {r["artifact_id"]: r["reason"] for r in out["result"]["refusals"]}
        self.assertIn("size", reasons[ids["grown.tmp"]])
        self.assertIn("ino", reasons[ids["swapped.tmp"]])
        self.assertIn("sha256", reasons[ids["rewritten.tmp"]])
        self.assertIn("does not exist", reasons[ids["gone.tmp"]])
        for rel in ("grown.tmp", "swapped.tmp", "rewritten.tmp"):
            self.assertTrue((self.mroot / rel).exists(), rel)
        self.assertEqual(p.stat().st_ino, ino)
        self.assertEqual(self.lite.get_artifact(ids["same.tmp"])["state"], "quarantined")
        self.assertEqual(self.storage_actions(cid).count("quarantine_refused"), 4)

    def test_swap_between_check_and_rename_is_caught_after_move_and_put_back(self):
        from refall_lite import storage_fs
        cid = self.campaign()
        self.write("race.tmp", b"planned body")
        art = self.reg(cid, "race.tmp")["artifact"]
        self.clock.advance(7200)
        plan = self.lite.plan_cleanup(cid, actor="hermes", rationale="sweep")["plan"]
        real_move = storage_fs.move_into_fresh_dir

        def racing_move(src, dest_dir, name):  # attacker swaps the file after validation, just before the rename
            src.unlink()
            src.write_bytes(b"other body!!")
            return real_move(src, dest_dir, name)
        storage_fs.move_into_fresh_dir = racing_move
        try:
            out = self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        finally:
            storage_fs.move_into_fresh_dir = real_move
        self.assertEqual(out["result"]["refused"], 1)
        self.assertIn("post-move verification failed", out["result"]["refusals"][0]["reason"])
        self.assertEqual((self.mroot / "race.tmp").read_bytes(), b"other body!!")  # put back, not deleted
        self.assertEqual(self.lite.get_artifact(art["id"])["state"], "present")


class Crash(BaseException):
    """Simulated process death (not an Exception, so nothing in the code under test can swallow it)."""


class LifecycleTests(StorageCase):
    def _plan(self, cid: str, *rels: str, **policy) -> dict:
        for rel in rels:  # one second apart: candidates are ordered by registration time
            self.write(rel, rel.encode() * 100)
            self.reg(cid, rel)
            self.clock.advance(1)
        self.clock.advance(7200)
        return self.lite.plan_cleanup(cid, actor="hermes", rationale="sweep", policy=policy or None)["plan"]

    def test_crash_before_and_after_rename_recovers_on_reopen_without_double_accounting(self):
        from refall_lite import storage_fs
        cid = self.campaign()
        plan = self._plan(cid, "before.tmp", "after.tmp", "clean.tmp")
        by_rel = {c["rel_path"]: c["artifact_id"] for c in plan["candidates"]}
        real_move, calls = storage_fs.move_into_fresh_dir, []

        def crashing_move(src, dest_dir, name):  # each simulated death happens once
            first = src.name not in calls
            calls.append(src.name)
            if src.name == "before.tmp" and first:
                raise Crash("killed before rename")
            out = real_move(src, dest_dir, name)
            if src.name == "after.tmp" and first:
                raise Crash("killed after rename, before the receipt commit")
            return out
        storage_fs.move_into_fresh_dir = crashing_move
        try:
            with self.assertRaises(Crash):
                self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
            self.reopen()
            states = {a["artifact_id"]: a["state"] for a in self.lite.get_cleanup_plan(plan["id"])["actions"]}
            self.assertEqual(states[by_rel["before.tmp"]], "intent")
            self.assertEqual(self.lite.get_cleanup_plan(plan["id"])["status"], "applying")
            self.assertTrue((self.mroot / "before.tmp").exists())  # durable intent, nothing lost
            with self.assertRaises(Crash):  # rerun: before.tmp re-validated, then after.tmp's crash happens
                self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
            self.reopen()
            self.assertFalse((self.mroot / "after.tmp").exists())
            self.assertEqual(self.lite.get_artifact(by_rel["after.tmp"])["state"], "present")  # no false success receipt
        finally:
            storage_fs.move_into_fresh_dir = real_move
        out = self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        self.assertEqual((out["plan"]["status"], out["result"]["quarantined"], out["result"]["refused"]), ("applied", 3, 0))
        self.assertEqual(out["result"]["quarantined_bytes"], sum(c["size_bytes"] for c in plan["candidates"]))
        led = self.lite.ledger(cid, "storage")
        for aid in by_rel.values():  # exactly one success receipt per artifact
            self.assertEqual(sum(1 for e in led if e["action"] == "quarantine" and e["payload"]["artifact_id"] == aid), 1)
        self.assertIn("rename completed before interruption; verified and finalized",
                      [e["payload"].get("decision") for e in led if e["action"] == "recover"])
        again = self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        self.assertTrue(again["idempotent"])
        self.assertEqual(len(self.lite.ledger(cid, "storage")), len(led))
        self.assertTrue(self.lite.verify_ledger(cid)["ok"])

    def test_restore_while_quarantined_then_purge_after_retention_keeps_tombstone(self):
        cid = self.campaign()
        plan = self._plan(cid, "keep.tmp", "drop.tmp", "w/deep.tmp", quarantine_retention_s=3600)
        ids = {c["rel_path"]: c["artifact_id"] for c in plan["candidates"]}
        self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        q_files = sorted(p.name for p in self.qroot.rglob("*") if p.is_file() and p.name != ".dsr-storage.lock")
        self.assertEqual(q_files, ["deep.tmp", "drop.tmp", "keep.tmp"])
        self.assertFalse((self.mroot / "keep.tmp").exists())
        # restore: dry run first, then execute; the parent directory is recreated safely if it vanished
        (self.mroot / "w").rmdir()
        self.assertFalse(self.lite.restore_artifact(cid, ids["w/deep.tmp"], actor="hermes")["executed"])
        for rel in ("keep.tmp", "w/deep.tmp"):
            res = self.lite.restore_artifact(cid, ids[rel], actor="hermes", execute=True)
            self.assertTrue(res["accepted"], res)
            self.assertEqual((self.mroot / rel).read_bytes(), rel.encode() * 100)
            self.assertEqual(self.lite.get_artifact(ids[rel])["state"], "present")
        # an occupied original location blocks restore instead of being overwritten
        self.lite.apply_cleanup_plan(cid, self.lite.plan_cleanup(cid, actor="hermes", rationale="again")["plan"]["id"],
                                     actor="hermes", execute=True)
        self.write("keep.tmp", b"newcomer")
        blocked = self.lite.restore_artifact(cid, ids["keep.tmp"], actor="hermes", execute=True)
        self.assertFalse(blocked["accepted"])
        self.assertIn("occupied", blocked["reasons"][0])
        self.assertEqual((self.mroot / "keep.tmp").read_bytes(), b"newcomer")
        # purge refuses before retention, then deletes after it, keeping hash/size/path tombstones
        early = self.lite.purge_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        self.assertEqual(early["purged"], 0)
        self.assertIn("quarantine retention until", early["items"][0]["reasons"][0])
        self.clock.advance(3601)
        dry = self.lite.purge_cleanup_plan(cid, plan["id"], actor="hermes")
        self.assertEqual([i["would"] for i in dry["items"]], ["purge"])
        self.assertTrue(any(p.name == "drop.tmp" for p in self.qroot.rglob("*")))
        done = self.lite.purge_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        self.assertEqual((done["purged"], done["reclaimed_bytes"]), (1, len(b"drop.tmp" * 100)))
        self.assertFalse(any(p.name == "drop.tmp" for p in self.qroot.rglob("*")))
        tomb = self.lite.get_artifact(ids["drop.tmp"])
        self.assertEqual(tomb["state"], "purged")
        self.assertEqual((tomb["tombstone"]["sha256"], tomb["tombstone"]["size_bytes"], tomb["tombstone"]["rel_path"]),
                         (digest(b"drop.tmp" * 100), 800, "drop.tmp"))
        self.assertEqual(self.lite.purge_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)["purged"], 0)  # idempotent
        inv = self.lite.storage_inventory(cid)["totals"]
        self.assertEqual((inv["tombstones"], inv["purged_bytes"]), (1, 800))
        # the path can be reused by a new registration; the tombstone stays
        self.write("drop.tmp", b"fresh")
        self.assertEqual(self.reg(cid, "drop.tmp")["outcome"], "created")
        self.assertEqual(self.lite.get_artifact(ids["drop.tmp"])["state"], "purged")
        actions = self.storage_actions(cid)
        for needed in ("quarantine_intent", "quarantine", "restore", "restore_refused", "purge_refused", "purge_intent", "purge"):
            self.assertIn(needed, actions)

    def test_concurrent_mutation_is_refused_while_another_apply_holds_the_storage_lock(self):
        from refall_lite import storage_fs
        cid = self.campaign()
        plan = self._plan(cid, "one.tmp", "two.tmp", quarantine_retention_s=0)
        real_move, seen, entered = storage_fs.move_into_fresh_dir, [], []

        def interleaved_move(src, dest_dir, name):  # a second supervisor process acts mid-apply
            if not entered:
                entered.append(True)
                other = RefallLite(self.db, clock=self.clock)
                try:
                    seen.append(other.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True))
                    seen.append(other.purge_cleanup_plan(cid, plan["id"], actor="hermes", execute=True))
                finally:
                    other.close()
            return real_move(src, dest_dir, name)
        storage_fs.move_into_fresh_dir = interleaved_move
        try:
            out = self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        finally:
            storage_fs.move_into_fresh_dir = real_move
        self.assertEqual([s["accepted"] for s in seen], [False, False])
        self.assertTrue(all("another storage mutation" in " ".join(s["reasons"]) for s in seen))
        self.assertEqual((out["plan"]["status"], out["result"]["quarantined"]), ("applied", 2))
        led = self.lite.ledger(cid, "storage")
        self.assertEqual(sum(e["action"] == "quarantine" for e in led), 2)
        self.assertNotIn("recover", [e["action"] for e in led])
        self.assertEqual([e["action"] for e in led if e["action"].endswith("_refused")], ["apply_refused", "purge_refused"])
        # the lock is released after the holder finishes: a later purge proceeds
        self.assertEqual(self.lite.purge_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)["purged"], 2)

    def test_hold_placed_while_quarantined_blocks_purge(self):
        cid = self.campaign()
        plan = self._plan(cid, "q.tmp", quarantine_retention_s=0)
        aid = plan["candidates"][0]["artifact_id"]
        self.lite.apply_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        self.lite.hold_artifact(cid, aid, actor="analyst", kind="hold", reason="incident review")
        out = self.lite.purge_cleanup_plan(cid, plan["id"], actor="hermes", execute=True)
        self.assertEqual(out["purged"], 0)
        self.assertIn("active hold", out["items"][0]["reasons"][0])
        self.assertEqual(self.lite.get_artifact(aid)["state"], "quarantined")


class FakeDisk:
    def __init__(self, total: int, free: int) -> None:
        self.total, self.free = total, free

    def __call__(self, path: str):
        return shutil._ntuple_diskusage(self.total, self.total - self.free, self.free)


class PressureTests(StorageCase):
    def test_thresholds_gate_only_storage_heavy_claims_and_emergency_is_durable(self):
        cid = self.campaign()
        self.lite.ingest_image(cid, family="acme", name="img", image_sha256=sha("img"), members=members("a", "b", "c"),
                               actor="hermes")
        self.to_middle(cid)
        self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        t = 1000 << 30
        disk = FakeDisk(t, int(t * 0.5))
        self.lite._disk_usage = disk
        bad = {"high": {"min_free_fraction": 0.01}, "critical": {"min_free_fraction": 0.05}}
        with self.assertRaises(ValueError):  # non-monotonic thresholds are a structural error
            self.lite.configure_storage_thresholds(actor="hermes", thresholds=bad)
        self.lite.configure_storage_thresholds(actor="hermes", thresholds={"emergency": {"min_free_fraction": 0.02,
                                                                                         "min_free_bytes": 10 << 30}})
        normal = self.lite.sample_storage(actor="hermes")
        self.assertEqual((normal["level"], normal["storage_heavy_claims_allowed"], normal["emergency_stop"]), ("normal", True, False))
        first = self.lite.claim_job(cid, worker="qwen", stage="middle")["job"]["id"]  # normal pressure: anything may start
        others = [j["id"] for j in self.lite.list_jobs(cid, stage="middle", status="queued")]
        heavy, light = others
        for jid in (first, heavy):  # the contract is explicit and durable; job names/kinds are never inspected
            self.lite.set_job_storage_intent(cid, jid, actor="hermes", intent="heavy", estimated_bytes=50 << 30,
                                             reason="full decompiler database")
        self.lite.set_job_storage_intent(cid, light, actor="hermes", intent="light", reason="metadata only")
        disk.free = int(t * 0.10)  # high: no new heavy claims, unrelated light work continues
        high = self.lite.sample_storage(actor="hermes")
        self.assertEqual((high["level"], high["storage_heavy_claims_allowed"], high["pause_storage_heavy"]), ("high", False, False))
        nxt = self.lite.claim_job(cid, worker="qwen", stage="middle")
        self.assertEqual(nxt["job"]["id"], light)
        idle = self.lite.claim_job(cid, worker="qwen", stage="middle")
        self.assertFalse(idle["claimed"])
        self.assertEqual(idle["storage_paused"], [heavy])
        disk.free = int(t * 0.06)  # critical: existing heavy work should pause
        crit = self.lite.sample_storage(actor="hermes")
        self.assertEqual((crit["level"], crit["pause_storage_heavy"], crit["pause_jobs"]), ("critical", True, [first]))
        disk.free = 5 << 30  # emergency by absolute free bytes, before the fraction is reached
        emer = self.lite.sample_storage(actor="hermes")
        self.assertEqual((emer["level"], emer["emergency_stop"]), ("emergency", True))
        self.assertGreaterEqual(emer["managed_bytes"], 0)
        self.assertIn("eligible_reclaim_estimate_bytes", emer)
        self.reopen()  # durable: status after restart still says emergency without re-sampling
        st = self.lite.status(cid)["storage"]
        self.assertEqual((st["level"], st["emergency_stop"], st["storage_heavy_claims_allowed"]), ("emergency", True, False))
        self.assertEqual(self.lite.storage_status()["level"], "emergency")
        changes = [e["payload"]["level"] for e in self.lite.ledger("host:storage", "storage") if e["action"] == "pressure_change"]
        self.assertEqual(changes, ["high", "critical", "emergency"])
        self.assertTrue(self.lite.verify_ledger("host:storage")["ok"])


class AuthorityTests(StorageCase):
    def test_non_operators_are_refused_and_every_refusal_is_ledgered(self):
        cid = self.campaign()
        self.write("w.tmp")
        art = self.reg(cid, "w.tmp")["artifact"]
        self.clock.advance(7200)
        plan = self.lite.plan_cleanup(cid, actor="hermes", rationale="sweep")["plan"]
        before = len(self.lite.ledger(cid, "storage"))
        for actor in ("qwen", "checker"):  # model and tool kinds are not operators
            self.assertFalse(self.reg(cid, "w.tmp", actor=actor)["accepted"])
            self.assertFalse(self.lite.plan_cleanup(cid, actor=actor, rationale="mine")["accepted"])
            self.assertFalse(self.lite.apply_cleanup_plan(cid, plan["id"], actor=actor, execute=True)["accepted"])
            self.assertFalse(self.lite.pin_artifact(cid, art["id"], actor=actor, reason="x")["accepted"])
            self.assertFalse(self.lite.hold_artifact(cid, art["id"], actor=actor, kind="hold", reason="x")["accepted"])
            self.assertFalse(self.lite.restore_artifact(cid, art["id"], actor=actor, execute=True)["accepted"])
            self.assertFalse(self.lite.purge_cleanup_plan(cid, plan["id"], actor=actor, execute=True)["accepted"])
            self.assertFalse(self.lite.configure_storage_root(f"r-{actor}", str(self.mroot), actor=actor)["accepted"])
            self.assertFalse(self.lite.sample_storage(actor=actor)["accepted"])
        refused = [e for e in self.lite.ledger(cid, "storage")[before:]]
        self.assertEqual(sorted({e["action"] for e in refused}),
                         ["action_refused", "apply_refused", "plan_refused", "purge_refused", "register_refused", "restore_refused"])
        self.assertTrue(all("operator kind" in " ".join(e["payload"]["reasons"]) for e in refused))
        self.assertEqual(self.lite.get_artifact(art["id"])["state"], "present")
        self.assertTrue((self.mroot / "w.tmp").exists())
        host = [e["action"] for e in self.lite.ledger("host:storage", "storage")]
        self.assertEqual(host.count("config_refused"), 4)
        with self.assertRaises(KeyError):  # unknown actor is structural: nothing written
            self.lite.plan_cleanup(cid, actor="nobody", rationale="x")
        with self.assertRaises(ValueError):  # unknown policy keys are structural: nothing written
            self.lite.plan_cleanup(cid, actor="hermes", rationale="x", policy={"delete_everything": True})


class StorageSecrecyTelemetryTests(TelCase):
    def test_raw_bodies_and_secrets_never_reach_state_ledger_or_telemetry(self):
        c = make_canaries()
        db = self.root / "s.sqlite"
        work = self.root / "work"
        work.mkdir()
        body = b"\x7fELF" + os.urandom(1 << 20) + f"BODY {c['custom']} {c['password']} {c['private_key']}".encode()
        (work / "fw.bin").write_bytes(body)
        (work / "x").mkdir()
        (work / "x" / "cfg").write_bytes(f"api_key={c['api_key']} {c['custom']}".encode())
        lite = RefallLite(db, telemetry=self.tel("refall-lite"))
        try:
            lite.register_actor("hermes", "supervisor")
            cid = lite.create_campaign("c", config=base_config(), actor="hermes")["id"]
            lite.configure_storage_root("work", str(work), actor="hermes")
            fw = lite.register_artifact(cid, actor="hermes", root="work", path="fw.bin", kind="firmware",
                                        retention_class="source", media_type="application/octet-stream")
            self.assertEqual((fw["artifact"]["sha256"], fw["artifact"]["size_bytes"]), (digest(body), len(body)))
            for bad in ({"labels": {"note": f"password={c['password']}"}},
                        {"producer": {**PRODUCER, "config_ref": c["conn"]}},
                        {"producer": {**PRODUCER, "rebuild_ref": f"extract --key {c['github']}"}},
                        {"media_type": c["api_key"]}):
                res = lite.register_artifact(cid, actor="hermes", root="work", path="x", kind="extraction_tree",
                                             retention_class="regenerable", **bad)
                self.assertFalse(res["accepted"], bad)
            ok = lite.register_artifact(cid, actor="hermes", root="work", path="x", kind="extraction_tree",
                                        retention_class="ephemeral")
            lite.reference_artifact(cid, ok["artifact"]["id"], actor="hermes", ref_type="external", ref_id="ticket-1",
                                    reason=f"keep; bearer {c['bearer']}")
            self.assertNotIn(c["bearer"], lite.get_artifact(ok["artifact"]["id"])["references"][0]["reason"])
        finally:
            lite.close()
        raw = b"".join(p.read_bytes() for p in (db, Path(f"{db}-wal")) if p.exists())
        self.assertNotIn(c["custom"].encode(), raw)  # no file body (or any slice of it) in SQLite
        self.assertLess(db.stat().st_size, len(body))
        self.assertNoNeedles(c, db, Path(f"{db}-wal"))
        evs = self.events()
        storage = [e for e in evs if e["event_type"].startswith("storage.")]
        self.assertEqual([e["event_type"] for e in storage],
                         ["storage.root_configure", "storage.register"] + ["storage.register_refused"] * 4
                         + ["storage.register", "storage.reference"])
        self.assertEqual({e["level"] for e in storage if e["event_type"].endswith("_refused")}, {"warning"})
        calls = {e["event_id"] for e in evs if e["event_type"] == "api.call"}
        self.assertTrue(all(e["parent_event_id"] in calls for e in storage))
        reg = storage[1]
        self.assertEqual((reg["data"]["payload"]["sha256"], reg["artifact_id"]), (digest(body), f"sha256:{digest(body)}"))
        self.assertLogsValid()


class StorageCliTests(unittest.TestCase):
    def test_cli_json_contract_read_only_defaults_authority_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / "managed").mkdir()
            (t / "q").mkdir()
            (t / "managed" / "scratch.tmp").write_bytes(b"scratch body")
            env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE="1", FIRMWARE_SPIDER_LOG_DIR=str(t / "logs"),
                       FIRMWARE_SPIDER_DEADLETTER_DIR=str(t / "dead"))

            def run(*a: str):
                p = subprocess.run([sys.executable, "-m", "refall_lite", "--db", str(t / "s.sqlite"), *a],
                                   capture_output=True, text=True, env=env)
                return p.returncode, json.loads(p.stdout)

            def put(name: str, obj) -> str:
                (t / name).write_text(json.dumps(obj))
                return str(t / name)

            run("actor", "add", "hermes", "--kind", "supervisor")
            run("actor", "add", "qwen", "--kind", "model")
            cid = run("campaign", "create", "c", "--config", put("cfg.json", base_config()), "--actor", "hermes")[1]["id"]
            self.assertTrue(run("storage", "root-add", "work", str(t / "managed"), "--actor", "hermes")[1]["accepted"])
            self.assertTrue(run("storage", "root-add", "quarantine", str(t / "q"), "--role", "quarantine",
                                "--actor", "hermes")[1]["accepted"])
            self.assertEqual([r["role"] for r in run("storage", "roots")[1]], ["quarantine", "managed"])
            code, reg = run("artifact", "register", cid, "--actor", "hermes", "--root", "work", "--path", "scratch.tmp",
                            "--kind", "scratch", "--class", "ephemeral", "--expires-at", "0")
            self.assertEqual((code, reg["outcome"]), (0, "created"))
            aid = reg["artifact"]["id"]
            self.assertEqual(run("artifact", "show", aid)[1]["sha256"], digest(b"scratch body"))
            self.assertEqual([a["id"] for a in run("artifact", "list", cid, "--state", "present")[1]], [aid])
            hold = run("artifact", "hold", cid, aid, "--actor", "hermes", "--kind", "hold", "--reason", "review")[1]
            self.assertTrue(hold["accepted"])
            ref = run("artifact", "reference", cid, aid, "--actor", "hermes", "--ref-type", "external", "--ref-id", "t-1",
                      "--reason", "ticket")[1]
            preview = run("storage", "plan", cid)[1]  # default: read-only preview, nothing persisted
            self.assertEqual((preview["recorded"], preview["candidates"]), (False, []))
            for rid in (["--hold", hold["hold"]], ["--reference", ref["reference"]]):
                self.assertTrue(run("artifact", "release", cid, *rid, "--actor", "hermes", "--reason", "done")[1]["accepted"])
            ledger_before = len(RefallLite(t / "s.sqlite", telemetry=False).ledger(cid, "storage"))
            preview = run("storage", "plan", cid, "--policy", put("p.json", {"quarantine_retention_s": 0}))[1]
            self.assertEqual([c["artifact_id"] for c in preview["candidates"]], [aid])
            self.assertEqual(len(RefallLite(t / "s.sqlite", telemetry=False).ledger(cid, "storage")), ledger_before)
            code, refused = run("storage", "plan", cid, "--record", "--actor", "qwen", "--rationale", "mine")
            self.assertEqual((code, refused["accepted"]), (0, False))  # policy refusal: ledgered, exit 0
            plan = run("storage", "plan", cid, "--record", "--actor", "hermes", "--rationale", "sweep",
                       "--policy", str(t / "p.json"))[1]["plan"]
            self.assertEqual(run("storage", "plan-show", plan["id"])[1]["plan_sha256"], plan["plan_sha256"])
            self.assertEqual(run("storage", "plans", cid)[1][0]["id"], plan["id"])
            self.assertEqual(run("storage", "validate", cid, plan["id"])[1]["would_quarantine"], 1)
            dry = run("storage", "apply", cid, plan["id"], "--actor", "hermes")[1]  # default: dry run
            self.assertFalse(dry["executed"])
            self.assertTrue((t / "managed" / "scratch.tmp").exists())
            done = run("storage", "apply", cid, plan["id"], "--actor", "hermes", "--execute")[1]
            self.assertEqual(done["result"]["quarantined"], 1)
            self.assertFalse((t / "managed" / "scratch.tmp").exists())
            self.assertTrue(run("storage", "restore", cid, aid, "--actor", "hermes", "--execute")[1]["accepted"])
            self.assertTrue((t / "managed" / "scratch.tmp").exists())
            self.assertEqual(run("storage", "purge", cid, plan["id"], "--actor", "hermes", "--execute")[1]["purged"], 0)
            inv = run("storage", "inventory", "--cid", cid)[1]
            self.assertEqual(inv["totals"]["present_bytes"], len(b"scratch body"))
            self.assertFalse(run("storage", "status")[1]["sampled"])  # read-only: never samples
            sample = run("storage", "sample", "--actor", "hermes")[1]
            self.assertIn(sample["level"], ("normal", "high", "critical", "emergency"))
            self.assertTrue(run("storage", "status")[1]["sampled"])
            self.assertEqual(run("storage", "thresholds")[1]["high"]["min_free_fraction"], 0.15)
            self.assertEqual(run("artifact", "pin", cid, aid, "--actor", "qwen", "--reason", "x")[1]["accepted"], False)
            for bad in (["artifact", "register", cid, "--actor", "hermes", "--root", "nope", "--path", "a", "--kind", "scratch",
                         "--class", "ephemeral"],
                        ["storage", "plan", cid, "--record", "--actor", "hermes", "--rationale", "x",
                         "--policy", put("bad.json", {"delete_everything": True})],
                        ["artifact", "show", "art_missing"]):
                code, err = run(*bad)
                self.assertEqual(code, 2, bad)
                self.assertIn("Error", err["error"])
