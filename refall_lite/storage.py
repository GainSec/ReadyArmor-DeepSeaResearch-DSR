"""Artifact registry, retention/cleanup and disk-pressure control (schema v4).

One persistent DSR supervisor on the control host owns all state and storage; Spark is remote LLM inference only and never
owns or mutates artifacts. See docs/STORAGE-AND-CLEANUP.md.

  * Registry: campaign-scoped registrations of files/directories under configured storage roots, with content
    identity (SHA-256; equal hashes are recorded as content twins, never merged), producer/provenance, retention
    class, lifecycle state, references, leases/holds, pins and job linkage. File bodies are never stored.
  * Cleanup is a durable workflow: inventory -> immutable plan (policy snapshot, exact candidates + snapshots,
    expected reclaim) -> read-only validation -> explicit operator apply (atomic same-filesystem rename into the
    quarantine root, post-move verification, then state + receipt) -> restore while quarantined -> separate explicit
    purge after the plan's quarantine retention, keeping a tombstone (hash/size/path) forever.
  * Canonical/protected and source/retained artifacts are never candidates, nor is anything pinned, referenced,
    held/leased, linked to unresolved work, needed by a validated/material finding, an input of a live artifact, or
    (regenerable) missing complete rebuild provenance.
  * Disk pressure: operator-taken samples (durable + ledgered) map free space onto normal/high/critical/emergency and
    produce supervisor guidance. Claims skip only jobs with an explicitly declared heavy storage intent.
Every state change requires an operator kind and is ledgered (kind ``storage``) in the same transaction; refusals are
ledgered as ``*_refused`` with reasons that name fields, never refused values. Structural input errors raise and
write nothing. Filesystem outcomes are verified before the success receipt is committed; an interrupted apply,
restore or purge is reconciled from its durable intent row when the same command is rerun.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any, Callable

from . import storage_fs as sfs
from ._base import Base
from .arcticbase.contracts import (
    ARTIFACT_CLASSES,
    ARTIFACT_KIND_MIN_CLASS,
    ARTIFACT_KINDS,
    CLASS_RANK,
    HOLD_KINDS,
    JOB_UNRESOLVED,
    LABELS_MAX,
    OPERATOR_KINDS,
    PRESSURE_GUIDANCE,
    PRESSURE_LEVELS,
    PROTECTED_CLASSES,
    REF_TYPES,
    ROOT_ROLES,
    STORAGE_INTENTS,
    canonical_json,
    evaluate_cleanup_policy,
    evaluate_provenance,
    evaluate_thresholds,
    normalize_sha256,
    pressure_level,
    sha256_text,
    storage_ref_reasons,
    storage_text,
)
from .arcticbase.store import HOST_SCOPE, dumps, loads, new_id

_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
LIVE_STATES = ("present", "quarantined", "missing")
LIST_LIMIT = 100
PACKAGE_DIR = Path(__file__).resolve().parents[1]


def _num(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


class StorageMixin(Base):
    # shutil.disk_usage by default; tests substitute a deterministic function per instance.
    _disk_usage: Callable[[str], Any] = staticmethod(shutil.disk_usage)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _operator_reasons(actor_row: dict, action: str) -> list[str]:
        if actor_row["kind"] in OPERATOR_KINDS:
            return []
        return [f"actor kind {actor_row['kind']} may not {action}; requires an operator kind {sorted(OPERATOR_KINDS)}"]

    def _root(self, name: str) -> dict:
        row = self.store.one("SELECT * FROM storage_roots WHERE name=?", (name,))
        if not row:
            raise ValueError(f"unknown storage root {name!r}")
        return dict(row)

    @staticmethod
    def _root_real(root: dict) -> str:
        sfs.check_root(root["path"], root["st_dev"], root["st_ino"])
        return root["path"]

    def _quarantine_root(self) -> dict | None:
        row = self.store.one("SELECT * FROM storage_roots WHERE role='quarantine'")
        return dict(row) if row else None

    def _artifact_row(self, cid: str, artifact_id: str) -> dict:
        art = self.get_artifact(artifact_id)
        if art["campaign_id"] != cid:
            raise ValueError(f"artifact {artifact_id} does not belong to campaign {cid}")
        return art

    @staticmethod
    def _art_head(art: dict) -> dict:
        return {"artifact_id": art["id"], "root": art["root_name"], "rel_path": art["rel_path"], "sha256": art["sha256"],
                "size_bytes": art["size_bytes"], "retention_class": art["retention_class"], "kind": art["kind"]}

    def _links(self, cid: str, *, job_id: str | None, image_id: str | None, member_sha256: str | None,
               code_unit_id: str | None, finding_id: str | None, run_id: str | None) -> dict:
        member = normalize_sha256(member_sha256) if member_sha256 else None
        if member_sha256 and not member:
            raise ValueError(f"artifact member_sha256 must be 64-hex: {member_sha256!r}")
        out: dict[str, str | None] = {}
        for name, ref, sql in (("job_id", job_id, "SELECT 1 FROM jobs WHERE id=? AND campaign_id=?"),
                               ("image_id", image_id, "SELECT 1 FROM images WHERE id=? AND campaign_id=?"),
                               ("member_sha256", member, "SELECT 1 FROM members WHERE sha256=? AND campaign_id=?"),
                               ("code_unit_id", code_unit_id, "SELECT 1 FROM code_units WHERE id=? AND campaign_id=?"),
                               ("finding_id", finding_id, "SELECT 1 FROM findings WHERE id=? AND campaign_id=?"),
                               ("run_id", run_id, "SELECT 1 FROM run_manifests WHERE run_id=? AND campaign_id=?")):
            if ref and not self.store.one(sql, (ref, cid)):
                raise ValueError(f"artifact {name} link {ref} does not exist in campaign {cid}")
            out[name] = ref or None
        return out

    # ------------------------------------------------------------------ roots / thresholds (host scope)
    def configure_storage_root(self, name: str, path: str, *, role: str = "managed", actor: str) -> dict:
        """Configure a root. managed: may be mutated by cleanup; retained: registration only, never mutated;
        quarantine: receives atomic renames (exactly one). Roots are immutable once configured."""
        actor_row = self.actor(actor)
        if not isinstance(name, str) or not _NAME.match(name):
            raise ValueError("storage root name must match [a-z0-9][a-z0-9_-]{0,63}")
        if role not in ROOT_ROLES:
            raise ValueError(f"storage root role must be one of {sorted(ROOT_ROLES)}")
        reasons = self._operator_reasons(actor_row, "configure storage roots")
        real, st = None, None
        try:
            real, st = sfs.canonical_root(path)
        except sfs.UnsafePathError as exc:
            reasons.append(f"unsafe root: {exc}")
        if real:
            real_path = Path(real)
            db = self.store.path.resolve()
            if real_path == Path(real_path.anchor) or real_path == Path.home().resolve():
                reasons.append("a filesystem root or home directory cannot be a storage root")
            if db.is_relative_to(real_path):
                reasons.append("storage root contains the canonical state database")
            protected = [PACKAGE_DIR] + ([PACKAGE_DIR.parent] if (PACKAGE_DIR.parent / ".git").exists() else [])
            if any(real_path.is_relative_to(p) or p.is_relative_to(real_path) for p in protected):
                reasons.append("storage root overlaps the REFALL Lite source tree / repository")
            existing = self.store.one("SELECT * FROM storage_roots WHERE name=?", (name,))
            if existing and (existing["path"], existing["role"]) == (real, role):
                return {"accepted": True, "outcome": "unchanged", "reasons": [], "root": dict(existing)}
            if existing:
                reasons.append(f"storage root {name} is already configured; roots are immutable")
            for other in self.store.all("SELECT name,path FROM storage_roots WHERE name!=?", (name,)):
                op = Path(other["path"])
                if real_path.is_relative_to(op) or op.is_relative_to(real_path):
                    reasons.append(f"storage root overlaps configured root {other['name']}")
            if role == "quarantine" and self.store.one("SELECT 1 FROM storage_roots WHERE role='quarantine' AND name!=?", (name,)):
                reasons.append("a quarantine root is already configured")
        head = {"name": name, "role": role, "path": real or "[unresolved]"}
        with self.store.tx():
            if reasons:
                self._ledger(HOST_SCOPE, "storage", "config_refused", actor, **head, reasons=reasons)
                return {"accepted": False, "outcome": "refused", "reasons": reasons, "root": None}
            assert st is not None
            self.store.conn.execute(
                "INSERT INTO storage_roots(name,role,path,st_dev,st_ino,configured_by,created_at) VALUES(?,?,?,?,?,?,?)",
                (name, role, real, st.st_dev, st.st_ino, actor, self.store.now()))
            self._ledger(HOST_SCOPE, "storage", "root_configure", actor, **head, st_dev=st.st_dev, st_ino=st.st_ino)
        return {"accepted": True, "outcome": "created", "reasons": [], "root": self._root(name)}

    def list_storage_roots(self) -> list[dict]:
        return [dict(r) for r in self.store.all("SELECT * FROM storage_roots ORDER BY name")]

    def storage_thresholds(self) -> dict:
        row = self.store.one("SELECT value FROM storage_config WHERE key='thresholds'")
        return evaluate_thresholds(loads(row["value"], {}) if row else {})

    def configure_storage_thresholds(self, *, actor: str, thresholds: dict) -> dict:
        actor_row = self.actor(actor)
        clean = evaluate_thresholds(thresholds)
        reasons = self._operator_reasons(actor_row, "configure disk-pressure thresholds")
        with self.store.tx():
            if reasons:
                self._ledger(HOST_SCOPE, "storage", "config_refused", actor, setting="thresholds", reasons=reasons)
                return {"accepted": False, "reasons": reasons, "thresholds": self.storage_thresholds()}
            self.store.conn.execute(
                "INSERT INTO storage_config(key,value,updated_by,updated_at) VALUES('thresholds',?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_by=excluded.updated_by, updated_at=excluded.updated_at",
                (dumps(clean), actor, self.store.now()))
            self._ledger(HOST_SCOPE, "storage", "thresholds_configure", actor, thresholds=clean)
        return {"accepted": True, "reasons": [], "thresholds": clean}

    # ------------------------------------------------------------------ registry
    def get_artifact(self, artifact_id: str) -> dict:
        row = self.store.one("SELECT * FROM artifacts WHERE id=?", (artifact_id,))
        if not row:
            raise KeyError(f"unknown artifact: {artifact_id}")
        data = dict(row)
        data["pinned"] = bool(data["pinned"])
        for key, default in (("snapshot", {}), ("producer", None), ("rebuild_missing", []), ("labels", None), ("tombstone", None)):
            data[key] = loads(data[key], default)
        data["references"] = [dict(r) for r in self.store.all(
            "SELECT id,ref_type,ref_id,reason,created_by,created_at FROM artifact_refs WHERE artifact_id=? AND released_at IS NULL "
            "ORDER BY created_at, id", (artifact_id,))]
        data["holds"] = [dict(r) for r in self.store.all(
            "SELECT id,kind,holder,reason,job_id,expires_at,created_at FROM artifact_holds WHERE artifact_id=? AND released_at IS NULL "
            "ORDER BY created_at, id", (artifact_id,))]
        return data

    def list_artifacts(self, cid: str, *, state: str | None = None, retention_class: str | None = None) -> list[dict]:
        self.get_campaign(cid)
        sql, args = "SELECT id FROM artifacts WHERE campaign_id=?", [cid]
        if state:
            sql += " AND state=?"
            args.append(state)
        if retention_class:
            sql += " AND retention_class=?"
            args.append(retention_class)
        return [self.get_artifact(r["id"]) for r in self.store.all(sql + " ORDER BY created_at, id", tuple(args))]

    @staticmethod
    def _labels(labels: object) -> tuple[dict | None, list[str]]:
        if labels in (None, {}):
            return None, []
        if not isinstance(labels, dict) or len(labels) > LABELS_MAX:
            return None, [f"labels must be an object of at most {LABELS_MAX} entries"]
        reasons = []
        for k, v in labels.items():
            if not isinstance(k, str) or not _NAME.match(k):
                reasons.append("label keys must match [a-z0-9][a-z0-9_-]{0,63}")
            else:
                reasons += storage_ref_reasons(v, f"labels.{k}", 200)
        return (None if reasons else dict(labels)), reasons

    def register_artifact(self, cid: str, *, actor: str, root: str, path: str, kind: str, retention_class: str,
                          media_type: str | None = None, sha256: str | None = None, producer: dict | None = None,
                          job_id: str | None = None, image_id: str | None = None, member_sha256: str | None = None,
                          code_unit_id: str | None = None, finding_id: str | None = None, run_id: str | None = None,
                          expires_at: float | None = None, labels: dict | None = None) -> dict:
        """Register (hash + snapshot) a file or directory under a configured root.

        Returns {accepted, outcome: created|deduplicated|refused, reasons, artifact, content_duplicates}."""
        actor_row = self.actor(actor)
        self.get_campaign(cid)
        if kind not in ARTIFACT_KINDS:
            raise ValueError(f"artifact kind must be one of {sorted(ARTIFACT_KINDS)}")
        if retention_class not in ARTIFACT_CLASSES:
            raise ValueError(f"retention_class must be one of {list(ARTIFACT_CLASSES)}")
        root_row = self._root(root)
        links = self._links(cid, job_id=job_id, image_id=image_id, member_sha256=member_sha256,
                            code_unit_id=code_unit_id, finding_id=finding_id, run_id=run_id)
        if expires_at is not None and not _num(expires_at):
            raise ValueError("expires_at must be an epoch timestamp")
        reasons = self._operator_reasons(actor_row, "register artifacts")
        path_reasons = storage_ref_reasons(path, "path", 1024)
        reasons += path_reasons
        head = {"root": root, "rel_path": None if path_reasons else path, "kind": kind, "retention_class": retention_class}
        if root_row["role"] == "quarantine":
            reasons.append("artifacts cannot be registered inside the quarantine root")
        minimum = ARTIFACT_KIND_MIN_CLASS[kind]
        if CLASS_RANK[retention_class] < CLASS_RANK[minimum]:
            reasons.append(f"kind {kind} must be registered as {minimum} or stronger, not {retention_class}")
        prov, prov_reasons, missing = evaluate_provenance(producer)
        reasons += prov_reasons
        if prov.get("actor") and not self.store.one("SELECT 1 FROM actors WHERE id=?", (prov["actor"],)):
            reasons.append("producer.actor is not a registered actor")
        for item in prov.get("inputs", []):
            if item.get("artifact_id") and not self.store.one("SELECT 1 FROM artifacts WHERE id=? AND campaign_id=?",
                                                              (item["artifact_id"], cid)):
                reasons.append("producer.inputs artifact_id must name an artifact in this campaign")
        clean_labels, label_reasons = self._labels(labels)
        reasons += label_reasons
        if media_type is not None:
            reasons += storage_ref_reasons(media_type, "media_type", 120)
        expected = None
        if sha256 is not None:
            expected = normalize_sha256(sha256)
            if not expected:
                reasons.append("sha256 must be 64 lowercase hex")
        snap: dict = {}
        rel = ""
        if not reasons:
            try:
                rel = sfs.normalize_rel(path)
                snap = sfs.snapshot(sfs.resolve(self._root_real(root_row), rel), hash_limit=None)
            except sfs.UnsafePathError as exc:
                reasons.append(f"unsafe path: {exc}")
            else:
                if expected and snap["sha256"] != expected:
                    reasons.append("sha256 mismatch: content does not match the expected digest")
        if reasons:
            with self.store.tx():
                self._ledger(cid, "storage", "register_refused", actor, **head, reasons=reasons)
            return {"accepted": False, "outcome": "refused", "reasons": reasons, "artifact": None, "content_duplicates": []}
        now = self.store.now()
        with self.store.tx():
            live = self.store.one(f"SELECT id FROM artifacts WHERE campaign_id=? AND root_name=? AND rel_path=? AND state IN "
                                  f"({','.join('?' * len(LIVE_STATES))})", (cid, root, rel, *LIVE_STATES))
            if live:
                existing = self.get_artifact(live["id"])
                if existing["state"] == "present" and existing["sha256"] == snap["sha256"]:
                    self.store.conn.execute(
                        "UPDATE artifacts SET snapshot=?, st_dev=?, st_ino=?, last_access_at=?, updated_at=? WHERE id=?",
                        (dumps(snap), snap["dev"], snap["ino"], now, now, existing["id"]))
                    self._ledger(cid, "storage", "dedup", actor, **self._art_head(existing))
                    return {"accepted": True, "outcome": "deduplicated", "reasons": [], "content_duplicates": [],
                            "artifact": self.get_artifact(existing["id"])}
                why = [f"location already registered as {existing['id']} ({existing['state']}) with different content or state; "
                       "plan/purge or restore it first"]
                self._ledger(cid, "storage", "register_refused", actor, **head, existing_artifact_id=existing["id"], reasons=why)
                return {"accepted": False, "outcome": "refused", "reasons": why, "artifact": existing, "content_duplicates": []}
            twins = [r["id"] for r in self.store.all(
                f"SELECT id FROM artifacts WHERE campaign_id=? AND sha256=? AND state IN ({','.join('?' * len(LIVE_STATES))}) "
                "ORDER BY created_at, id", (cid, snap["sha256"], *LIVE_STATES))]
            shared = self.store.scalar(
                f"SELECT COUNT(*) FROM artifacts WHERE campaign_id!=? AND root_name=? AND rel_path=? AND state IN "
                f"({','.join('?' * len(LIVE_STATES))})", (cid, root, rel, *LIVE_STATES))
            art_id = new_id("art")
            self.store.conn.execute(
                "INSERT INTO artifacts(id,campaign_id,root_name,rel_path,kind,media_type,retention_class,object_type,sha256,"
                "size_bytes,reclaim_bytes,st_dev,st_ino,snapshot,job_id,image_id,member_sha256,code_unit_id,finding_id,run_id,"
                "producer,rebuild_missing,labels,expires_at,last_access_at,state,registered_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'present',?,?,?)",
                (art_id, cid, root, rel, kind, media_type, retention_class, snap["type"], snap["sha256"], snap["size"],
                 snap["reclaim_bytes"], snap["dev"], snap["ino"], dumps(snap), links["job_id"], links["image_id"],
                 links["member_sha256"], links["code_unit_id"], links["finding_id"], links["run_id"],
                 dumps(prov) if prov else None, dumps(missing), dumps(clean_labels) if clean_labels else None,
                 float(expires_at) if expires_at is not None else None, now, actor, now, now))
            art = self.get_artifact(art_id)
            self._ledger(cid, "storage", "register", actor, **self._art_head(art), object_type=snap["type"],
                         producer=prov or None, rebuild_missing=missing, content_duplicates=twins,
                         shared_location_registrations=shared, **{k: v for k, v in links.items() if v})
        return {"accepted": True, "outcome": "created", "reasons": [], "artifact": art, "content_duplicates": twins}

    def reference_artifact(self, cid: str, artifact_id: str, *, actor: str, ref_type: str, ref_id: str, reason: str) -> dict:
        """Record that something depends on an artifact; an active reference blocks cleanup."""
        actor_row = self.actor(actor)
        art = self._artifact_row(cid, artifact_id)
        if ref_type not in REF_TYPES:
            raise ValueError(f"ref_type must be one of {sorted(REF_TYPES)}")
        ref_id, reason = storage_text(ref_id, "ref_id", 300), storage_text(reason, "reason")
        target_sql = {"finding": "SELECT 1 FROM findings WHERE id=? AND campaign_id=?",
                      "job": "SELECT 1 FROM jobs WHERE id=? AND campaign_id=?",
                      "artifact": "SELECT 1 FROM artifacts WHERE id=? AND campaign_id=?",
                      "run": "SELECT 1 FROM run_manifests WHERE run_id=? AND campaign_id=?"}.get(ref_type)
        if target_sql and not self.store.one(target_sql, (ref_id, cid)):
            raise ValueError(f"reference target {ref_type}:{ref_id} does not exist in campaign {cid}")
        reasons = self._operator_reasons(actor_row, "reference artifacts")
        if art["state"] == "purged":
            reasons.append("artifact body is purged; only its tombstone remains")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "storage", "action_refused", actor, operation="reference", **self._art_head(art), reasons=reasons)
                return {"accepted": False, "reasons": reasons, "reference": None}
            ref = new_id("aref")
            now = self.store.now()
            self.store.conn.execute(
                "INSERT INTO artifact_refs(id,campaign_id,artifact_id,ref_type,ref_id,reason,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (ref, cid, artifact_id, ref_type, ref_id, reason, actor, now))
            self.store.conn.execute("UPDATE artifacts SET last_access_at=?, updated_at=? WHERE id=?", (now, now, artifact_id))
            self._ledger(cid, "storage", "reference", actor, **self._art_head(art), reference_id=ref, ref_type=ref_type,
                         ref_id=ref_id, reason=reason)
        return {"accepted": True, "reasons": [], "reference": ref, "artifact": self.get_artifact(artifact_id)}

    def hold_artifact(self, cid: str, artifact_id: str, *, actor: str, kind: str, reason: str,
                      expires_at: float | None = None, job_id: str | None = None) -> dict:
        """Lease (expiring, for active work) or hold (until released). Either blocks cleanup while active."""
        actor_row = self.actor(actor)
        art = self._artifact_row(cid, artifact_id)
        if kind not in HOLD_KINDS:
            raise ValueError(f"hold kind must be one of {sorted(HOLD_KINDS)}")
        reason = storage_text(reason, "reason")
        now = self.store.now()
        if expires_at is not None and not _num(expires_at):
            raise ValueError("expires_at must be an epoch timestamp")
        if kind == "lease" and (expires_at is None or float(expires_at) <= now):
            raise ValueError("a lease requires a future expires_at")
        if job_id and not self.store.one("SELECT 1 FROM jobs WHERE id=? AND campaign_id=?", (job_id, cid)):
            raise ValueError(f"job {job_id} does not exist in campaign {cid}")
        reasons = self._operator_reasons(actor_row, "hold or lease artifacts")
        if art["state"] == "purged":
            reasons.append("artifact body is purged; only its tombstone remains")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "storage", "action_refused", actor, operation=kind, **self._art_head(art), reasons=reasons)
                return {"accepted": False, "reasons": reasons, "hold": None}
            hold = new_id("ahold")
            self.store.conn.execute(
                "INSERT INTO artifact_holds(id,campaign_id,artifact_id,kind,holder,reason,job_id,expires_at,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)", (hold, cid, artifact_id, kind, actor, reason, job_id,
                                              float(expires_at) if expires_at is not None else None, now))
            self.store.conn.execute("UPDATE artifacts SET last_access_at=?, updated_at=? WHERE id=?", (now, now, artifact_id))
            self._ledger(cid, "storage", "hold", actor, **self._art_head(art), hold_id=hold, hold_kind=kind, reason=reason,
                         expires_at=expires_at, job_id=job_id)
        return {"accepted": True, "reasons": [], "hold": hold, "artifact": self.get_artifact(artifact_id)}

    def release_artifact(self, cid: str, *, actor: str, reason: str, hold_id: str | None = None,
                         reference_id: str | None = None) -> dict:
        """Release exactly one hold/lease or reference."""
        actor_row = self.actor(actor)
        if bool(hold_id) == bool(reference_id):
            raise ValueError("release exactly one of hold_id or reference_id")
        reason = storage_text(reason, "reason")
        table, ident = ("artifact_holds", hold_id) if hold_id else ("artifact_refs", reference_id)
        row = self.store.one(f"SELECT * FROM {table} WHERE id=? AND campaign_id=?", (ident, cid))
        if not row:
            raise ValueError(f"{'hold' if hold_id else 'reference'} {ident} does not exist in campaign {cid}")
        art = self.get_artifact(row["artifact_id"])
        reasons = self._operator_reasons(actor_row, "release artifact holds or references")
        if row["released_at"] is not None:
            reasons.append("already released")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "storage", "action_refused", actor, operation="release", **self._art_head(art),
                             released_id=ident, reasons=reasons)
                return {"accepted": False, "reasons": reasons}
            now = self.store.now()
            self.store.conn.execute(f"UPDATE {table} SET released_at=?, released_by=? WHERE id=?", (now, actor, ident))
            self._ledger(cid, "storage", "release", actor, **self._art_head(art), released_id=ident,
                         released_kind="hold" if hold_id else "reference", reason=reason)
        return {"accepted": True, "reasons": [], "artifact": self.get_artifact(art["id"])}

    def pin_artifact(self, cid: str, artifact_id: str, *, actor: str, reason: str, pinned: bool = True) -> dict:
        actor_row = self.actor(actor)
        art = self._artifact_row(cid, artifact_id)
        reason = storage_text(reason, "reason")
        reasons = self._operator_reasons(actor_row, "pin artifacts")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "storage", "action_refused", actor, operation="pin", **self._art_head(art), reasons=reasons)
                return {"accepted": False, "reasons": reasons, "artifact": art}
            self.store.conn.execute("UPDATE artifacts SET pinned=?, pin_reason=?, updated_at=? WHERE id=?",
                                    (int(bool(pinned)), reason if pinned else None, self.store.now(), artifact_id))
            self._ledger(cid, "storage", "pin", actor, **self._art_head(art), pinned=bool(pinned), reason=reason)
        return {"accepted": True, "reasons": [], "artifact": self.get_artifact(artifact_id)}

    def set_job_storage_intent(self, cid: str, job_id: str, *, actor: str, intent: str, reason: str,
                               estimated_bytes: int | None = None) -> dict:
        """Explicit, durable storage-intent contract: only `heavy` jobs are paused under disk pressure."""
        actor_row = self.actor(actor)
        job = self.get_job(job_id)
        if job["campaign_id"] != cid:
            raise ValueError("job does not belong to campaign")
        if intent not in STORAGE_INTENTS:
            raise ValueError(f"storage intent must be one of {sorted(STORAGE_INTENTS)}")
        if estimated_bytes is not None and (not isinstance(estimated_bytes, int) or isinstance(estimated_bytes, bool) or estimated_bytes < 0):
            raise ValueError("estimated_bytes must be a non-negative integer")
        reason = storage_text(reason, "reason")
        reasons = self._operator_reasons(actor_row, "declare job storage intent")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "storage", "action_refused", actor, operation="intent", job_id=job_id, reasons=reasons)
                return {"accepted": False, "reasons": reasons}
            now = self.store.now()
            self.store.conn.execute(
                "INSERT INTO job_storage_intents(job_id,campaign_id,intent,estimated_bytes,reason,declared_by,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET intent=excluded.intent, estimated_bytes=excluded.estimated_bytes, "
                "reason=excluded.reason, declared_by=excluded.declared_by, updated_at=excluded.updated_at",
                (job_id, cid, intent, estimated_bytes, reason, actor, now, now))
            self._ledger(cid, "storage", "intent", actor, job_id=job_id, intent=intent, estimated_bytes=estimated_bytes, reason=reason)
        return {"accepted": True, "reasons": [], "job_id": job_id, "intent": intent, "estimated_bytes": estimated_bytes}

    # ------------------------------------------------------------------ eligibility
    def _nested(self, art: dict) -> tuple[list[dict], list[dict]]:
        """(live registrations of enclosing directories, live registrations contained in this directory) in the same
        root, across campaigns. A nested registration is cleaned only together with its enclosing directory."""
        live = ",".join("?" * len(LIVE_STATES))
        parts = art["rel_path"].split("/")
        prefixes = ["/".join(parts[:i]) for i in range(1, len(parts))]
        outer = [dict(r) for r in self.store.all(
            f"SELECT id, campaign_id FROM artifacts WHERE root_name=? AND state IN ({live}) AND object_type='dir' "
            f"AND rel_path IN ({','.join('?' * len(prefixes)) or 'NULL'})", (art["root_name"], *LIVE_STATES, *prefixes))]
        inner = [] if art["object_type"] != "dir" else [dict(r) for r in self.store.all(
            f"SELECT id, campaign_id FROM artifacts WHERE root_name=? AND state IN ({live}) AND id!=? "
            "AND substr(rel_path, 1, ?) = ?", (art["root_name"], *LIVE_STATES, art["id"], len(art["rel_path"]) + 1,
                                               art["rel_path"] + "/"))]
        return outer, inner

    def _protections(self, art: dict, now: float, *, nested: bool = True) -> list[str]:
        """Reasons an artifact must not be cleaned regardless of policy (empty = no standing protection)."""
        reasons = []
        if nested:
            outer, inner = self._nested(art)
            if outer:
                reasons.append(f"contained in registered directory artifact {outer[0]['id']} (cleaned only with it)")
            for c in inner:
                if c["campaign_id"] != art["campaign_id"]:
                    reasons.append("contains a registration of another campaign")
                    break
                if self._protections(self.get_artifact(c["id"]), now, nested=False):
                    reasons.append(f"contains protected artifact {c['id']}")
                    break
        if art["retention_class"] in PROTECTED_CLASSES:
            reasons.append(f"class {art['retention_class']} is protected; never cleaned")
        root = self.store.one("SELECT role FROM storage_roots WHERE name=?", (art["root_name"],))
        if not root or root["role"] != "managed":
            reasons.append(f"root {art['root_name']} is not a managed root")
        if art["pinned"]:
            reasons.append("pinned")
        if art["references"]:
            reasons.append("referenced by " + ", ".join(sorted({f"{r['ref_type']}:{r['ref_id']}" for r in art["references"]})[:5]))
        active = [h for h in art["holds"] if h["expires_at"] is None or h["expires_at"] > now]
        if active:
            reasons.append("active " + ", ".join(sorted({h["kind"] for h in active})))
        cid = art["campaign_id"]
        if art["finding_id"]:
            camp = self.get_campaign(cid)
            material = {s.lower() for s in camp["config"].get("material_severities") or []}
            f = self.store.one("SELECT tier, severity FROM findings WHERE id=?", (art["finding_id"],))
            if f and (f["tier"] == "validated" or f["severity"] in material):
                reasons.append(f"required by {'validated' if f['tier'] == 'validated' else 'material'} finding {art['finding_id']}")
        if art["job_id"]:
            status = self.store.scalar("SELECT status FROM jobs WHERE id=?", (art["job_id"],))
            if status in JOB_UNRESOLVED:
                reasons.append(f"linked job {art['job_id']} is {status}")
        consumers = [r["id"] for r in self.store.all(
            "SELECT id, producer FROM artifacts WHERE campaign_id=? AND id!=? AND state IN ('present','quarantined') "
            "AND producer IS NOT NULL", (cid, art["id"]))
            if any(i.get("artifact_id") == art["id"] or i.get("sha256") == art["sha256"]
                   for i in (loads(r["producer"], {}) or {}).get("inputs", []))]
        if consumers:
            reasons.append(f"rebuild input of live artifact(s) {', '.join(consumers[:5])}")
        shared = self.store.scalar(
            "SELECT COUNT(*) FROM artifacts WHERE campaign_id!=? AND root_name=? AND rel_path=? AND state IN ('present','quarantined','missing')",
            (cid, art["root_name"], art["rel_path"]))
        if shared:
            reasons.append("location is also registered by another campaign")
        return reasons

    def _eligibility(self, art: dict, policy: dict, now: float) -> list[str]:
        if art["state"] != "present":
            return [f"state {art['state']}"]
        reasons = self._protections(art, now)
        if art["retention_class"] not in policy["classes"] and art["retention_class"] not in PROTECTED_CLASSES:
            reasons.append(f"class {art['retention_class']} not requested by policy")
        if art["retention_class"] == "regenerable":
            if art["rebuild_missing"]:
                reasons.append(f"incomplete rebuild provenance: missing {', '.join(art['rebuild_missing'])}")
            for item in (art["producer"] or {}).get("inputs", []):
                if item.get("artifact_id"):
                    state = self.store.scalar("SELECT state FROM artifacts WHERE id=?", (item["artifact_id"],))
                    if state != "present":
                        reasons.append(f"rebuild input {item['artifact_id']} is {state}")
        if art["expires_at"] is not None:
            if now < art["expires_at"]:
                reasons.append(f"retained until expires_at {art['expires_at']}")
        elif art["retention_class"] in policy["min_age_s"]:
            evidence = art["finding_id"] or self.store.scalar(
                "SELECT COUNT(*) FROM artifact_refs WHERE artifact_id=? AND ref_type IN ('finding','replay')", (art["id"],))
            minimum = policy["evidence_diagnostic_min_age_s"] if art["retention_class"] == "diagnostic" and evidence \
                else policy["min_age_s"][art["retention_class"]]
            idle = now - max(art["created_at"] or 0, art["last_access_at"] or 0)
            if idle < minimum:
                reasons.append(f"younger than minimum age {minimum}s (idle {int(idle)}s)")
        return reasons

    @staticmethod
    def _category(reason: str) -> str:
        return re.sub(r"[^a-z_ ]", "", reason.split(" by ")[0].split(":")[0].split(" (")[0].lower()).strip()[:60]

    def _fs_check(self, art: dict, expected: dict, hash_limit: int) -> tuple[Path | None, dict, list[str]]:
        """Re-resolve + re-snapshot a target. Any unsafe path or drift is a refusal (the target is never deleted)."""
        try:
            root = self._root(art["root_name"])
            if root["role"] != "managed":
                return None, {}, [f"root {art['root_name']} is not a managed root"]
            path = sfs.resolve(self._root_real(root), art["rel_path"])
            snap = sfs.snapshot(path, hash_limit=hash_limit)
        except sfs.UnsafePathError as exc:
            return None, {}, [f"unsafe or missing target: {exc}"]
        changed = sfs.drift(expected, snap)
        if changed:
            return path, snap, [f"target drifted ({', '.join(changed)}); refused, not deleted"]
        return path, snap, []

    # ------------------------------------------------------------------ inventory / plan
    def storage_inventory(self, cid: str | None = None) -> dict:
        """Logical and physical bytes by campaign/class/state/root (read-only, from the registry)."""
        sql, args = "SELECT * FROM artifacts", ()
        if cid:
            self.get_campaign(cid)
            sql, args = sql + " WHERE campaign_id=?", (cid,)
        groups: dict[tuple, dict] = {}
        physical: set[tuple] = set()
        totals = {"artifacts": 0, "logical_bytes": 0, "physical_bytes": 0, "present_bytes": 0, "quarantined_bytes": 0,
                  "purged_bytes": 0, "tombstones": 0}
        for r in self.store.all(sql + " ORDER BY created_at, id", args):
            key = (r["campaign_id"], r["retention_class"], r["state"], r["root_name"])
            g = groups.setdefault(key, {"campaign_id": key[0], "retention_class": key[1], "state": key[2], "root": key[3],
                                        "artifacts": 0, "logical_bytes": 0, "physical_bytes": 0})
            g["artifacts"] += 1
            totals["artifacts"] += 1
            if r["state"] == "purged":
                totals["tombstones"] += 1
                totals["purged_bytes"] += r["reclaim_bytes"]
                continue
            g["logical_bytes"] += r["size_bytes"]
            totals["logical_bytes"] += r["size_bytes"]
            if r["state"] == "present":
                totals["present_bytes"] += r["size_bytes"]
            elif r["state"] == "quarantined":
                totals["quarantined_bytes"] += r["size_bytes"]
            ident = (r["st_dev"], r["st_ino"])
            if ident not in physical:  # hard links / one inode registered twice count once
                physical.add(ident)
                g["physical_bytes"] += r["size_bytes"]
                totals["physical_bytes"] += r["size_bytes"]
        return {"campaign_id": cid, "totals": totals, "groups": sorted(groups.values(), key=lambda g: (
            g["campaign_id"], CLASS_RANK[g["retention_class"]], g["state"], g["root"]))}

    @staticmethod
    def _plan_hash(cid: str, policy: dict, candidates: list[dict]) -> str:
        return sha256_text(canonical_json({"campaign_id": cid, "policy": policy, "candidates": candidates}))

    def get_cleanup_plan(self, plan_id: str) -> dict:
        row = self.store.one("SELECT * FROM cleanup_plans WHERE id=?", (plan_id,))
        if not row:
            raise KeyError(f"unknown cleanup plan: {plan_id}")
        data = dict(row)
        for key, default in (("policy", {}), ("refused_classes", []), ("candidates", []), ("exclusions", {}), ("result", None)):
            data[key] = loads(data[key], default)
        data["actions"] = [self._action(dict(a)) for a in self.store.all(
            "SELECT * FROM cleanup_actions WHERE plan_id=? ORDER BY seq", (plan_id,))]
        return data

    @staticmethod
    def _action(a: dict) -> dict:
        for key in ("planned_snapshot", "post_snapshot", "receipt"):
            a[key] = loads(a[key], None)
        return a

    def list_cleanup_plans(self, cid: str) -> list[dict]:
        self.get_campaign(cid)
        return [{k: p[k] for k in ("id", "status", "expected_reclaim_bytes", "created_by", "created_at", "applied_at")}
                | {"candidates": len(p["candidates"])}
                for p in (self.get_cleanup_plan(r["id"]) for r in self.store.all(
                    "SELECT id FROM cleanup_plans WHERE campaign_id=? ORDER BY created_at, id", (cid,)))]

    def _select_candidates(self, cid: str, policy: dict, now: float) -> tuple[list[dict], dict, int]:
        """Eligible candidates (DB protections + safe path + unchanged since registration), in deterministic order."""
        candidates: list[dict] = []
        excluded: dict[str, int] = {}
        examples: list[dict] = []
        reclaim, target = 0, policy["target_reclaim_bytes"]
        rows = self.store.all(
            "SELECT id FROM artifacts WHERE campaign_id=? AND state='present' ORDER BY created_at, id", (cid,))
        arts = sorted((self.get_artifact(r["id"]) for r in rows), key=lambda a: (CLASS_RANK[a["retention_class"]], a["created_at"], a["id"]))
        for art in arts:
            why = self._eligibility(art, policy, now)
            snap: dict = {}
            if not why:
                _, snap, why = self._fs_check(art, art["snapshot"], policy["hash_verify_max_bytes"])
                if why:
                    why = [w.replace("target drifted", "target drifted since registration") for w in why]
            if not why and (len(candidates) >= policy["max_candidates"] or (target is not None and reclaim >= target)):
                why = ["plan limit reached (max_candidates / target_reclaim_bytes)"]
            if why:
                for w in why:
                    excluded[self._category(w)] = excluded.get(self._category(w), 0) + 1
                if len(examples) < LIST_LIMIT:
                    examples.append({"artifact_id": art["id"], "retention_class": art["retention_class"], "reasons": why})
                continue
            candidates.append({"artifact_id": art["id"], "root": art["root_name"], "rel_path": art["rel_path"],
                               "retention_class": art["retention_class"], "kind": art["kind"], "sha256": art["sha256"],
                               "size_bytes": art["size_bytes"], "reclaim_bytes": snap["reclaim_bytes"], "snapshot": snap,
                               "contained": sorted(c["id"] for c in self._nested(art)[1])})
            reclaim += snap["reclaim_bytes"]
        return candidates, {"by_reason": dict(sorted(excluded.items())), "examples": examples, "considered": len(arts)}, reclaim

    def preview_cleanup(self, cid: str, *, policy: dict | None = None) -> dict:
        """Read-only planning preview: same selection as plan_cleanup, nothing persisted or ledgered."""
        self.get_campaign(cid)
        snapshot_policy, refused_classes = evaluate_cleanup_policy(policy)
        candidates, exclusions, reclaim = self._select_candidates(cid, snapshot_policy, self.store.now())
        return {"recorded": False, "policy": snapshot_policy, "refused_classes": refused_classes,
                "candidates": candidates, "exclusions": exclusions, "expected_reclaim_bytes": reclaim}

    def plan_cleanup(self, cid: str, *, actor: str, rationale: str, policy: dict | None = None) -> dict:
        """Build an immutable cleanup plan. No filesystem mutation; candidates are frozen with their snapshots."""
        actor_row = self.actor(actor)
        self.get_campaign(cid)
        rationale = storage_text(rationale, "rationale")
        snapshot_policy, refused_classes = evaluate_cleanup_policy(policy)
        reasons = self._operator_reasons(actor_row, "plan cleanup")
        if reasons:
            with self.store.tx():
                self._ledger(cid, "storage", "plan_refused", actor, reasons=reasons)
            return {"accepted": False, "reasons": reasons, "plan": None}
        now = self.store.now()
        candidates, exclusions, reclaim = self._select_candidates(cid, snapshot_policy, now)
        plan_id = new_id("cplan")
        digest = self._plan_hash(cid, snapshot_policy, candidates)
        with self.store.tx():
            self.store.conn.execute(
                "INSERT INTO cleanup_plans(id,campaign_id,status,rationale,policy,refused_classes,candidates,exclusions,"
                "expected_reclaim_bytes,plan_sha256,created_by,created_at) VALUES(?,?,'planned',?,?,?,?,?,?,?,?,?)",
                (plan_id, cid, rationale, dumps(snapshot_policy), dumps(refused_classes), dumps(candidates), dumps(exclusions),
                 reclaim, digest, actor, now))
            for seq, c in enumerate(candidates):
                self.store.conn.execute(
                    "INSERT INTO cleanup_actions(id,plan_id,campaign_id,artifact_id,seq,state,planned_snapshot,updated_at) "
                    "VALUES(?,?,?,?,?,'pending',?,?)", (new_id("cact"), plan_id, cid, c["artifact_id"], seq, dumps(c["snapshot"]), now))
            self._ledger(cid, "storage", "plan", actor, plan_id=plan_id, plan_sha256=digest, candidates=len(candidates),
                         expected_reclaim_bytes=reclaim, refused_classes=refused_classes, excluded=exclusions["by_reason"],
                         policy_sha256=sha256_text(canonical_json(snapshot_policy)), rationale=rationale)
        return {"accepted": True, "reasons": [], "plan": self.get_cleanup_plan(plan_id)}

    def _plan_for(self, cid: str, plan_id: str) -> dict:
        plan = self.get_cleanup_plan(plan_id)
        if plan["campaign_id"] != cid:
            raise ValueError("cleanup plan does not belong to campaign")
        return plan

    def validate_cleanup_plan(self, cid: str, plan_id: str) -> dict:
        """Dry run: re-check every pending candidate against current state and the filesystem. Never mutates."""
        plan = self._plan_for(cid, plan_id)
        now = self.store.now()
        intact = self._plan_hash(cid, plan["policy"], plan["candidates"]) == plan["plan_sha256"]
        items = []
        for a in plan["actions"]:
            art = self.get_artifact(a["artifact_id"])
            if a["state"] != "pending":
                items.append({"artifact_id": art["id"], "action_state": a["state"], "would": "no-op"})
                continue
            why = self._eligibility(art, plan["policy"], now)
            if not why:
                _, _, why = self._fs_check(art, a["planned_snapshot"], plan["policy"]["hash_verify_max_bytes"])
            items.append({"artifact_id": art["id"], "action_state": "pending", "would": "refuse" if why else "quarantine",
                          "reasons": why, "reclaim_bytes": art["reclaim_bytes"]})
        quarantine = [i for i in items if i["would"] == "quarantine"]
        return {"plan_id": plan_id, "status": plan["status"], "plan_sha256_ok": intact, "dry_run": True,
                "would_quarantine": len(quarantine), "would_refuse": sum(i["would"] == "refuse" for i in items),
                "would_reclaim_bytes_on_purge": sum(i["reclaim_bytes"] for i in quarantine),
                "expected_reclaim_bytes": plan["expected_reclaim_bytes"], "items": items}

    # ------------------------------------------------------------------ apply (quarantine)
    def _contained_ids(self, plan: dict, artifact_id: str) -> list[str]:
        return next((c.get("contained", []) for c in plan["candidates"] if c["artifact_id"] == artifact_id), [])

    def _carry_contained(self, plan: dict, art: dict, state: str, *, tombstone: dict | None = None) -> None:
        """Nested registrations moved with their enclosing directory share its lifecycle state."""
        now = self.store.now()
        for cid_ in self._contained_ids(plan, art["id"]):
            if state == "purged":
                inner = self.get_artifact(cid_)
                tomb = {**(tombstone or {}), "sha256": inner["sha256"], "size_bytes": inner["size_bytes"],
                        "rel_path": inner["rel_path"], "contained_in": art["id"]}
                self.store.conn.execute("UPDATE artifacts SET state='purged', purged_at=?, tombstone=?, updated_at=? WHERE id=?",
                                        (now, dumps(tomb), now, cid_))
            else:
                self.store.conn.execute("UPDATE artifacts SET state=?, quarantined_at=?, updated_at=? WHERE id=?",
                                        (state, now if state == "quarantined" else None, now, cid_))

    def _q_paths(self, qroot: dict, action: dict, art: dict) -> tuple[str, Path]:
        rel = action["quarantine_rel"] or f"{art['campaign_id']}/{action['plan_id']}/{action['id']}"
        return rel, Path(qroot["path"], rel, Path(art["rel_path"]).name)

    def _claim_action(self, action_id: str, expected: str) -> bool:
        """Compare-and-set guard (inside a tx): only one apply/restore/purge may move an action out of ``expected``."""
        return self.store.scalar("SELECT state FROM cleanup_actions WHERE id=?", (action_id,)) == expected

    def _set_action(self, action_id: str, state: str, **cols: Any) -> None:
        sets = ", ".join(f"{k}=?" for k in cols)
        vals = [dumps(v) if isinstance(v, (dict, list)) else v for v in cols.values()]
        self.store.conn.execute(f"UPDATE cleanup_actions SET state=?, {sets + ', ' if sets else ''}updated_at=? WHERE id=?",
                                (state, *vals, self.store.now(), action_id))

    def _finalize_quarantine(self, cid: str, plan: dict, action: dict, art: dict, actor: str, dest: Path, post: dict,
                             source: str) -> None:
        now = self.store.now()
        receipt = {"summary": f"quarantined by atomic same-filesystem rename ({source})",
                   "evidence_refs": [f"artifact:{art['id']}", f"sha256:{art['sha256']}"],
                   "from": f"{art['root_name']}:{art['rel_path']}", "to": str(dest), "post_move_verified": True,
                   "hash_verified": bool(post.get("sha256")), "reclaim_bytes_on_purge": post.get("reclaim_bytes", 0)}
        with self.store.tx():
            self._set_action(action["id"], "quarantined", post_snapshot=post, receipt=receipt, reason=None)
            self.store.conn.execute("UPDATE artifacts SET state='quarantined', quarantined_at=?, updated_at=? WHERE id=?",
                                    (now, now, art["id"]))
            self._carry_contained(plan, art, "quarantined")
            self._ledger(cid, "storage", "quarantine", actor, **self._art_head(art), plan_id=plan["id"], action_id=action["id"],
                         quarantine_path=str(dest), receipt=receipt, contained=self._contained_ids(plan, art["id"]))

    def _refuse_action(self, cid: str, plan: dict, action: dict, art: dict, actor: str, reasons: list[str],
                       state: str = "refused", artifact_state: str | None = None) -> None:
        with self.store.tx():
            self._set_action(action["id"], state, reason="; ".join(reasons)[:2000])
            if artifact_state:
                self.store.conn.execute("UPDATE artifacts SET state=?, updated_at=? WHERE id=?",
                                        (artifact_state, self.store.now(), art["id"]))
            self._ledger(cid, "storage", "quarantine_refused", actor, **self._art_head(art), plan_id=plan["id"],
                         action_id=action["id"], action_state=state, reasons=reasons)

    def _recover_quarantine(self, cid: str, plan: dict, action: dict, art: dict, actor: str, qroot: dict) -> str:
        """Reconcile an interrupted quarantine from its durable intent row. Returns the action's new state."""
        _, dest = self._q_paths(qroot, action, art)
        try:
            src = sfs.resolve(self._root_real(self._root(art["root_name"])), art["rel_path"], must_exist=False)
        except sfs.UnsafePathError as exc:
            self._refuse_action(cid, plan, action, art, actor, [f"recovery: unsafe source path: {exc}"], state="anomaly")
            return "anomaly"
        src_there, dest_there = sfs.exists(src), sfs.exists(dest)
        if src_there and not dest_there:
            with self.store.tx():
                self._set_action(action["id"], "pending")
                self._ledger(cid, "storage", "recover", actor, **self._art_head(art), plan_id=plan["id"], action_id=action["id"],
                             decision="rename not performed before interruption; re-validating from pending")
            return "pending"
        if dest_there and not src_there:
            post = sfs.snapshot(dest, hash_limit=plan["policy"]["hash_verify_max_bytes"])
            changed = sfs.drift(action["planned_snapshot"], post)
            if changed:
                self._refuse_action(cid, plan, action, art, actor, [f"recovery: quarantined body differs from plan ({', '.join(changed)})"],
                                    state="anomaly", artifact_state="missing")
                return "anomaly"
            with self.store.tx():
                self._ledger(cid, "storage", "recover", actor, **self._art_head(art), plan_id=plan["id"], action_id=action["id"],
                             decision="rename completed before interruption; verified and finalized")
                self._finalize_quarantine(cid, plan, action, art, actor, dest, post, "recovered after interruption")
            return "quarantined"
        why = "both source and quarantine copy exist" if src_there else "neither source nor quarantine copy exists"
        self._refuse_action(cid, plan, action, art, actor, [f"recovery: {why}; left untouched for the operator"],
                            state="anomaly", artifact_state=None if src_there else "missing")
        return "anomaly"

    def _quarantine_one(self, cid: str, plan: dict, action: dict, actor: str, qroot: dict) -> str:
        art = self.get_artifact(action["artifact_id"])
        policy = plan["policy"]
        why = self._eligibility(art, policy, self.store.now())
        src: Path | None = None
        if not why:
            src, _, why = self._fs_check(art, action["planned_snapshot"], policy["hash_verify_max_bytes"])
        if why:
            self._refuse_action(cid, plan, action, art, actor, why)
            return "refused"
        assert src is not None
        rel, dest = self._q_paths(qroot, action, art)
        with self.store.tx():
            if not self._claim_action(action["id"], "pending"):  # another run already took this action
                return "skipped"
            self._set_action(action["id"], "intent", quarantine_rel=rel)
            self._ledger(cid, "storage", "quarantine_intent", actor, **self._art_head(art), plan_id=plan["id"], action_id=action["id"],
                         quarantine_rel=rel)
        action = {**action, "quarantine_rel": rel, "state": "intent"}
        try:
            qreal = self._root_real(qroot)
            slot_parent = sfs.ensure_dirs(qreal, str(Path(rel).parent))
            moved = sfs.move_into_fresh_dir(src, slot_parent / Path(rel).name, dest.name)
        except sfs.UnsafePathError as exc:
            self._refuse_action(cid, plan, action, art, actor, [f"move refused: {exc}"])
            return "refused"
        post = sfs.snapshot(moved, hash_limit=policy["hash_verify_max_bytes"])
        changed = sfs.drift(action["planned_snapshot"], post)
        if changed:  # swapped between check and rename: put it back, never keep or delete an unplanned body
            try:
                sfs.move_back(moved, src)
                self._refuse_action(cid, plan, action, art, actor, [f"post-move verification failed ({', '.join(changed)}); moved back"])
                return "refused"
            except sfs.UnsafePathError as exc:
                self._refuse_action(cid, plan, action, art, actor, [f"post-move verification failed and move-back refused: {exc}"],
                                    state="anomaly", artifact_state="missing")
                return "anomaly"
        self._finalize_quarantine(cid, plan, action, art, actor, moved, post, "apply")
        return "quarantined"

    def apply_cleanup_plan(self, cid: str, plan_id: str, *, actor: str, execute: bool = False) -> dict:
        """Dry run unless execute=True. Applies exactly the plan's frozen candidates (never more); rerunning resumes an
        interrupted apply from durable intent rows and is a no-op once the plan is finished."""
        actor_row = self.actor(actor)
        plan = self._plan_for(cid, plan_id)
        if not execute:
            return {"accepted": True, "executed": False, "validation": self.validate_cleanup_plan(cid, plan_id)}
        reasons = self._operator_reasons(actor_row, "apply cleanup plans")
        if self._plan_hash(cid, plan["policy"], plan["candidates"]) != plan["plan_sha256"]:
            reasons.append("plan content does not match its recorded plan_sha256 (tampered); refused")
        qroot = self._quarantine_root()
        if qroot is None:
            reasons.append("no quarantine root configured")
        else:
            try:
                self._root_real(qroot)
            except sfs.UnsafePathError as exc:
                reasons.append(f"quarantine root unusable: {exc}")
        if plan["status"] not in ("planned", "applying") and not reasons:
            return {"accepted": True, "executed": True, "idempotent": True, "plan": plan, "result": plan["result"]}
        if reasons:
            with self.store.tx():
                self._ledger(cid, "storage", "apply_refused", actor, plan_id=plan_id, reasons=reasons)
            return {"accepted": False, "executed": False, "reasons": reasons, "plan": plan}
        assert qroot is not None
        try:
            with sfs.mutation_lock(qroot["path"]):
                return self._apply_locked(cid, plan_id, plan, actor, qroot)
        except sfs.UnsafePathError as exc:
            if "storage lock" not in str(exc):
                raise
            with self.store.tx():
                self._ledger(cid, "storage", "apply_refused", actor, plan_id=plan_id, reasons=[str(exc)])
            return {"accepted": False, "executed": False, "reasons": [str(exc)], "plan": plan}

    def _apply_locked(self, cid: str, plan_id: str, plan: dict, actor: str, qroot: dict) -> dict:
        plan = self.get_cleanup_plan(plan_id)  # re-read under the lock
        if plan["status"] not in ("planned", "applying"):
            return {"accepted": True, "executed": True, "idempotent": True, "plan": plan, "result": plan["result"]}
        if plan["status"] == "planned":
            with self.store.tx():
                self.store.conn.execute("UPDATE cleanup_plans SET status='applying', applied_by=? WHERE id=?", (actor, plan_id))
                self._ledger(cid, "storage", "apply", actor, plan_id=plan_id, phase="start", candidates=len(plan["actions"]))
        for action in plan["actions"]:
            state = action["state"]
            if state == "intent":
                state = self._recover_quarantine(cid, plan, action, self.get_artifact(action["artifact_id"]), actor, qroot)
                action = {**action, "state": state}
            if state == "pending":
                self._quarantine_one(cid, plan, action, actor, qroot)
        plan = self.get_cleanup_plan(plan_id)
        done = [a for a in plan["actions"] if a["state"] in ("quarantined", "restored", "purge_intent", "purged")]
        bad = [a for a in plan["actions"] if a["state"] in ("refused", "anomaly")]
        status = "applied" if not bad else ("partial" if done else "refused")
        result = {"quarantined": len(done), "refused": len(bad),
                  "quarantined_bytes": sum((a["post_snapshot"] or {}).get("size", 0) for a in done),
                  "reclaim_bytes_on_purge": sum((a["post_snapshot"] or {}).get("reclaim_bytes", 0) for a in done),
                  "refusals": [{"artifact_id": a["artifact_id"], "state": a["state"], "reason": a["reason"]} for a in bad][:LIST_LIMIT]}
        with self.store.tx():
            self.store.conn.execute("UPDATE cleanup_plans SET status=?, applied_at=?, result=? WHERE id=?",
                                    (status, self.store.now(), dumps(result), plan_id))
            self._ledger(cid, "storage", "apply", actor, plan_id=plan_id, phase="finish", status=status, **result)
        return {"accepted": True, "executed": True, "idempotent": False, "plan": self.get_cleanup_plan(plan_id), "result": result}

    # ------------------------------------------------------------------ restore / purge
    def _quarantined_action(self, art: dict) -> dict | None:
        row = self.store.one("SELECT * FROM cleanup_actions WHERE artifact_id=? AND state IN ('quarantined','restore_intent','purge_intent') "
                             "ORDER BY updated_at DESC LIMIT 1", (art["id"],))
        return self._action(dict(row)) if row else None

    def restore_artifact(self, cid: str, artifact_id: str, *, actor: str, execute: bool = False) -> dict:
        """Move a quarantined artifact back to its original location (dry run unless execute=True)."""
        actor_row = self.actor(actor)
        art = self._artifact_row(cid, artifact_id)
        action = self._quarantined_action(art)
        qroot = self._quarantine_root()
        reasons = self._operator_reasons(actor_row, "restore artifacts")
        if not action or action["state"] == "purge_intent" or qroot is None:
            reasons.append(f"artifact is {art['state']}; only quarantined artifacts can be restored")
        src = dest = None
        plan: dict = {}
        root_real = ""
        if not reasons:
            assert action is not None and qroot is not None
            plan = self.get_cleanup_plan(action["plan_id"])
            _, src = self._q_paths(qroot, action, art)
            try:
                self._root_real(qroot)
                root_real = self._root_real(self._root(art["root_name"]))
                dest = sfs.resolve(root_real, art["rel_path"], must_exist=False)
            except sfs.UnsafePathError as exc:
                reasons.append(f"unsafe restore target: {exc}")
            if not reasons and action["state"] == "restore_intent":
                if sfs.exists(dest) and not sfs.exists(src):
                    post = sfs.snapshot(dest, hash_limit=plan["policy"]["hash_verify_max_bytes"])
                    return self._finish_restore(cid, plan, action, art, actor, post, "recovered after interruption", execute)
                if not (sfs.exists(src) and not sfs.exists(dest)):
                    reasons.append("restore interrupted with ambiguous filesystem state; left untouched for the operator")
            if not reasons:
                if sfs.exists(dest):
                    reasons.append("original location is occupied; refusing to overwrite")
                elif not sfs.exists(src):
                    reasons.append("quarantined body is missing")
                else:
                    changed = sfs.drift(action["post_snapshot"] or {}, sfs.snapshot(src, hash_limit=plan["policy"]["hash_verify_max_bytes"]))
                    if changed:
                        reasons.append(f"quarantined body drifted ({', '.join(changed)}); refused")
        if reasons:
            if execute:
                with self.store.tx():
                    self._ledger(cid, "storage", "restore_refused", actor, **self._art_head(art), reasons=reasons)
            return {"accepted": False, "executed": False, "reasons": reasons, "artifact": art}
        if not execute:
            return {"accepted": True, "executed": False, "would_restore_to": f"{art['root_name']}:{art['rel_path']}", "artifact": art}
        assert action is not None and src is not None and dest is not None and qroot is not None
        try:
            with sfs.mutation_lock(qroot["path"]):
                return self._restore_locked(cid, plan, action, art, actor, src, dest, root_real)
        except sfs.UnsafePathError as exc:
            if "storage lock" not in str(exc):
                raise
            with self.store.tx():
                self._ledger(cid, "storage", "restore_refused", actor, **self._art_head(art), reasons=[str(exc)])
            return {"accepted": False, "executed": False, "reasons": [str(exc)], "artifact": art}

    def _restore_locked(self, cid: str, plan: dict, action: dict, art: dict, actor: str, src: Path, dest: Path,
                        root_real: str) -> dict:
        artifact_id = art["id"]
        with self.store.tx():
            if not self._claim_action(action["id"], "quarantined"):
                return {"accepted": False, "executed": False, "reasons": ["restore already in progress or finished"],
                        "artifact": self.get_artifact(artifact_id)}
            self._set_action(action["id"], "restore_intent")
            self._ledger(cid, "storage", "restore", actor, **self._art_head(art), plan_id=action["plan_id"], phase="intent")
        try:
            parent = str(Path(art["rel_path"]).parent)
            if parent != ".":
                sfs.ensure_dirs(root_real, parent)
            sfs.move_back(src, dest)
        except sfs.UnsafePathError as exc:
            with self.store.tx():
                self._set_action(action["id"], "quarantined")
                self._ledger(cid, "storage", "restore_refused", actor, **self._art_head(art), reasons=[f"move refused: {exc}"])
            return {"accepted": False, "executed": False, "reasons": [f"move refused: {exc}"], "artifact": self.get_artifact(artifact_id)}
        post = sfs.snapshot(dest, hash_limit=plan["policy"]["hash_verify_max_bytes"])
        return self._finish_restore(cid, plan, action, art, actor, post, "restore", True)

    def _finish_restore(self, cid: str, plan: dict, action: dict, art: dict, actor: str, post: dict, source: str,
                        execute: bool) -> dict:
        if not execute:
            return {"accepted": True, "executed": False, "would_restore_to": "recovery: restore already moved the body back",
                    "artifact": art}
        changed = sfs.drift(action["post_snapshot"] or {}, post)
        receipt = {"summary": f"restored from quarantine ({source})", "evidence_refs": [f"artifact:{art['id']}"],
                   "post_move_verified": not changed, "drift": changed}
        with self.store.tx():
            self._set_action(action["id"], "restored", receipt={**(action["receipt"] or {}), "restore": receipt})
            self.store.conn.execute("UPDATE artifacts SET state='present', quarantined_at=NULL, snapshot=?, updated_at=? WHERE id=?",
                                    (dumps(post), self.store.now(), art["id"]))
            self._carry_contained(plan, art, "present")
            self._ledger(cid, "storage", "restore", actor, **self._art_head(art), plan_id=plan["id"], phase="done", receipt=receipt)
        return {"accepted": True, "executed": True, "reasons": [], "receipt": receipt, "artifact": self.get_artifact(art["id"])}

    def purge_cleanup_plan(self, cid: str, plan_id: str, *, actor: str, execute: bool = False) -> dict:
        """Permanently delete quarantined bodies of a plan whose quarantine retention has elapsed (dry run unless
        execute=True). Protections are re-checked; tombstones (hash/size/path/receipt) are kept forever."""
        actor_row = self.actor(actor)
        plan = self._plan_for(cid, plan_id)
        qroot = self._quarantine_root()
        reasons = self._operator_reasons(actor_row, "purge quarantined artifacts")
        if qroot is None:
            reasons.append("no quarantine root configured")
        if reasons:
            if execute:
                with self.store.tx():
                    self._ledger(cid, "storage", "purge_refused", actor, plan_id=plan_id, reasons=reasons)
            return {"accepted": False, "executed": False, "reasons": reasons}
        assert qroot is not None
        if not execute:
            return self._purge_pass(cid, plan, actor, qroot, execute=False)
        try:
            with sfs.mutation_lock(qroot["path"]):
                return self._purge_pass(cid, self.get_cleanup_plan(plan_id), actor, qroot, execute=True)
        except sfs.UnsafePathError as exc:
            if "storage lock" not in str(exc):
                raise
            with self.store.tx():
                self._ledger(cid, "storage", "purge_refused", actor, plan_id=plan_id, reasons=[str(exc)])
            return {"accepted": False, "executed": False, "reasons": [str(exc)]}

    def _purge_pass(self, cid: str, plan: dict, actor: str, qroot: dict, *, execute: bool) -> dict:
        plan_id = plan["id"]
        now = self.store.now()
        retention = plan["policy"]["quarantine_retention_s"]
        items, purged_bytes = [], 0
        for action in plan["actions"]:
            if action["state"] not in ("quarantined", "purge_intent"):
                continue
            art = self.get_artifact(action["artifact_id"])
            _, body = self._q_paths(qroot, action, art)
            why: list[str] = []
            if action["state"] == "quarantined":
                due = (art["quarantined_at"] or now) + retention
                if now < due:
                    why.append(f"quarantine retention until {due}")
                why += [w for w in self._protections(art, now) if not w.startswith("location is also")]
                if not why:
                    try:
                        self._root_real(qroot)
                        if not sfs.exists(body):
                            why.append("quarantined body is missing")
                        else:
                            changed = sfs.drift(action["post_snapshot"] or {}, sfs.snapshot(body, hash_limit=plan["policy"]["hash_verify_max_bytes"]))
                            if changed:
                                why.append(f"quarantined body drifted ({', '.join(changed)}); refused")
                    except sfs.UnsafePathError as exc:
                        why.append(f"unsafe quarantine body: {exc}")
            if why:
                items.append({"artifact_id": art["id"], "would": "skip", "reasons": why})
                if execute:
                    with self.store.tx():
                        self._ledger(cid, "storage", "purge_refused", actor, **self._art_head(art), plan_id=plan_id, reasons=why)
                continue
            if not execute:
                items.append({"artifact_id": art["id"], "would": "purge", "reclaim_bytes": art["reclaim_bytes"]})
                continue
            if action["state"] == "quarantined":
                with self.store.tx():
                    if not self._claim_action(action["id"], "quarantined"):
                        items.append({"artifact_id": art["id"], "would": "skip", "reasons": ["action changed concurrently"]})
                        continue
                    self._set_action(action["id"], "purge_intent")
                    self._ledger(cid, "storage", "purge_intent", actor, **self._art_head(art), plan_id=plan_id, action_id=action["id"])
            sfs.remove(body)  # idempotent: an interrupted purge resumes here on rerun
            if sfs.exists(body):
                items.append({"artifact_id": art["id"], "would": "skip", "reasons": ["body still present after delete"]})
                continue
            reclaimed = (action["post_snapshot"] or {}).get("reclaim_bytes", 0)
            tomb = {"sha256": art["sha256"], "size_bytes": art["size_bytes"], "reclaimed_bytes": reclaimed,
                    "root": art["root_name"], "rel_path": art["rel_path"], "quarantine_path": str(body),
                    "plan_id": plan_id, "purged_by": actor, "purged_at": self.store.now(), "verified_absent": True}
            with self.store.tx():
                self._set_action(action["id"], "purged", receipt={**(action["receipt"] or {}), "purge": tomb})
                self.store.conn.execute("UPDATE artifacts SET state='purged', purged_at=?, tombstone=?, updated_at=? WHERE id=?",
                                        (tomb["purged_at"], dumps(tomb), tomb["purged_at"], art["id"]))
                self._carry_contained(plan, art, "purged", tombstone={"plan_id": plan_id, "purged_by": actor})
                self._ledger(cid, "storage", "purge", actor, **self._art_head(art), plan_id=plan_id, tombstone=tomb,
                             contained=self._contained_ids(plan, art["id"]))
            purged_bytes += reclaimed
            items.append({"artifact_id": art["id"], "would": "purged", "reclaimed_bytes": reclaimed})
        return {"accepted": True, "executed": execute, "reasons": [], "items": items,
                "purged": sum(i["would"] == "purged" for i in items), "reclaimed_bytes": purged_bytes}

    # ------------------------------------------------------------------ disk pressure
    def _latest_sample(self) -> dict | None:
        row = self.store.one("SELECT * FROM storage_samples ORDER BY seq DESC LIMIT 1")
        if not row:
            return None
        return {**dict(row), "payload": loads(row["payload"], {})}

    def _current_level(self) -> str:
        sample = self._latest_sample()
        return sample["level"] if sample else "normal"

    def _guidance(self, level: str) -> dict:
        claims, pause, stop = PRESSURE_GUIDANCE[level]
        heavy = [r["job_id"] for r in self.store.all(
            "SELECT i.job_id FROM job_storage_intents i JOIN jobs j ON j.id=i.job_id WHERE i.intent='heavy' AND j.status='claimed' "
            "ORDER BY i.job_id")]
        actions = {"normal": [], "high": ["plan cleanup (storage plan) and review quarantine purges"],
                   "critical": ["apply eligible cleanup plans", "pause claimed storage-heavy jobs listed in pause_jobs"],
                   "emergency": ["emergency-stop storage-heavy work now", "purge due quarantine", "operator attention required"]}[level]
        return {"storage_heavy_claims_allowed": claims, "pause_storage_heavy": pause, "emergency_stop": stop,
                "pause_jobs": heavy[:LIST_LIMIT] if pause else [], "running_storage_heavy_jobs": heavy[:LIST_LIMIT],
                "recommended_actions": actions}

    def _reclaim_estimate(self) -> dict:
        policy, _ = evaluate_cleanup_policy(None)
        now = self.store.now()
        eligible = 0
        for r in self.store.all("SELECT id FROM artifacts WHERE state='present'"):
            art = self.get_artifact(r["id"])
            if not self._eligibility(art, policy, now):
                eligible += art["reclaim_bytes"]
        quarantined = self.store.scalar("SELECT COALESCE(SUM(reclaim_bytes),0) FROM artifacts WHERE state='quarantined'")
        managed = self.store.scalar("SELECT COALESCE(SUM(size_bytes),0) FROM artifacts WHERE state IN ('present','quarantined')")
        return {"managed_bytes": int(managed), "eligible_reclaim_estimate_bytes": eligible,
                "quarantined_reclaim_bytes": int(quarantined)}

    def sample_storage(self, *, actor: str) -> dict:
        """Take a durable disk-pressure sample over every configured root's filesystem and return supervisor guidance."""
        actor_row = self.actor(actor)
        roots = self.list_storage_roots()
        if not roots:
            raise ValueError("no storage roots configured")
        reasons = self._operator_reasons(actor_row, "sample storage pressure")
        if reasons:
            with self.store.tx():
                self._ledger(HOST_SCOPE, "storage", "config_refused", actor, setting="sample", reasons=reasons)
            return {"accepted": False, "reasons": reasons}
        thresholds = self.storage_thresholds()
        filesystems: dict[int, dict] = {}
        problems = []
        for r in roots:
            try:
                self._root_real(r)
            except sfs.UnsafePathError as exc:
                problems.append({"root": r["name"], "problem": str(exc)})
                continue
            usage = self._disk_usage(r["path"])
            fs = filesystems.setdefault(r["st_dev"], {"device": r["st_dev"], "roots": [], "total_bytes": int(usage.total),
                                                      "used_bytes": int(usage.used), "free_bytes": int(usage.free)})
            fs["roots"].append(r["name"])
        for fs in filesystems.values():
            fs["free_fraction"] = round(fs["free_bytes"] / fs["total_bytes"], 6) if fs["total_bytes"] else 0.0
            fs["level"] = pressure_level(fs["total_bytes"], fs["free_bytes"], thresholds)
        level = max((fs["level"] for fs in filesystems.values()), key=PRESSURE_LEVELS.index, default="normal")
        if problems:  # an unusable root is never silently ignored
            level = max(level, "critical", key=PRESSURE_LEVELS.index)
        previous = self._current_level()
        now = self.store.now()
        payload = {"protocol": "dsr.storage.guidance.v1", "level": level, "previous_level": previous, "sampled_at": now,
                   "filesystems": sorted(filesystems.values(), key=lambda f: f["device"]), "root_problems": problems,
                   "thresholds": thresholds, **self._reclaim_estimate(), **self._guidance(level)}
        with self.store.tx():
            sid = new_id("ssample")
            self.store.conn.execute("INSERT INTO storage_samples(id,level,payload,sampled_by,sampled_at) VALUES(?,?,?,?,?)",
                                    (sid, level, dumps(payload), actor, now))
            summary = {"sample_id": sid, "level": level, "previous_level": previous, "emergency_stop": payload["emergency_stop"],
                       "free_bytes": min((f["free_bytes"] for f in filesystems.values()), default=None),
                       "eligible_reclaim_estimate_bytes": payload["eligible_reclaim_estimate_bytes"], "root_problems": len(problems)}
            if level != previous:
                self._ledger(HOST_SCOPE, "storage", "pressure_change", actor, **summary)
            else:
                self._ledger(HOST_SCOPE, "storage", "sample", actor, **summary)
        return {"accepted": True, "reasons": [], "sample_id": sid, **payload}

    def storage_status(self) -> dict:
        """Latest durable pressure state + guidance (read-only; never samples)."""
        sample = self._latest_sample()
        thresholds = self.storage_thresholds()
        if not sample:
            return {"protocol": "dsr.storage.guidance.v1", "level": "normal", "sampled": False, "stale": True,
                    "note": "no storage sample recorded; claims are not pressure-gated until the supervisor samples",
                    **self._reclaim_estimate(), **self._guidance("normal")}
        age = self.store.now() - sample["sampled_at"]
        return {**sample["payload"], "sampled": True, "sample_id": sample["id"], "sample_age_s": round(age, 3),
                "stale": age > thresholds["max_sample_age_s"], **self._guidance(sample["level"])}

    # ------------------------------------------------------------------ engine hooks
    def _storage_claim_block(self, cid: str, job: dict) -> str | None:
        intent = self.store.scalar("SELECT intent FROM job_storage_intents WHERE job_id=?", (job["id"],))
        if intent != "heavy":
            return None
        level = self._current_level()
        return None if PRESSURE_GUIDANCE[level][0] else level

    def _storage_status(self, cid: str) -> dict:
        counts = {s: 0 for s in ("present", "quarantined", "purged", "missing")}
        for r in self.store.all("SELECT state, COUNT(*) n FROM artifacts WHERE campaign_id=? GROUP BY state", (cid,)):
            counts[r["state"]] = r["n"]
        sample = self._latest_sample()
        level = sample["level"] if sample else "normal"
        claims, pause, stop = PRESSURE_GUIDANCE[level]
        return {"level": level, "sampled_at": sample["sampled_at"] if sample else None, "storage_heavy_claims_allowed": claims,
                "pause_storage_heavy": pause, "emergency_stop": stop, "artifacts": counts,
                "open_plans": self.store.scalar("SELECT COUNT(*) FROM cleanup_plans WHERE campaign_id=? AND status IN ('planned','applying')", (cid,))}
