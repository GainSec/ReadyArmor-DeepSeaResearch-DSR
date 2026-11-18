"""ArcticBase REFALL state layer — Lite subset: durable SQLite store.

One SQLite file is the canonical state for campaigns (ArcticBase "workbench"),
fleet inventory, jobs, budgets, findings/evidence, transitions + receipts,
pending actions, an append-only hash-chained ledger, run manifests, stage
checkpoints, reports, closeout packages, (v3) single-supervisor wishlist items and (v4) the
artifact registry with retention/cleanup plans and disk-pressure samples.

Adapted from REFALL-V11 ``arctic_base/refall/coverage_db.py`` (pragmas, table
shapes), ``ledger.py`` (append-only kinds) and ``runtime_state.py`` (manifest /
checkpoint tables). Every state mutation and its ledger entry are written in
the same transaction, so a crash can never leave state without its audit row.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .contracts import LAYER_NAME, LEDGER_KINDS, PROFILE, SCHEMA_VERSION, canonical_json


class IncompatibleStoreError(RuntimeError):
    """The file is not an ArcticBase REFALL Lite store, or was written by a newer schema.

    REFALL Lite never resets or rewrites an incompatible store; it refuses to open it.
    """

SCHEMA = """
CREATE TABLE IF NOT EXISTS store_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS actors (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, provider TEXT, created_at REAL
);

CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
  current_stage TEXT NOT NULL DEFAULT 'inventory', config TEXT NOT NULL,
  stop_reason TEXT, consecutive_failures INTEGER NOT NULL DEFAULT 0,
  created_by TEXT, created_at REAL, updated_at REAL
);

CREATE TABLE IF NOT EXISTS images (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id),
  family TEXT NOT NULL, name TEXT NOT NULL, image_sha256 TEXT NOT NULL,
  metadata TEXT, ingest_seq INTEGER NOT NULL, created_at REAL,
  UNIQUE(campaign_id, image_sha256)
);
CREATE TABLE IF NOT EXISTS members (
  campaign_id TEXT NOT NULL REFERENCES campaigns(id), sha256 TEXT NOT NULL,
  size_bytes INTEGER, kind TEXT, primary_family TEXT NOT NULL,
  first_image_id TEXT NOT NULL, created_at REAL,
  PRIMARY KEY(campaign_id, sha256)
);
CREATE TABLE IF NOT EXISTS occurrences (
  campaign_id TEXT NOT NULL, member_sha256 TEXT NOT NULL, image_id TEXT NOT NULL REFERENCES images(id),
  path TEXT NOT NULL, family TEXT NOT NULL, created_at REAL,
  UNIQUE(image_id, path)
);
CREATE INDEX IF NOT EXISTS ix_occ_member ON occurrences(campaign_id, member_sha256);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id),
  identity_key TEXT NOT NULL, stage TEXT NOT NULL, kind TEXT NOT NULL,
  target_type TEXT NOT NULL, target_ref TEXT NOT NULL, family TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued', priority INTEGER NOT NULL DEFAULT 100,
  attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL,
  claimed_by TEXT, claim_token TEXT, lease_expires REAL, not_before REAL NOT NULL DEFAULT 0,
  failure_class TEXT, last_error TEXT, cost_used REAL NOT NULL DEFAULT 0,
  payload TEXT, result TEXT, enqueued_by TEXT, seq INTEGER NOT NULL,
  created_at REAL, updated_at REAL,
  UNIQUE(campaign_id, identity_key)
);
CREATE INDEX IF NOT EXISTS ix_jobs_status ON jobs(campaign_id, status, priority, seq);

CREATE TABLE IF NOT EXISTS budget_usage (
  campaign_id TEXT NOT NULL, scope TEXT NOT NULL,
  claims_used INTEGER NOT NULL DEFAULT 0, cost_used REAL NOT NULL DEFAULT 0,
  PRIMARY KEY(campaign_id, scope)
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id),
  dedup_key TEXT NOT NULL, title TEXT NOT NULL, vuln_class TEXT, severity TEXT NOT NULL,
  tier TEXT NOT NULL DEFAULT 'hypothesis', member_sha256 TEXT, image_id TEXT, job_id TEXT,
  created_by TEXT NOT NULL, origin_kind TEXT NOT NULL, duplicate_of TEXT,
  payload TEXT NOT NULL, created_at REAL, updated_at REAL,
  UNIQUE(campaign_id, dedup_key)
);
CREATE TABLE IF NOT EXISTS finding_transitions (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, finding_id TEXT NOT NULL,
  from_state TEXT, to_state TEXT, actor TEXT, receipt_type TEXT, receipt TEXT,
  duplicate_of TEXT, status TEXT NOT NULL, reasons TEXT, created_at REAL
);
CREATE INDEX IF NOT EXISTS ix_tr_finding ON finding_transitions(campaign_id, finding_id);
CREATE TABLE IF NOT EXISTS transition_receipts (
  id TEXT PRIMARY KEY, transition_id TEXT NOT NULL, finding_id TEXT NOT NULL,
  campaign_id TEXT NOT NULL, receipt_type TEXT NOT NULL, receipt TEXT NOT NULL,
  actor TEXT, created_at REAL
);

CREATE TABLE IF NOT EXISTS pending_actions (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, identity_key TEXT NOT NULL,
  kind TEXT NOT NULL, title TEXT NOT NULL, description TEXT,
  status TEXT NOT NULL DEFAULT 'open', priority TEXT DEFAULT 'medium',
  source_job_id TEXT, source_finding_id TEXT, source_member TEXT, scope TEXT,
  required_receipt_type TEXT, requested_by TEXT, payload TEXT,
  resolution TEXT, created_at REAL, updated_at REAL,
  UNIQUE(campaign_id, identity_key)
);

CREATE TABLE IF NOT EXISTS ledger (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, campaign_id TEXT NOT NULL,
  kind TEXT NOT NULL, action TEXT NOT NULL, actor TEXT, payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL, created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ledger_campaign ON ledger(campaign_id, seq);

CREATE TABLE IF NOT EXISTS run_manifests (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, run_id TEXT NOT NULL,
  payload TEXT NOT NULL, created_at REAL, updated_at REAL,
  UNIQUE(campaign_id, run_id)
);
CREATE TABLE IF NOT EXISTS stage_checkpoints (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, run_id TEXT, stage TEXT NOT NULL,
  checkpoint_key TEXT NOT NULL, status TEXT NOT NULL, input_hashes TEXT, output_refs TEXT,
  created_at REAL, updated_at REAL, seq INTEGER NOT NULL,
  UNIQUE(campaign_id, checkpoint_key)
);
CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, ledger_watermark INTEGER NOT NULL,
  content TEXT NOT NULL, content_sha256 TEXT NOT NULL, created_by TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS closeouts (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, passed INTEGER NOT NULL,
  payload TEXT NOT NULL, created_by TEXT, created_at REAL
);
"""

# Schema v2 (lineage/reuse addendum). Additive only: new tables + new nullable columns.
LINEAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS code_units (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id), content_sha256 TEXT NOT NULL,
  granularity TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', parent_unit_id TEXT, created_by TEXT, created_at REAL,
  UNIQUE(campaign_id, content_sha256, granularity, name)
);
CREATE TABLE IF NOT EXISTS fingerprint_observations (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, code_unit_id TEXT NOT NULL REFERENCES code_units(id),
  kind TEXT NOT NULL, tier INTEGER, mode TEXT NOT NULL, value TEXT NOT NULL, value_digest TEXT NOT NULL,
  analyzer TEXT NOT NULL, analyzer_version TEXT NOT NULL, algorithm_version TEXT NOT NULL,
  source_actor TEXT NOT NULL, source_kind TEXT NOT NULL, qualifies INTEGER NOT NULL,
  confidence TEXT, evidence TEXT, created_at REAL,
  UNIQUE(campaign_id, code_unit_id, kind, analyzer, algorithm_version, value_digest)
);
CREATE INDEX IF NOT EXISTS ix_obs_digest ON fingerprint_observations(campaign_id, algorithm_version, kind, value_digest);
CREATE TABLE IF NOT EXISTS similarity_edges (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, unit_a TEXT NOT NULL, unit_b TEXT NOT NULL,
  method TEXT NOT NULL, algorithm_version TEXT NOT NULL, score REAL NOT NULL, confidence TEXT NOT NULL,
  policy_passed INTEGER NOT NULL, evidence TEXT NOT NULL, status TEXT NOT NULL, override INTEGER NOT NULL DEFAULT 0,
  decided_by TEXT, decision TEXT, created_by TEXT, created_at REAL, updated_at REAL,
  UNIQUE(campaign_id, unit_a, unit_b, method, algorithm_version)
);
CREATE TABLE IF NOT EXISTS code_families (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, identity_key TEXT NOT NULL, name TEXT, status TEXT NOT NULL,
  algorithm_version TEXT NOT NULL, policy TEXT NOT NULL, representative_unit_id TEXT, representative_rationale TEXT,
  created_by TEXT, decided_by TEXT, decision TEXT, created_at REAL, updated_at REAL,
  UNIQUE(campaign_id, identity_key)
);
CREATE TABLE IF NOT EXISTS code_family_members (
  family_id TEXT NOT NULL REFERENCES code_families(id), code_unit_id TEXT NOT NULL, campaign_id TEXT NOT NULL,
  status TEXT NOT NULL, equivalence_tier INTEGER, via_edges TEXT, added_by TEXT, created_at REAL, updated_at REAL,
  PRIMARY KEY(family_id, code_unit_id)
);
CREATE TABLE IF NOT EXISTS representatives (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, family_id TEXT NOT NULL, code_unit_id TEXT NOT NULL,
  rationale TEXT NOT NULL, selected_by TEXT, active INTEGER NOT NULL DEFAULT 1, created_at REAL
);
CREATE TABLE IF NOT EXISTS analysis_receipts (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, code_unit_id TEXT, content_sha256 TEXT NOT NULL, job_id TEXT,
  analysis_kind TEXT NOT NULL, lineage_role TEXT, outcome TEXT NOT NULL, checked_scope TEXT, checked_digests TEXT,
  finding_ids TEXT, evidence TEXT, derived_from TEXT, created_at REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_receipt_job ON analysis_receipts(campaign_id, job_id) WHERE job_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS delta_receipts (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, job_id TEXT NOT NULL UNIQUE, family_id TEXT NOT NULL,
  variant_unit_id TEXT NOT NULL, representative_receipt_id TEXT NOT NULL, outcome TEXT NOT NULL,
  changed_items TEXT, evidence TEXT, algorithm_version TEXT NOT NULL, created_at REAL
);
CREATE TABLE IF NOT EXISTS reuse_records (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, kind TEXT NOT NULL, source_receipt_id TEXT NOT NULL,
  target_unit_id TEXT NOT NULL, family_id TEXT, basis TEXT NOT NULL, algorithm_version TEXT NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0, actor TEXT, created_at REAL,
  UNIQUE(campaign_id, kind, source_receipt_id, target_unit_id, algorithm_version)
);
CREATE TABLE IF NOT EXISTS finding_applicability (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, finding_id TEXT NOT NULL REFERENCES findings(id),
  image_id TEXT NOT NULL, path TEXT NOT NULL, content_sha256 TEXT NOT NULL, code_unit_id TEXT, product_family TEXT,
  derived_via TEXT NOT NULL, via_family_id TEXT, algorithm_version TEXT, state TEXT NOT NULL, checks TEXT NOT NULL,
  stale INTEGER NOT NULL DEFAULT 0, evidence TEXT, decided_by TEXT, decision TEXT, created_at REAL, updated_at REAL,
  UNIQUE(campaign_id, finding_id, image_id, path)
);
CREATE TABLE IF NOT EXISTS attack_chain_nodes (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, node_key TEXT NOT NULL, kind TEXT NOT NULL, label TEXT NOT NULL,
  scope TEXT NOT NULL, code_unit_id TEXT, family_id TEXT, finding_id TEXT, product_family TEXT, image_id TEXT,
  evidence TEXT, created_by TEXT, created_at REAL,
  UNIQUE(campaign_id, node_key)
);
CREATE TABLE IF NOT EXISTS attack_chain_edges (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, edge_key TEXT NOT NULL, src_node_id TEXT NOT NULL,
  dst_node_id TEXT NOT NULL, relation TEXT NOT NULL, product_family TEXT, reused_from_edge_id TEXT,
  evidence TEXT, created_by TEXT, created_at REAL, updated_at REAL,
  UNIQUE(campaign_id, edge_key)
);
CREATE TABLE IF NOT EXISTS attack_chain_preconditions (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, edge_id TEXT NOT NULL REFERENCES attack_chain_edges(id),
  ordinal INTEGER NOT NULL, description TEXT NOT NULL, state TEXT NOT NULL, evidence TEXT, checked_by TEXT,
  created_at REAL, updated_at REAL,
  UNIQUE(edge_id, ordinal)
);
"""
# v1 -> v2 column additions (artifact-occurrence container context).
V2_COLUMNS = [("occurrences", "container", "TEXT"), ("occurrences", "offset", "INTEGER"), ("occurrences", "package", "TEXT")]

# Schema v3 (single-supervisor wishlist). Additive only: one new table. Identity is
# (campaign, scope, kind, normalised item); recurrence updates the row instead of inserting.
# disposition/decision hold the supervisor's investment triage (provide_now | use_existing_alternative |
# defer_with_trigger | decline) with rationale, assessment and objective revisit trigger.
# Capability holds bounded references only (contracts.evaluate_capability); never credential values.
WISHLIST_SCHEMA = """
CREATE TABLE IF NOT EXISTS wishlist_items (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id), identity_key TEXT NOT NULL,
  kind TEXT NOT NULL, item TEXT NOT NULL, item_key TEXT NOT NULL, scope_type TEXT NOT NULL, scope_ref TEXT NOT NULL,
  job_id TEXT, image_id TEXT, member_sha256 TEXT, code_unit_id TEXT, finding_id TEXT,
  reason TEXT NOT NULL, required_for TEXT NOT NULL, blocking INTEGER NOT NULL DEFAULT 0,
  requested_by TEXT NOT NULL, request_count INTEGER NOT NULL DEFAULT 1, status TEXT NOT NULL DEFAULT 'open',
  resolved_by TEXT, resolution TEXT, capability TEXT, superseded_by TEXT,
  disposition TEXT, decision TEXT, history TEXT NOT NULL DEFAULT '[]',
  created_at REAL, updated_at REAL,
  UNIQUE(campaign_id, identity_key)
);
CREATE INDEX IF NOT EXISTS ix_wish_status ON wishlist_items(campaign_id, status, kind);
"""

# Schema v4 (artifact registry, retention/cleanup, disk pressure). Additive only: new tables, no column changes.
# Host-scoped rows (roots, thresholds, samples) are ledgered on the reserved chain HOST_SCOPE; artifacts, references,
# holds, plans and cleanup actions are campaign-scoped. No file body is ever stored: only hashes, sizes and metadata.
STORAGE_SCHEMA = """
CREATE TABLE IF NOT EXISTS storage_roots (
  name TEXT PRIMARY KEY, role TEXT NOT NULL, path TEXT NOT NULL UNIQUE, st_dev INTEGER NOT NULL, st_ino INTEGER NOT NULL,
  configured_by TEXT NOT NULL, created_at REAL
);
CREATE TABLE IF NOT EXISTS storage_config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_by TEXT, updated_at REAL);
CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id), root_name TEXT NOT NULL REFERENCES storage_roots(name),
  rel_path TEXT NOT NULL, kind TEXT NOT NULL, media_type TEXT, retention_class TEXT NOT NULL, object_type TEXT NOT NULL,
  sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, reclaim_bytes INTEGER NOT NULL, st_dev INTEGER, st_ino INTEGER,
  snapshot TEXT NOT NULL, job_id TEXT, image_id TEXT, member_sha256 TEXT, code_unit_id TEXT, finding_id TEXT, run_id TEXT,
  producer TEXT, rebuild_missing TEXT NOT NULL DEFAULT '[]', labels TEXT, pinned INTEGER NOT NULL DEFAULT 0, pin_reason TEXT,
  expires_at REAL, last_access_at REAL, state TEXT NOT NULL DEFAULT 'present', registered_by TEXT NOT NULL,
  quarantined_at REAL, purged_at REAL, tombstone TEXT, created_at REAL, updated_at REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_artifact_live ON artifacts(campaign_id, root_name, rel_path)
  WHERE state IN ('present','quarantined','missing');
CREATE INDEX IF NOT EXISTS ix_artifact_sha ON artifacts(campaign_id, sha256);
CREATE INDEX IF NOT EXISTS ix_artifact_state ON artifacts(campaign_id, state, retention_class);
CREATE TABLE IF NOT EXISTS artifact_refs (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, artifact_id TEXT NOT NULL REFERENCES artifacts(id), ref_type TEXT NOT NULL,
  ref_id TEXT NOT NULL, reason TEXT NOT NULL, created_by TEXT NOT NULL, created_at REAL, released_at REAL, released_by TEXT
);
CREATE INDEX IF NOT EXISTS ix_artifact_refs ON artifact_refs(artifact_id, released_at);
CREATE TABLE IF NOT EXISTS artifact_holds (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL, artifact_id TEXT NOT NULL REFERENCES artifacts(id), kind TEXT NOT NULL,
  holder TEXT NOT NULL, reason TEXT NOT NULL, job_id TEXT, expires_at REAL, created_at REAL, released_at REAL, released_by TEXT
);
CREATE INDEX IF NOT EXISTS ix_artifact_holds ON artifact_holds(artifact_id, released_at);
CREATE TABLE IF NOT EXISTS cleanup_plans (
  id TEXT PRIMARY KEY, campaign_id TEXT NOT NULL REFERENCES campaigns(id), status TEXT NOT NULL, rationale TEXT NOT NULL,
  policy TEXT NOT NULL, refused_classes TEXT NOT NULL, candidates TEXT NOT NULL, exclusions TEXT NOT NULL,
  expected_reclaim_bytes INTEGER NOT NULL, plan_sha256 TEXT NOT NULL, created_by TEXT NOT NULL, created_at REAL,
  applied_by TEXT, applied_at REAL, result TEXT
);
CREATE TABLE IF NOT EXISTS cleanup_actions (
  id TEXT PRIMARY KEY, plan_id TEXT NOT NULL REFERENCES cleanup_plans(id), campaign_id TEXT NOT NULL, artifact_id TEXT NOT NULL,
  seq INTEGER NOT NULL, state TEXT NOT NULL, planned_snapshot TEXT NOT NULL, quarantine_rel TEXT, post_snapshot TEXT,
  reason TEXT, receipt TEXT, updated_at REAL, UNIQUE(plan_id, artifact_id)
);
CREATE INDEX IF NOT EXISTS ix_cleanup_actions_artifact ON cleanup_actions(artifact_id, state);
CREATE TABLE IF NOT EXISTS storage_samples (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, level TEXT NOT NULL, payload TEXT NOT NULL,
  sampled_by TEXT NOT NULL, sampled_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS job_storage_intents (
  job_id TEXT PRIMARY KEY REFERENCES jobs(id), campaign_id TEXT NOT NULL, intent TEXT NOT NULL, estimated_bytes INTEGER,
  reason TEXT NOT NULL, declared_by TEXT NOT NULL, created_at REAL, updated_at REAL
);
"""
STORAGE_TABLES = ["storage_roots", "storage_config", "artifacts", "artifact_refs", "artifact_holds", "cleanup_plans",
                  "cleanup_actions", "storage_samples", "job_storage_intents"]
# Reserved ledger chain for host-level storage state (the control-plane host; one supervisor).
HOST_SCOPE = "host:storage"

GENESIS = "0" * 64


def dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def loads(value: Any, default: Any = None) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return default


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


class ArcticBaseStore:
    """Durable canonical store. Open, use, close; reopen to resume."""

    def __init__(self, path: str | Path, clock: Callable[[], float] | None = None, telemetry: Any = None) -> None:
        from ..observability import resolve_telemetry
        self.tel = resolve_telemetry(telemetry)
        self._pending_events: list[dict] = []
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock or time.time
        self.conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._depth = 0
        self.closed = False
        try:
            self._open_or_migrate()
        except BaseException as exc:
            self.conn.close()
            self.closed = True
            self.tel.exception(exc, event_type="state.open_refused" if isinstance(exc, IncompatibleStoreError) else "error.exception",
                               data={"path": str(self.path)}, message="store open refused; file untouched")
            raise
        self.tel.emit("state.open", {"path": str(self.path), "meta": self.info(), "migrated_from": self.migrated_from},
                      component="refall-lite.arcticbase")
        if self.migrated_from:
            self.tel.emit("state.migrate", {"path": str(self.path), "from_schema": self.migrated_from,
                                            "to_schema": SCHEMA_VERSION, "mode": "additive"},
                          component="refall-lite.arcticbase")

    def _open_or_migrate(self) -> None:
        """Create a fresh store, migrate v1/v2/v3 forward in place (additive), or refuse explicitly."""
        tables = {r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables and "store_meta" not in tables:
            raise IncompatibleStoreError(f"{self.path} is not an ArcticBase REFALL Lite store (no store_meta table)")
        if "store_meta" in tables:
            meta = {r[0]: r[1] for r in self.conn.execute("SELECT key,value FROM store_meta")}
            if meta.get("layer") != LAYER_NAME or meta.get("profile") != PROFILE:
                raise IncompatibleStoreError(
                    f"{self.path} is not an ArcticBase REFALL Lite store (layer={meta.get('layer')!r}, profile={meta.get('profile')!r})")
            try:
                version = int(meta.get("schema_version", "0"))
            except ValueError as exc:
                raise IncompatibleStoreError(f"unreadable schema_version {meta.get('schema_version')!r}") from exc
            if version > SCHEMA_VERSION:
                raise IncompatibleStoreError(
                    f"store schema_version {version} is newer than this REFALL Lite build supports ({SCHEMA_VERSION}); "
                    "upgrade refall-lite instead of opening it with an older build")
            if version < 1:
                raise IncompatibleStoreError(f"unsupported schema_version {version}")
        else:
            version = SCHEMA_VERSION  # brand-new file
        self.conn.executescript(SCHEMA)
        with self.tx():
            for key, value in (("layer", LAYER_NAME), ("profile", PROFILE), ("schema_version", str(SCHEMA_VERSION))):
                self.conn.execute("INSERT OR IGNORE INTO store_meta(key,value) VALUES(?,?)", (key, value))
            self._ensure_v2_columns()
            if version < SCHEMA_VERSION:
                self._migrate_forward(version)
        self.conn.executescript(LINEAGE_SCHEMA)
        self.conn.executescript(WISHLIST_SCHEMA)
        self.conn.executescript(STORAGE_SCHEMA)
        self.migrated_from = version if version < SCHEMA_VERSION else None

    def _ensure_v2_columns(self) -> None:
        for table, column, ddl in V2_COLUMNS:
            cols = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    def _migrate_forward(self, version: int) -> None:
        """Additive v1/v2/v3 -> current. Existing rows are never rewritten; one migrate ledger entry per campaign."""
        added = [f"{t}.{c}" for t, c, _ in V2_COLUMNS] if version < 2 else []
        if version < 3:
            added.append("table:wishlist_items")
        added += [f"table:{name}" for name in STORAGE_TABLES]
        self.conn.execute("UPDATE store_meta SET value=? WHERE key='schema_version'", (str(SCHEMA_VERSION),))
        self.conn.execute("INSERT OR REPLACE INTO store_meta(key,value) VALUES('migrated_from',?)", (str(version),))
        for row in self.conn.execute("SELECT id FROM campaigns").fetchall():
            self.append_ledger(row[0], "runtime-event", "migrate", None,
                               {"from_schema": version, "to_schema": SCHEMA_VERSION, "mode": "additive", "added": added})

    # -- lifecycle -----------------------------------------------------------
    def close(self) -> None:
        if not self.closed:
            self.conn.close()
            self.closed = True
            self.tel.emit("state.close", {"path": str(self.path)}, component="refall-lite.arcticbase")

    def now(self) -> float:
        return float(self.clock())

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Re-entrant IMMEDIATE transaction (serialises writers across processes)."""
        if self._depth:
            self._depth += 1
            try:
                yield self.conn
            finally:
                self._depth -= 1
            return
        self.conn.execute("BEGIN IMMEDIATE")
        self._depth = 1
        self._pending_events = []
        try:
            yield self.conn
        except BaseException as exc:
            self._depth = 0
            self.conn.execute("ROLLBACK")
            self._telemetry_rollback(exc)
            raise
        else:
            self._depth = 0
            try:
                self.conn.execute("COMMIT")
            except BaseException as exc:
                self._telemetry_rollback(exc, commit_failed=True)
                raise
            self._telemetry_commit()

    # -- telemetry (observes committed state only; never alters it) ---------
    def _telemetry_commit(self) -> None:
        from ..observability import emit_ledger
        pending, self._pending_events = self._pending_events, []
        for entry in pending:
            emit_ledger(self.tel, entry, loads(entry["payload"], {}))
        if pending:
            self.tel.emit("state.commit", {"ledger_entries": len(pending)}, component="refall-lite.arcticbase")

    def _telemetry_rollback(self, exc: BaseException, commit_failed: bool = False) -> None:
        pending, self._pending_events = self._pending_events, []
        discarded = [{"campaign_id": e["campaign_id"], "kind": e["kind"], "action": e["action"]} for e in pending]
        self.tel.emit("state.rollback", {"discarded": discarded, "commit_failed": commit_failed,
                                         "reason": f"{type(exc).__name__}: {exc}"}, component="refall-lite.arcticbase")

    def info(self) -> dict[str, str]:
        return {row["key"]: row["value"] for row in self.conn.execute("SELECT key,value FROM store_meta")}

    # -- query helpers -------------------------------------------------------
    def one(self, sql: str, args: tuple = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, args).fetchone()

    def all(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        return list(self.conn.execute(sql, args))

    def scalar(self, sql: str, args: tuple = ()) -> Any:
        row = self.conn.execute(sql, args).fetchone()
        return row[0] if row else None

    # -- ledger (append-only, hash-chained per campaign) ---------------------
    @staticmethod
    def _entry_hash(prev_hash: str, entry: dict[str, Any]) -> str:
        return hashlib.sha256((prev_hash + canonical_json(entry)).encode("utf-8")).hexdigest()

    def append_ledger(self, campaign_id: str, kind: str, action: str, actor: str | None, payload: dict[str, Any]) -> dict:
        if kind not in LEDGER_KINDS:
            raise ValueError(f"unsupported ledger kind: {kind}")
        with self.tx():
            prev = self.scalar(
                "SELECT entry_hash FROM ledger WHERE campaign_id=? ORDER BY seq DESC LIMIT 1", (campaign_id,)
            ) or GENESIS
            entry = {
                "id": new_id("led"),
                "campaign_id": campaign_id,
                "kind": kind,
                "action": action,
                "actor": actor,
                "payload": dumps(payload),
                "created_at": self.now(),
            }
            entry_hash = self._entry_hash(prev, entry)
            cur = self.conn.execute(
                "INSERT INTO ledger(id,campaign_id,kind,action,actor,payload,prev_hash,entry_hash,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (entry["id"], campaign_id, kind, action, actor, entry["payload"], prev, entry_hash, entry["created_at"]),
            )
            out = {**entry, "seq": cur.lastrowid, "prev_hash": prev, "entry_hash": entry_hash}
            self._pending_events.append(out)  # emitted by tx() after COMMIT, discarded on ROLLBACK
            return out

    def ledger(self, campaign_id: str, kind: str | None = None) -> list[dict]:
        sql = "SELECT * FROM ledger WHERE campaign_id=?"
        args: list[Any] = [campaign_id]
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        out = []
        for row in self.all(sql + " ORDER BY seq", tuple(args)):
            item = dict(row)
            item["payload"] = loads(item["payload"], {})
            out.append(item)
        return out

    def verify_ledger(self, campaign_id: str) -> dict:
        prev = GENESIS
        count = 0
        for row in self.all("SELECT * FROM ledger WHERE campaign_id=? ORDER BY seq", (campaign_id,)):
            entry = {k: row[k] for k in ("id", "campaign_id", "kind", "action", "actor", "payload", "created_at")}
            if row["prev_hash"] != prev or self._entry_hash(prev, entry) != row["entry_hash"]:
                return {"ok": False, "entries": count, "bad_seq": row["seq"]}
            prev = row["entry_hash"]
            count += 1
        return {"ok": True, "entries": count, "head": prev}

    def ledger_watermark(self, campaign_id: str) -> int:
        return int(self.scalar("SELECT COALESCE(MAX(seq),0) FROM ledger WHERE campaign_id=?", (campaign_id,)))
