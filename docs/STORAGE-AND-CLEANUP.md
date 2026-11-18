# Artifact registry, retention/cleanup, and disk pressure (schema v4)

This is the operator and agent reference for DSR's storage control. It assumes one persistent DSR supervisor and authoritative artifact store on the control host. Spark is a remote LLM inference worker only and does not own cleanup, retention, campaign state, or scheduling. There is no distributed queue, cluster coordination, or watchdog daemon, and Hermes is not in the steady-state path.

Code:
- `refall_lite/storage.py`: registry, eligibility, plan/apply/restore/purge, sampling, and claim gating.
- `refall_lite/storage_fs.py`: stdlib filesystem safety.
- `refall_lite/arcticbase/contracts.py`: vocabulary, provenance/policy/threshold gates.
- `refall_lite/arcticbase/store.py`: `STORAGE_SCHEMA`, additive v1/v2/v3→v4 migration.

Tests: `tests/test_storage.py` and `tests/test_migration.py`.

## Authority and audit

- Every state change requires an operator actor kind (`supervisor` or `human`). That covers root/threshold configuration, sampling, registration, references, holds, releases, pins, job storage intents, plans, apply, restore, and purge.
- A model or tool actor is refused. The refusal is ledgered as `storage.*_refused` (warning level) with reasons, and nothing else changes.
- Each mutation and its ledger row (kind `storage`) are written in one `BEGIN IMMEDIATE` transaction. Telemetry receives them only after COMMIT.
- Host-level rows (roots, thresholds, samples) use the reserved ledger chain `host:storage`, which `ledger verify host:storage` checks. Everything else is ledgered on the owning campaign's chain.
- Structural errors raise before any write: unknown actor, campaign, root, kind, class, or policy key; malformed links; cross-campaign references. They surface as `api.error`, or exit code 2 on the CLI.
- Refusal reasons name fields, never refused values. A secret-looking path, label, producer reference, or media type is refused and not stored.
- File bodies are never read into SQLite, ledgers, telemetry, or logs. Only SHA-256, sizes, types, inode/device, mtimes, and bounded metadata are kept.

## Roots

| Role | Meaning |
|---|---|
| `managed` | DSR-owned work space. Cleanup may move, restore, and purge registered artifacts here. |
| `retained` | Registration only (e.g. the verified corpus). Never mutated. |
| `quarantine` | Exactly one. It receives same-filesystem atomic renames. Registration inside it is refused. |

A root is canonicalised once (realpath), must be a real directory (not a symlink), and is immutable after configuration. The registry records its `(st_dev, st_ino)` and checks them before every use. If the root is swapped for a symlink or for another directory at the same path, the operation is refused.

These roots are refused when configured:
- a filesystem root or the home directory;
- a directory containing the state database;
- anything overlapping the REFALL Lite source tree or the repository;
- anything overlapping another configured root;
- a second quarantine root.

## Artifact record

| Group | Fields |
|---|---|
| Identity | `id`, `campaign_id`, `root_name` + `rel_path` (managed location), `object_type` (file/dir), `sha256` (file content, or a deterministic tree-content digest for directories), `size_bytes`, `reclaim_bytes` (bytes freed on purge: files with `nlink == 1` only), `snapshot` (type/dev/ino/size/mtime_ns/nlink/tree_digest/sha256), `kind`, `media_type` |
| Linkage | optional `job_id`, `image_id`, `member_sha256`, `code_unit_id`, `finding_id`, `run_id`. Each link must exist in the same campaign. |
| Provenance | `producer` = closed schema `{tool, version, commit, config_ref, config_sha256, rebuild_ref, inputs[{artifact_id, sha256, ref}], actor}`; `rebuild_missing`; `registered_by`, `created_at` |
| Lifecycle | `retention_class`, `pinned` + `pin_reason`, `expires_at`, `last_access_at` (refreshed by dedup/reference/hold), `state` ∈ `present, quarantined, purged, missing`, `quarantined_at`, `purged_at`, `tombstone` |
| Relations | `artifact_refs` (type ∈ `finding, job, artifact, run, manifest, checkpoint, report, closeout, replay, external`; reason; release receipt); `artifact_holds` (`lease` must expire, `hold` lasts until released; reason; optional job) |

Deduplication works by location. Re-registering a live location with the same content is `deduplicated`: the snapshot is refreshed and nothing new is inserted. A different hash or state at a live location is refused.

Equal content at another location becomes a separate registration. The registry returns it as `content_duplicates`, because equal hashes do not prove semantic equivalence and are never merged. When another campaign registers the same location, that is recorded, and the location is protected from either campaign's cleanup.

### Retention classes

| Class | Examples (closed `kind` vocabulary) | Cleanup |
|---|---|---|
| `canonical` | `state_db, ledger, manifest, checkpoint, evidence, validation_receipt, applicability_decision, lineage_decision, closeout`. These kinds must be registered as canonical. | **never** |
| `source` | `firmware, dump, representative, variant, crash_sample, harness, repro_script`. These must be source or stronger. | **never** |
| `regenerable` | `extraction_tree, decompiler_output, decompiler_db, embedding, index, graph, rendered_report` | only with complete rebuild provenance: tool, version or commit, every input with a sha256, `config_sha256`, `rebuild_ref`, and the output hash (the artifact's own sha256) |
| `diagnostic` | `log, log_segment, trace` | evidence-linked diagnostics wait `evidence_diagnostic_min_age_s` (default 30 days); the tombstone survives body deletion |
| `ephemeral` | `partial_download, temp_workspace, test_cache, bytecode_cache, overlay, debug_artifact, scratch, other` | after `min_age_s` |

Registering a kind below its minimum class is refused. Incomplete regenerable provenance does not refuse the registration, but the artifact can never become a candidate (fail closed).

## Eligibility (applied at plan, re-applied at apply and before purge)

An artifact is excluded, with a durable reason, if any of these holds:
- its state is not `present`;
- its class is `canonical` or `source` (even when a broad policy requests those classes, which are stripped and reported as `refused_classes`);
- its class was not requested by the policy;
- its root is not `managed`;
- it is pinned, has an active reference, or has an active hold or unexpired lease;
- it is linked to a validated or material-severity finding;
- it is linked to an unresolved job (`queued, claimed, blocked, budget_blocked`);
- it is a rebuild input of another live artifact;
- another campaign registered the same location;
- it is contained in a registered directory artifact (it is cleaned only with that directory), or it is a directory containing a protected or other-campaign registration;
- it is regenerable with missing provenance or with an input that is no longer present;
- it has not yet reached `expires_at`, or (with no expiry) is younger than the policy's minimum idle age;
- its path is unsafe;
- it changed since registration.

### Path safety (`storage_fs.py`)

Paths are root-relative. Absolute paths, NUL bytes, and empty, `.` or `..` components are refused.

Each component is checked with `lstat`. A symlink at any position is refused and never followed. Every parent must be a real directory, and the leaf must be a regular file or directory, so device files, sockets, and FIFOs are refused, including inside directory trees. As defence in depth, the real path must stay under the root.

## Workflow

```
inventory ──► plan (immutable) ──► validate (dry run) ──► apply --execute ──► quarantined ──► restore --execute
                                                                                   └──► purge --execute (after retention) ──► purged + tombstone
```

1. **Inventory**: `storage_inventory([cid])` reports logical and physical bytes (unique inode) by campaign, class, state, and root, plus quarantined bytes, purged bytes, and the tombstone count. It is read-only.
2. **Plan**: `preview_cleanup` is the read-only default. `plan_cleanup` (operator) records an immutable plan containing:
   - the policy snapshot;
   - the rationale;
   - the exact candidates, each with its snapshot (re-hashed for files ≤ `hash_verify_max_bytes`, default 256 MiB);
   - exclusion counts by reason, plus up to 100 examples;
   - `expected_reclaim_bytes` (the exact sum of candidates' `reclaim_bytes`);
   - `plan_sha256`.

   One `pending` cleanup action is created per candidate. Plans never touch the filesystem.
3. **Validate**: `validate_cleanup_plan` re-checks eligibility and snapshots, and reports `would_quarantine/would_refuse`. It never mutates.
4. **Apply**: `apply_cleanup_plan(..., execute=False)` is a dry run by default. With `execute=True` (operator):
   - The plan is refused if its content no longer matches `plan_sha256`, or if the quarantine root is missing or unsafe.
   - Only the frozen actions are processed. New eligible material is never added.
   - For each action, eligibility and snapshot are re-checked. Any drift in path, type, dev, inode, size, mtime_ns, nlink, tree digest, or hash makes it `refused`; the target is left alone.
   - Otherwise a `quarantine_intent` row is committed. The body is then moved by one `os.rename` into a freshly, exclusively created slot `quarantine/<campaign>/<plan>/<action>/<name>`; nothing is overwritten, cross-device moves are refused, and directories are fsynced.
   - The moved body is re-snapshotted. On mismatch it is moved back and refused.
   - Only after that verification are the `quarantined` state and receipt committed. Nested registrations inside a moved directory take on its state.
5. **Restore** (operator, `execute=True`): only while quarantined. The quarantined body is re-verified, parents are recreated without following symlinks, and the restore is refused if the original location is occupied.
6. **Purge** (operator, a separate `execute=True` call per plan):
   - Only after the plan's `quarantine_retention_s` (default 24 h).
   - Protections are re-checked, so a hold added while quarantined blocks the purge, and the quarantined body is re-verified.
   - Steps: `purge_intent` row → `unlink` or a symlink-attack-safe `rmtree` → absence is verified → `purged` with a tombstone (sha256, size, path, quarantine path, reclaimed bytes, actor, time).

   Quarantine does **not** free space; purge does.

### Restart safety and idempotency

Apply, restore, and purge with `execute=True` hold a host-wide exclusive lock (`flock` on `<quarantine>/.dsr-storage.lock`, non-blocking). A second concurrent mutator is refused with a ledgered `apply_refused`/`restore_refused`/`purge_refused`, so recovery never races a live mover. The OS releases the lock if the holder dies, so a crash never leaves it stuck. Each intent write is also a compare-and-set on the action's durable state.

The plan status runs `planned → applying → applied | partial | refused`. A rerun of the same command reconciles every `*_intent` row from the filesystem, and each decision is ledgered as `storage.recover`:

| Durable row | Filesystem | Outcome |
|---|---|---|
| `intent` | source present, slot empty | back to `pending`, re-validated |
| `intent` | slot present, source absent | verified against the plan snapshot, then finalized (one receipt) |
| `intent` | both or neither present | `anomaly`, left untouched for the operator |
| `restore_intent` | moved back | finalized; otherwise reverted to `quarantined` or flagged ambiguous |
| `purge_intent` | any | deletion resumes; absence is verified before the receipt |

Bytes are accounted only in the finalize transaction, so a crash or rerun cannot double-count them or produce a false success receipt. A finished plan reruns as `idempotent: true` with no new ledger rows.

## Disk pressure

`sample_storage` (operator) runs `disk_usage` on each configured root's filesystem. A level fires when free space falls below `min_free_fraction` **or** below `min_free_bytes`. The strictest firing level wins, and a root that fails its identity check forces at least `critical`.

| Level (default free fraction) | Storage-heavy claims may start | Pause existing heavy work | Emergency stop |
|---|---|---|---|
| `normal` | yes | no | no |
| `high` (< 15 %) | **no** | no | no |
| `critical` (< 8 %) | no | **yes** (`pause_jobs`) | no |
| `emergency` (< 3 % or < 1 GiB) | no | yes | **yes** |

Fraction thresholds must tighten from `high` to `emergency`. Byte floors are independent, and 0 means no floor. Configure them with `configure_storage_thresholds`.

Each sample is a durable `storage_samples` row plus a host-chain ledger entry: `storage.pressure_change` (warning) when the level changes, otherwise `storage.sample`. The guidance (`dsr.storage.guidance.v1`) includes:
- per-filesystem capacity, used, free, free fraction, and level;
- `managed_bytes`;
- `eligible_reclaim_estimate_bytes`, from DB-side eligibility under the default policy;
- `quarantined_reclaim_bytes`;
- the claim, pause, and emergency flags, with recommended actions.

`storage_status()` and `status(cid)["storage"]` read the latest durable sample and never sample. They report `stale` once the sample is older than `max_sample_age_s`, which defaults to 900 s.

**Storage-intent contract:** `set_job_storage_intent(cid, job, intent=none|light|heavy, estimated_bytes, reason)`. `claim_job` skips only jobs with an explicitly declared `heavy` intent while the level forbids heavy claims, and reports them as `storage_paused`. Job names and kinds are never inspected, so undeclared and light jobs stay claimable. REFALL Lite does not preempt claimed work; the supervisor acts on `pause_jobs` and `emergency_stop`.

## API

```python
lite.configure_storage_root(name, path, role="managed", actor=); lite.list_storage_roots()
lite.configure_storage_thresholds(actor=, thresholds=); lite.storage_thresholds()
lite.register_artifact(cid, actor=, root=, path=, kind=, retention_class=, media_type=, sha256=, producer=, job_id=, image_id=,
                       member_sha256=, code_unit_id=, finding_id=, run_id=, expires_at=, labels=)
lite.get_artifact(aid); lite.list_artifacts(cid, state=, retention_class=)
lite.reference_artifact(cid, aid, actor=, ref_type=, ref_id=, reason=); lite.hold_artifact(cid, aid, actor=, kind=, reason=, expires_at=, job_id=)
lite.release_artifact(cid, actor=, reason=, hold_id=|reference_id=); lite.pin_artifact(cid, aid, actor=, reason=, pinned=True)
lite.set_job_storage_intent(cid, job_id, actor=, intent=, reason=, estimated_bytes=)
lite.storage_inventory(cid=None); lite.storage_status(); lite.sample_storage(actor=)
lite.preview_cleanup(cid, policy=); lite.plan_cleanup(cid, actor=, rationale=, policy=)
lite.get_cleanup_plan(pid); lite.list_cleanup_plans(cid); lite.validate_cleanup_plan(cid, pid)
lite.apply_cleanup_plan(cid, pid, actor=, execute=False); lite.restore_artifact(cid, aid, actor=, execute=False)
lite.purge_cleanup_plan(cid, pid, actor=, execute=False)
```

Policy keys: `classes`, `min_age_s{ephemeral,regenerable,diagnostic}`, `evidence_diagnostic_min_age_s`, `quarantine_retention_s`, `max_candidates` (1..10000), `target_reclaim_bytes`, `hash_verify_max_bytes`.

## CLI

Stdout is always one JSON document. A policy refusal returns `accepted: false` with exit 0, and structural errors exit 2. Read-only by default: `storage plan` without `--record`, and `apply`, `restore`, and `purge` without `--execute`.

```bash
refall-lite storage root-add work /srv/dsr/work --actor dsr-supervisor            # --role managed|retained|quarantine
refall-lite storage root-add quarantine /srv/dsr/quarantine --role quarantine --actor dsr-supervisor
refall-lite storage roots | storage thresholds [--thresholds t.json --actor A] | storage inventory [--cid CID] | storage status
refall-lite storage sample --actor dsr-supervisor
refall-lite storage intent CID JOB --intent heavy --reason "decompiler db" --estimated-bytes 53687091200 --actor dsr-supervisor
refall-lite artifact register CID --actor A --root work --path x/tree --kind extraction_tree --class regenerable --producer prov.json
refall-lite artifact show AID | artifact list CID [--state S --class C]
refall-lite artifact reference CID AID --actor A --ref-type finding --ref-id FID --reason "evidence"
refall-lite artifact hold CID AID --actor A --kind lease --expires-at EPOCH --reason "worker reading" [--job JOB]
refall-lite artifact release CID --actor A --reason R (--hold HID | --reference RID)
refall-lite artifact pin CID AID --actor A --reason R [--unpin]
refall-lite storage plan CID [--policy p.json]                                     # preview, read-only
refall-lite storage plan CID --record --actor A --rationale "hourly sweep" [--policy p.json]
refall-lite storage plans CID | storage plan-show PID | storage validate CID PID
refall-lite storage apply CID PID --actor A [--execute]
refall-lite storage restore CID AID --actor A [--execute]
refall-lite storage purge CID PID --actor A [--execute]
```

## Non-goals and remaining gaps

- Cross-device quarantine is refused. There is no copy + fsync + hash + atomic-finalize fallback, so the quarantine root must share a filesystem with each managed root it serves.
- Retiring `source` or `canonical` material is out of scope. There is no downgrade, unregister, or "include protected" override.
- Telemetry segment retention stays owned by `fwspider_telemetry` (its own tombstones). The downloader's `files/`/`.part` handling stays with the downloader. Neither directory should be configured as a `managed` root. The corpus may be registered under a `retained` root.
- Hash re-verification at apply/restore/purge covers files up to `hash_verify_max_bytes`. Larger files are compared by metadata snapshot only (type/dev/inode/size/mtime_ns/nlink).
- A TOCTOU window remains between the pre-move check and `rename`. It is closed after the fact by post-move verification and move-back, not prevented, because there is no `renameat2`/`O_PATH` in portable stdlib.
- The live hash stored for a directory is a tree digest computed by this code, not an external archive hash.
- In inventory, logical bytes double-count nested registrations. Physical bytes de-duplicate by inode only.
- Claims are not gated until the supervisor records a sample (fail-open, reported as `sampled: false`/`stale`). A stale sample keeps gating at its last level.
- There is no autonomous scheduler. The supervisor decides when to sample, plan, apply, and purge. Pausing claimed heavy jobs is advisory (`pause_jobs`), and emergency stop is the supervisor's call (`stop_campaign`).
- There is no authentication: actor kind is trusted as elsewhere in REFALL Lite.
- Scope is control-host-local storage only. Spark (remote LLM inference) storage is neither sampled nor managed. Durable model-request state, Spark health checks, and inference retry/backoff belong to the next supervisor phase and are not part of this slice.
- The mutation lock uses `fcntl.flock`, which is POSIX-only and reliable only on a local filesystem. The quarantine root must not live on NFS.
- `missing` and `anomaly` states are reported for the operator. Nothing repairs them automatically.
