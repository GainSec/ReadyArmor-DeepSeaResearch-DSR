# REFALL Lite

This is the bounded campaign-state layer of Deep Sea Research (formerly "Firmware Spider"). Its canonical state lives in the **ArcticBase REFALL state layer (Lite subset)**: a single local SQLite file that holds all campaign, job, evidence, ledger, manifest, checkpoint, report, and closeout state.

REFALL Lite is **not** a model supervisor. Hermes is the dynamic operator and model supervisor, and Qwen on Spark (or Claude/Codex-style lanes) are bounded workers. REFALL Lite supplies:

- durable campaign state
- bounded jobs, with retries and recovery
- budgets and stop conditions
- stage and escalation gates
- evidence promotion
- SHA-256 member deduplication with occurrence mappings
- report and closeout state

It never calls a model, never picks a provider, and never plans work.

**Schema v2: cross-firmware code lineage and knowledge reuse.** Exact SHA-256 dedup is tier 0. On top of it, REFALL Lite adds:

- versioned fingerprint observations from external analyzers
- auditable multi-signal similarity edges
- code families with representatives
- bounded delta jobs for variants
- per-occurrence finding applicability gates
- negative-result reuse that requires proven code+config digest equivalence
- shared attack-chain nodes with product-specific reachability

Language, ISA, compiler, or package name alone never cluster anything, and a single fuzzy score never passes the policy. See `LINEAGE-AND-REUSE.md`.

**Schema v3: single-supervisor wishlist.** The analysis model requests missing capabilities (tools, MCP servers, dependencies, environments, access, artifacts, hardware, analyzers, web search, operator input) instead of installing or building them. Requests are deduplicated per campaign/scope/kind/item. Only an operator-kind supervisor triages them, as `provide_now`, `use_existing_alternative`, `defer_with_trigger`, or `decline`, with a rationale, an assessment, and objective revisit triggers. Provided capabilities are secret-free provenance/version/transport/config references, injected into matching job packets. Blocking items pause only dependent jobs. See `WISHLIST.md`.

**Schema v4: artifact registry, retention/cleanup, disk pressure.** Campaign-scoped registrations of files and directories under explicitly configured roots (`managed`, `retained`, one `quarantine`) carry SHA-256 identity, provenance, a retention class (canonical, source, regenerable, diagnostic, ephemeral), references, leases/holds and pins. File bodies are never stored. Cleanup is an operator-only, ledgered workflow: immutable plan → read-only validation → `--execute` apply by atomic same-filesystem rename into quarantine with post-move verification and crash recovery → restore → separate purge after retention, keeping tombstones. Canonical and source material is never a candidate. Disk-pressure samples map onto normal/high/critical/emergency guidance, and claims skip only jobs with an explicitly declared heavy storage intent. See `STORAGE-AND-CLEANUP.md`.

**Observability.** Every state transition, API/CLI call, worker/model/tool interaction, subprocess and error is
recorded as structured JSONL in the central Firmware Spider log directory (`FIRMWARE_SPIDER_LOG_DIR`) by the
bundled `fwspider_telemetry` package (shared with the Node downloader). CLI stdout stays pure JSON. See
`OBSERVABILITY.md`, `../EVENT-SCHEMA.json` and `REDACTION-POLICY.md`.

- Stdlib only (Python ≥ 3.11); no runtime dependencies. `pytest` runs the suite; everything except the one live test also runs under `unittest`.
- Clean-room reimplementation of the REFALL-V11 state layer; see `ARCTICBASE-SUBSET.md`.

## Install and test

```bash
# root test command (no install needed)
python3 -m pytest -q

# fresh environment
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest -q

```

## Synthetic end-to-end examples

```bash
python3 examples/run_lineage_campaign.py --workdir /tmp/refall-lite-lineage   # lineage / reuse addendum (~136 CLI calls)
```

It demonstrates the following, on synthetic data only:

- an exact duplicate at different paths and images
- non-identical httpd builds clustered into one family
- false candidates rejected: rtspd shares only metadata, webd only fuzzy features
- representative receipt reuse, bounded delta jobs, and refusal of a full repeat
- applicability gating (`applicable` vs `not_present`)
- negative-result reuse only with equal code and config digests
- a shared attack-chain node with product-specific reachability: router confirmed, cam refuted, nas refused
- staleness after a fingerprint algorithm version change

Observability scenario (one run across three processes, reconstructed in order from JSONL alone):

```bash
python3 examples/run_observability_scenario.py --workdir /tmp/refall-lite-obs     # 22 checks
python3 -m fwspider_telemetry --log-dir /tmp/refall-lite-obs/logs chain --run <run_id>
```

### Baseline example

```bash
python3 examples/run_synthetic_campaign.py --workdir /tmp/refall-lite-demo
```

The example drives about 94 separate `refall-lite` CLI processes, so the store is closed and reopened between every action. The inputs are synthetic metadata (`examples/synthetic_fleet/`, with hashes of the form `sha256("SYNTHETIC-NOT-REAL:…")`), and the workers are deterministic simulations. **No real firmware is analyzed and no model is invoked.** The independent check and replay use a real deterministic program (`examples/synthetic_check.py`).

The example demonstrates:

- broad inventory, then middle-depth analysis over unique members
- a crash with lease expiry, followed by resume and reclaim
- a stale claim token being refused
- a late image in another product family inheriting an existing finding through occurrences, with no re-analysis
- closeout blocked while a material finding is still a hypothesis
- model-only promotion attempts being refused
- a deterministic independent check, then a two-run replay that produces `validated`
- capped selective deep work
- a fuzz-ready escalation gate (the OSS-CRS lane is optional and not run)
- a passing closeout
- a separate campaign showing the run-budget hard stop

## CLI

```
refall-lite --db STATE.sqlite <command>
  actor add ID --kind model|supervisor|tool|human
  campaign create NAME --config cfg.json --actor A | stop CID | list
  status CID | info
  image ingest CID --file image.json --actor A | image occurrences CID SHA
  job enqueue-images|enqueue-members CID --stage S --kind K --actor A
  job claim CID --worker W [--stage S] | packet CID JOB | submit CID JOB --token T --file F
  job fail CID JOB --token T --status CLASS | cancel | list
  stage gate CID | advance CID --actor A | select-deep CID SHA --actor A --reason R
  finding list|show|record|transition|occurrences
  escalation request CID SHA --finding F --actor A --receipt R | approve CID ACTION --actor A --receipt R
  pending list|resolve   budget show|raise   manifest   checkpoint   resume
  report draft|show      closeout check|run  ledger verify|list
  lineage ingest|unit|units|observations|pass|compare|edges|edge-approve|edge-reject
  lineage propose|approve|reject|families|family|representative|plan|deltas|receipts|reuse
  lineage reuse-negative|set-algorithm|show|knowledge|config
  applicability propagate|list|check|decide
  chain node|edge|check|reuse|show
  wishlist request|list|show|resolve|revisit
  artifact register|show|list|reference|hold|release|pin
  storage root-add|roots|thresholds|inventory|status|sample|intent|plan|plans|plan-show|validate|apply|restore|purge
```

The Python API is `refall_lite.RefallLite(db_path)`, which exposes the same operations. The worker seam lives in `refall_lite.worker`: `run_one(lite, cid, adapter)` with any adapter that has `worker_id` and `run(packet) -> str|dict`.

## Layout

| Path | Role |
|---|---|
| `refall_lite/arcticbase/contracts.py` | ArcticBase contracts: ids, vocabularies, receipt/candidate/transition gates, redaction, resume preflight |
| `refall_lite/arcticbase/store.py` | ArcticBase durable SQLite store and hash-chained ledger |
| `refall_lite/engine.py` | Bounded job engine: budgets, leases, retries, stops, stage gates, manifest/checkpoint/resume |
| `refall_lite/fleet.py` | Images, families, member SHA-256 dedup, occurrences |
| `refall_lite/findings.py` | Findings, promotion tiers, dispositions, fuzz escalation |
| `refall_lite/closeout.py` | Report state and closeout gate |
| `refall_lite/worker.py` | Provider-neutral submit protocol, failure taxonomy, adapter seam |
| `refall_lite/lineage.py` | Signal registry, multi-signal policy, code units, observations, edges, families, representatives, lineage pass, delta planning, receipts, version invalidation |
| `refall_lite/wishlist.py` | Single-supervisor wishlist: request dedup/reopen, investment triage + revisit triggers, capability records, dependent-only blockers, packet injection |
| `refall_lite/storage.py` | Artifact registry, eligibility/protection, immutable cleanup plans, quarantine apply/restore/purge with crash recovery, disk-pressure sampling, heavy-intent claim gating |
| `refall_lite/storage_fs.py` | Stdlib filesystem safety: root identity, lstat path walk (no traversal/symlinks/special files), snapshots/drift, exclusive same-device rename, symlink-safe purge |
| `refall_lite/reuse.py` | Per-occurrence finding applicability gates, negative states, attack-chain nodes/edges/preconditions |
| `refall_lite/cli.py` | JSON CLI (exit 4 = observability unavailable under strict policy) |
| `refall_lite/observability.py` | ledger-after-commit events, API envelopes, telemetry resolution |
| `refall_lite/model_worker.py` | model-backed worker adapter with full model-call envelopes (mock client only) |
| `fwspider_telemetry/` | shared telemetry package: schema, redaction, sink, artifacts, model envelope, query CLI, Node emitter |

## Explicit exclusions

The following are not included:

- manager/head-agent or provider planning
- UI/frontend
- launchd/Docker
- watchdog/coverage service
- remote SSH executors
- analysis toolchains
- threat-model loops
- vendor disclosure workflow
- visual evidence UI

A static methodology bundle may be *referenced by path* in a job packet (`methodology_bundle`); Lite never executes it. OSS-CRS appears only as a `lane_hint` on `fuzz_ready` jobs. See `ARCTICBASE-SUBSET.md` and `REFALL-LITE-ARCHITECTURE.md`.

## Migration

- Opening a schema-v1 store (the baseline, commit `75532a1`) migrates it forward in place and **additively**:
  - new tables
  - new nullable occurrence columns `container`, `offset`, `package`
  - `store_meta.schema_version = 2` and `migrated_from = 1`
  - one `runtime-event/migrate` ledger entry per campaign

  Nothing is dropped or rewritten. This is proven against `tests/fixtures/baseline_v1.sqlite`, a real store produced by the baseline code.
- Opening a schema-v1 or schema-v2 store migrates it to schema v3 additively. The only addition is the `wishlist_items` table, plus `migrated_from` and one `runtime-event/migrate` ledger entry per campaign. A v1 store takes the v2 steps in the same single migration. This is proven against `tests/fixtures/baseline_v2.sqlite`, a real store produced by the pre-wishlist code (commit `4e23e0c`).
- Opening a schema-v1/v2/v3 store migrates it to schema v4 additively. The additions are nine storage tables (`storage_roots`, `storage_config`, `artifacts`, `artifact_refs`, `artifact_holds`, `cleanup_plans`, `cleanup_actions`, `storage_samples`, `job_storage_intents`), plus the same single `runtime-event/migrate` ledger entry per campaign. This is proven against `tests/fixtures/baseline_v3.sqlite`, a real store produced by the pre-storage code (commit `3b2ad1b`).
- A store with a newer `schema_version`, a foreign `store_meta`, or no `store_meta` raises `IncompatibleStoreError`. The CLI reports it and exits with code 3. The file is never reset.

## Known gaps

- No HTTP API. Hermes integrates through the Python API or the CLI.
- Redaction is pattern-based (private keys, cloud/API tokens, password or token key-value pairs) and is not a guarantee.
- Telemetry model envelopes are proven with a deterministic mock model; no real Qwen client ships yet.
- Budgets count claims and worker-reported `cost_units`; Lite does not meter tokens or time itself.
- In-flight jobs may finish after a run-budget exhaustion, so cost overshoot is bounded by the jobs in flight.
- There is no closeout override path; blockers must be resolved with receipts.
- Wishlist: no capability catalog, tool/MCP adapter, health prober, or live web-search provider ships. Worker submissions cannot yet carry wishlist requests; the supervisor relays them. Open wishes do not block closeout (see `WISHLIST.md`).
- Storage: cross-device quarantine is refused (no copy fallback); `source`/`canonical` retirement is out of scope; files above `hash_verify_max_bytes` are drift-checked by metadata only; pre-rename TOCTOU is detected after the move and undone, not prevented; claims are not pressure-gated until the supervisor samples; pausing claimed heavy jobs and emergency stop are supervisor actions (see `STORAGE-AND-CLEANUP.md`).
- Lineage: Lite ships no binary analyzer, disassembler, or function matcher; it consumes external observations. Candidate generation is bounded, scheduling is file-level, and the example fingerprints are synthetic (see `LINEAGE-AND-REUSE.md` → Limitations).
