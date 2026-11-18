# ArcticBase REFALL Subset (Lite profile)

REFALL Lite's canonical durable state and evidence layer is the **ArcticBase REFALL state layer, Lite subset**. It lives in `refall_lite/arcticbase/` (contracts and store). The store reports `layer = "ArcticBase REFALL state layer"` and `profile = "lite"` in the `store_meta` table, and through `RefallLite.store_info()`.

Source: REFALL-V11 `arcticbase/backend/src/arctic_base/refall/` @ `0a4bba9b`. Everything was reimplemented clean-room with the stdlib; nothing was copied verbatim.

## Retained (same semantics)

| ArcticBase contract / semantic | Lite location |
|---|---|
| `stable_id(prefix, payload)` = prefix + sha256(canonical JSON)[:24] | `contracts.stable_id` (image ids, manifest ids, closeout ids) |
| EvidenceReceipt requires ≥1 of evidence_refs / source_anchors / artifact_refs / commands / negative_tests | `contracts.receipt_has_material` (transitions, pending resolution, escalation) |
| FindingCandidate requires a location and evidence; the gate reasons "missing evidence / confidence / anchors" | `contracts.evaluate_finding_candidate` |
| Source-anchor normalisation; `../` escapes refused | `contracts.anchor_path` |
| Only provisional statuses are creatable; validation claims need verification material | worker or caller tiers are ignored, findings land at `hypothesis`, and a limitation is recorded |
| Every transition proposal is recorded as accepted or refused with reasons, plus a receipts table | `finding_transitions`, `transition_receipts` |
| Suppressive transitions need receipt_type plus material; DUPLICATE needs duplicate_of | `contracts.evaluate_transition` |
| Canonical finding dedup: one record, variants merged | `contracts.finding_dedup_key`, `findings._record_finding_locked` |
| Pending actions: identity key, required receipt type, terminal statuses done/deferred/cancelled with receipt | `_base._open_pending`, `resolve_pending_action` |
| Append-only ledger with a closed kind set | `store.append_ledger`, `contracts.LEDGER_KINDS` |
| RunManifest upsert per (subject, run_id); stage checkpoints with input_hashes; resume_preflight drift classes | `engine.put_manifest`, `checkpoint`, `contracts.resume_preflight` |
| Closeout check shape; blocking fail ⇒ refused; open pending actions block; VALID-without-proof blocks; report-current/stale | `closeout.closeout_gate` |
| CloseoutPackage persisted with checks and a stable id | `closeout.closeout` |
| SQLite pragmas WAL / busy_timeout / foreign_keys | `store.ArcticBaseStore` |
| "Agents cannot authorize their own live actions" | escalation approval: an operator only, never the requester |
| "Keep secrets redacted" | `contracts.redact` is applied to worker data before persistence |

## Adapted

| ArcticBase | Lite change | Why |
|---|---|---|
| Workbench / subject | `campaigns` row | Fleet campaigns are the unit of work |
| Status `PROVISIONALLY_VALID…VALID` × quality `HYPOTHESIS/CODE_CONFIRMED/LIVE_CONFIRMED` | single tier `hypothesis → independently_checked → validated`, plus `rejected`/`duplicate` | Matches the project rule: model output stays provisional until a deterministic or independent non-model check |
| VALID needs a `live_repro` receipt | `validated` needs a `deterministic_replay` receipt with ≥2 identical output SHA-256 values, from a tool or human, reached only from `independently_checked` | Firmware work is replay-based, not live-target-based |
| Ledger as per-workbench JSONL | Ledger in the SQLite file, in the same transaction as the state change, hash-chained per campaign | Atomicity and tamper evidence |
| Dedup key uses `affected_component` | Uses `member_sha256` | Member-level fleet dedup |
| Coverage units (file/line partitions) with leases | Jobs over images and members with leases, claim tokens, attempts, and budgets | Firmware fleet instead of source lines |
| Coverage-service wishlist (subject, kind, item, reason, status; any caller sets any status) | `wishlist_items`: campaign/scope identity with dedup, operator-only legal transitions, investment-triage dispositions with revisit triggers, closed secret-free capability records, ledgered refusals | Single-supervisor DSR; see `WISHLIST.md` |
| Refused transitions block closeout | Downgraded to a warning | Refused model-only promotions are expected traffic; the material-finding check covers the substance |
| `resume_drift_decision` warns | Opens a pending action, which blocks closeout until resolved | Restart drift must be acknowledged |
| Pydantic DTOs | stdlib functions that return reason lists | Zero runtime dependencies |

## Added in schema v2 (lineage addendum; Lite-specific, no REFALL-V11 equivalent)

These tables are additive and migrated forward from v1:

- `code_units`, `fingerprint_observations`, `similarity_edges`
- `code_families`, `code_family_members`, `representatives`
- `analysis_receipts`, `delta_receipts`, `reuse_records`
- `finding_applicability`
- `attack_chain_nodes`, `attack_chain_edges`, `attack_chain_preconditions`

Also added: the occurrence columns `container`, `offset`, `package`, and the ledger kinds `lineage`, `applicability`, `attack-chain`. ArcticBase semantics carried into the new layer:

- canonical dedup with variants preserved: one finding record plus per-occurrence applicability rows, extending ArcticBase `related_locations`
- typed receipts with material for every decision
- every decision ledgered, whether accepted or refused
- pending actions for operator review (`lineage_review`)
- "agents cannot authorize their own actions": model and supervisor observations never qualify as equivalence evidence; model actors cannot decide applicability gates or attack-chain preconditions

## Omitted

- ContextPackage / subject context and SourceInventoryPackage. Fleet ingest replaces them.
- ScopeOverlay and the external-target scope checks.
- ThreatModelPackage and the threat-model cycle.
- TaskManifest. Replaced by the job packet.
- Capability broker: grants, requests, and `authorize_execution`.
- Closeout overrides.
- Visual-evidence, toolchain, vendor/CNA report, external-scope, and coverage-threshold closeout checks.
- Runtime events projection, observations, evidence deltas, evidence graph, nonfatal-error projection, and artifact store.
- Wishlist, attack patterns, and class coverage.
- (DSR addition, not an ArcticBase subset) artifact registry/retention/cleanup and disk pressure: schema v4, `STORAGE-AND-CLEANUP.md`.
- FastAPI routes, the filesystem object store, the report renderer, and the frontend.
