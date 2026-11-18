# REFALL Lite Architecture

## Roles

| Actor kind | Who | Can | Cannot |
|---|---|---|---|
| `supervisor` | Hermes | create campaigns, ingest images, enqueue, advance stages, select deep work, approve escalation, raise budgets, stop, resolve pending actions, draft reports, close out | claim jobs; promote evidence (Hermes is model-driven, so its judgement is not independent) |
| `human` | operator | everything `supervisor` can, plus act as an independent checker | — |
| `model` | Qwen on Spark, Claude/Codex-style lanes | claim jobs, submit results, record hypotheses, request escalation | promote or dispose findings, advance stages, change budgets, approve anything |
| `tool` | deterministic non-model checkers or replayers | claim jobs, act as an independent check or replay | operator actions |

Attribution comes from the claim, not from the payload. A finding submitted through a job is attributed to the worker that claimed that job.

## Components

```
Hermes (supervisor) ──API/CLI──► RefallLite facade
                                   ├─ engine     jobs · leases · budgets · retries · stops · stage gates · resume
                                   ├─ fleet      images · families · members(sha256) · occurrences
                                   ├─ findings   tiers · receipts · dispositions · escalation
                                   ├─ closeout   report state · closeout gate · CloseoutPackage
                                   └─ worker     job packet ▸ adapter.run ▸ refall-submit envelope
                                            │
                     ArcticBase REFALL state layer (lite): one SQLite file, WAL, BEGIN IMMEDIATE,
                     hash-chained ledger written in the same transaction as each state change
```

## Job state machine

```
queued ──claim──► claimed ──submit ok──► succeeded
  ▲                 │
  │  retryable &    ├─fail / malformed / missing submit / lease expiry─┐
  │  attempts<max   │                                                   │
  └─────────────────┘◄──────────────────────────────────────────────────┤
                         retryable & attempts>=max ─► dead   (+ operator_attention)
                         non-retryable              ─► blocked (+ operator_attention)
queued ──scope budget exhausted at claim──► budget_blocked (+ budget_decision)
any non-terminal ──operator stop / deadline / cancel──► cancelled
```

- `attempts` increments at claim, so the retry ceiling equals `max_attempts` claims.
- A claim returns a `claim_token` and a lease. Submissions carrying a wrong or stale token, or arriving after cancellation or lease reclaim, are refused and audited as a `runtime-event`.
- Backoff: `not_before = now + backoff_s × attempts`.
- Failure classes are retryable (timeout, rate limit, unavailable, transport, truncated, missing/malformed submit, lease expired, unknown) or non-retryable (capability_missing, scope_blocked, operator_stop, tool_execution_error).
- Resolving `operator_attention` cancels the blocked job. Resolving `budget_decision` cancels the jobs it blocked; `raise_budget` requeues them instead.

## Budget and stop model

- Scopes are `run`, `stage:<s>`, `family:<f>`, and `artifact:<image-id|member-sha>`. `type:*` gives a default template per scope type. Every job charges all four scopes: one claim at claim time, plus `cost_units` on success or failure (`default_job_cost` if the worker reports none).
- **The run budget is mandatory.** A campaign without `budgets.run.max_claims` and `max_cost` is refused.
- Usage is persisted, so a restart never refreshes a budget.
- If a non-run scope is exhausted, the claim marks the job `budget_blocked`; other families and artifacts continue.

Hard stops set the campaign to `stopped`. After a hard stop, nothing more can be claimed or enqueued, and queued or budget-blocked jobs are cancelled:

| Stop | Trigger | Claimed jobs |
|---|---|---|
| `budget_exhausted:run` | run claims or cost spent | may finish (overshoot bounded by in-flight jobs); stops once none remain or at the next claim attempt |
| `consecutive_failures` | `max_consecutive_failures` reached; a success resets the count | may finish |
| `deadline` | `deadline_at` passed; checked on claim, submit, fail, and resume | cancelled |
| `operator_stop` | supervisor or human | cancelled; late submissions refused |

Run-budget exhaustion is not reversible. `raise_budget` requires an active campaign.

Further ceilings: `max_jobs` (enqueue ceiling) and `max_deep_selections` (selective-deep cap).

## Stage gates (broad → selective)

`advance_stage` is operator-only and records each attempt to the ledger as `stage-gate`. A successful advance writes a checkpoint whose `input_hashes` are the image SHA-256 map.

| From → To | Gate |
|---|---|
| inventory → middle | at least one image; no unresolved inventory jobs; every image's inventory job is terminal; at least one succeeded |
| middle → deep | no unresolved middle jobs; **every product family** has at least one member with a succeeded middle job; optional `middle_coverage_min` |
| deep → fuzz_ready | no unresolved deep jobs; at least one approved `fuzz_escalation` |

Other placement rules:

- Inventory jobs target images; middle jobs target unique members.
- Deep jobs exist only through `select_for_deep`. This is operator-only, needs a reason, requires the member to have a succeeded middle job, and is capped by `max_deep_selections`.
- `fuzz_ready` jobs exist only through `approve_escalation`. The request needs a finding on that member at tier ≥ `independently_checked`, plus harness `artifact_refs`. The approver must be an operator and must not be the requester.
- These jobs carry `lane_hint: oss-crs-optional`. OSS-CRS is a specialist lane outside Lite.

## Evidence promotion

```
hypothesis ──tool/human, independent_check|deterministic_replay receipt──► independently_checked
independently_checked ──tool/human, deterministic_replay, ≥2 replays with identical output_sha256,
                        commands + artifact_refs──► validated
hypothesis|independently_checked ──non-model, typed receipt──► rejected | duplicate(duplicate_of)
```

- Every finding enters as `hypothesis`, whoever submits it. A requested higher tier is ignored and appended as a limitation.
- Every proposal, accepted or refused, is stored in `finding_transitions` with reasons and written to the ledger.
- Tier skipping is refused, and the checker may not be the finding's creator.
- Limitations, `source_anchors`, and `artifact_refs` only ever accumulate.
- **A model-only finding cannot reach `validated`.** Model and supervisor actors cannot promote, and a receipt that self-reports `checker_kind: model` is refused.
- Finding dedup key: `(campaign, vuln_class, normalized title, member_sha256)`. A repeat merges evidence, limitations, and contributors without resetting the tier.

## Firmware-fleet flow

1. `ingest_image(family, name, image_sha256, members[path, sha256])`. Each member is stored once per campaign by SHA-256; every (image, path, family) placement is an occurrence row. The member's `primary_family` is the first family that ingested it, and its jobs charge that family's budget.
2. Inventory runs one job per image. Then middle-depth runs **one job per unique member SHA-256**; re-enqueueing is deduplicated by an identity key, so identical members are analyzed once.
3. Findings anchor to a member SHA-256. `finding_occurrences` is a join, so images and families ingested later inherit the finding without re-analysis.
4. Selective deep work runs on operator-chosen members only, then the fuzz-ready escalation gate.
5. `draft_report` is deterministic JSON. Its content SHA-256 and ledger watermark are stored. The report is provisional below `validated` and goes stale on any later non-neutral ledger entry.
6. The closeout gate blocks on any of:
   - unresolved jobs (queued, claimed, blocked, budget_blocked)
   - open pending actions
   - material findings (default severities medium/high/critical) not yet `validated`
   - validated findings without a replay receipt
   - a missing manifest
   - a missing or stale report
   - a broken ledger chain

   It warns on non-material hypotheses, refused transitions, a stopped campaign, and incomplete middle coverage. A passing `closeout` persists a CloseoutPackage and sets the campaign to `closed`.

## Lineage and knowledge reuse (schema v2)

The full contract is in `LINEAGE-AND-REUSE.md`. In summary:

```
image ─► occurrence(path,container,offset,package) ─► content object (sha256, tier 0)
                                                        └─► code unit (file | function | module)
external analyzer ─► fingerprint observations (kind, tier, mode, analyzer, algorithm_version, source kind)
lineage pass ─► similarity edges (method, score, confidence, evidence, algorithm_version, status)
             ─► code family (proposed → approved | rejected | stale) ─► representative (scored, ledgered)
deep stage   ─► plan_lineage_work: representative full job ─► receipt ─► delta jobs per variant
finding      ─► applicability rows per occurrence (candidate_applicable → applicable | negative states)
attack chain ─► shared component node ◄── product entry/reachability edges (+ preconditions per product)
```

- **Order of work:** fingerprint and cluster before deep analysis (a stage-gate addition); then one representative per family; then bounded deltas; never a full repeat for a variant that has an eligible representative receipt.
- **Promotion rule extended to reuse:** anything propagated stays candidate-only until per-variant or per-product gates pass, and model actors cannot decide gates.
- **Invalidation:** a fingerprint algorithm version change stales every similarity-derived decision.

## Restart and resume

All state is in SQLite, and every mutation commits with its ledger row. A new process opening the same file continues exactly. `resume()` does three things:

- reclaims expired leases (counted as a `lease_expired` attempt)
- enforces the deadline
- compares the caller's current input hashes with the checkpoint `input_hashes`; drift opens a `resume_drift_decision` pending action, which blocks closeout until it is resolved

Concurrent processes are serialized with `BEGIN IMMEDIATE`, so two workers never claim the same job.

## Observability (fwspider_telemetry)

REFALL Lite emits structured telemetry without changing any gate, schedule, lineage or verification semantics:

- `ArcticBaseStore.append_ledger` buffers each ledger entry inside its transaction; `tx()` emits them as
  `<domain>.<action>` events only after COMMIT (with `ledger_seq` and `entry_hash`) and emits
  `state.rollback` on ROLLBACK. Canonical state is never written by telemetry.
- `RefallLite` public methods are wrapped by `observability.instrument_api` (`api.call` pre-operation and
  critical -> `api.result` / `api.error`); ledger events are children of the call that caused them.
- `cli.main` records invocation/inputs/result digests to the sink; stdout remains machine-readable JSON.
- `worker.run_one` and `model_worker.ModelWorker` record the worker seam and full model-call envelopes.
- Under the default strict policy an unusable log directory refuses work before the store is opened
  (exit 4); post-commit telemetry failures are dead-lettered and reported on stderr, never raised.

See `OBSERVABILITY.md`.
