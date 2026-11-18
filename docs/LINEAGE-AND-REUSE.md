# Cross-Firmware Code Lineage and Knowledge Reuse

This is the ArcticBase REFALL state layer (Lite), schema v2. It is implemented in `refall_lite/lineage.py` and `refall_lite/reuse.py`, with tests in `tests/test_lineage.py`, `tests/test_migration.py`, and `tests/test_lineage_e2e.py`, and the example in `examples/run_lineage_campaign.py`.

REFALL Lite does **not** analyze binaries. It stores *versioned fingerprint observations* produced by external analyzers (a tool or a human actor) and compares them deterministically. From that it records auditable similarity edges, code families, and representatives, then schedules bounded delta work and gates every piece of reused knowledge.

## Terminology → tables

| Term | Meaning | Table |
|---|---|---|
| firmware image | one ingested image | `images` |
| artifact occurrence | one path in one image, plus optional `container`, `offset`, `package` | `occurrences` |
| content object | exact bytes, keyed by SHA-256 (tier 0) | `members` |
| code unit | a whole file, or a named function/module inside a content object | `code_units` |
| fingerprint observation | one signal from one analyzer under one algorithm version | `fingerprint_observations` |
| similarity edge | a pairwise comparison: method, score, confidence, evidence, algorithm version, status | `similarity_edges` |
| code family | a lineage cluster with member status, policy snapshot, and representative | `code_families`, `code_family_members`, `representatives` |
| analysis receipt | the result of a middle, full-deep, delta, or reused analysis on a content object, with checked scopes and digests | `analysis_receipts` |
| delta receipt | a variant-vs-representative outcome: consistent, diverged, or inconclusive | `delta_receipts` |
| reuse record | a representative-analysis or negative-result reuse, with its basis and algorithm version | `reuse_records` |
| finding applicability | per-occurrence state and gates for one finding | `finding_applicability` |
| attack chain | nodes (shared or product), edges, and per-edge preconditions | `attack_chain_nodes`, `attack_chain_edges`, `attack_chain_preconditions` |

A finding stays **one record**. Its reach across firmware images is represented by applicability rows, never by copies of the finding.

## Signal registry (`lite-fp-v1`)

| Tier | Kinds | Mode | Counts toward equivalence? |
|---|---|---|---|
| 0 | content SHA-256 | — | identical bytes share one content object and one middle-depth job |
| 1 | `normalized_digest` | exact | yes; exact anchor |
| 2 | `build_id`, `package_version`, `version_string` | exact | yes; exact anchor |
| 2 | `source_paths`, `symbol_set`, `import_set`, `export_set` | set (Jaccard) | yes, if score ≥ `fuzzy_min_score` |
| 3 | `function_hashes`, `cfg_features`, `strings_constants` | set (Jaccard, within one analyzer) | yes, if score ≥ `fuzzy_min_score` |
| 4 | `behavior_digest` (deterministic replayed-behavior digest) | exact | yes; not an anchor |
| — | `language`, `isa`, `compiler`, `toolchain`, `package_name`, `file_type`, `soname`, `artifact_class`, `behavioral_role` | metadata | **never**; candidate generation, exposure, and priority only |
| — | `scoped_digest` `{scope, digest}` | scoped | not used for similarity; used for negative-result equivalence |

Unknown kinds are refused. So are observations whose `algorithm_version` differs from the campaign's.

## Equivalence policy (`lite-multisignal-v1`, configurable per campaign)

```json
"lineage": {"algorithm_version": "lite-fp-v1", "min_signal_kinds": 2, "min_tiers": 2,
            "fuzzy_min_score": 0.85, "require_exact_anchor": true, "auto_approve": false,
            "max_candidate_pairs": 2000, "max_delta_jobs": 200, "max_delta_items": 50,
            "require_before_deep": null}
```

An edge passes the policy only when **all** of the following hold:

- at least `min_signal_kinds` qualifying signal kinds
- drawn from at least `min_tiers` distinct tiers
- with at least one exact tier-1/2 anchor (when `require_exact_anchor` is set)

A signal qualifies only if **both** observations came from a `tool` or `human` actor. Model- and supervisor-sourced observations are recorded but never qualify.

Consequences:

- **Same language/ISA/compiler/package name alone:** no edge is stored. The pair is counted as `metadata_only_rejected` in the lineage-pass ledger event.
- **One fuzzy score alone, at any value:** the edge is stored as `candidate` with `policy_passed=false`. It is never auto-approved, and a supervisor cannot approve it.
- **Two fuzzy signals with no exact anchor:** does not pass.
- **A `behavioral_role` label plus one lineage signal:** does not pass, because a role label is metadata.
- **Below-threshold override:** only a `human` actor with a `human_lineage_review` receipt can approve such an edge. It is recorded as `override=true`.

Every edge stores the following, and its creation, approval, rejection, re-evaluation, and staling are ledgered:

- `method`, `algorithm_version`, `score` (mean of the qualifying scores), `confidence` (high/medium/low), and `policy_passed`
- `evidence.qualifying`, `below_threshold`, `non_qualifying`, `metadata_only`, each with tier, mode, score, analyzer, and both observation ids
- a snapshot of the policy used

## Lineage pass → families → representatives

`run_lineage_pass` does the following:

1. Builds an inverted index over observation values and set elements, and generates candidate pairs (structural pairs first, then metadata-only pairs), bounded by `max_candidate_pairs`.
2. Evaluates each pair and stores or updates its edge.
3. Takes connected components over usable edges (approved, or candidate with `policy_passed`).
   - A new component becomes a family: `approved` if `auto_approve` is set and every edge passes, otherwise `proposed`, with a `lineage_review` pending action.
   - A component that touches exactly one active family extends that family.
   - A component that spans several families opens a merge-conflict review and is never auto-merged.
4. Auto-selects a representative for each approved family. The score (`lite-rep-score-v1`) combines:
   - coverage: occurrences + 2 × product families
   - exposure: an exposed `behavioral_role`
   - centrality: the sum of approved edge scores
   - evidence: the number of qualifying signals
   - an already-analyzed bonus

   Ties go to the smallest unit id. The full rationale is stored and ledgered.
5. Writes the checkpoint `lineage-pass:<algorithm_version>` with the digest of the current observations.

Operators can also call `propose_cluster`, `approve_cluster`, and `reject_cluster` (rejection needs a receipt), and `approve_edge` / `reject_edge`.

## Scheduler integration

- **Fingerprint and cluster before deep work.** Once observations exist (or `require_before_deep` is true), the middle→deep stage gate requires:
  - a lineage-pass checkpoint for the current algorithm version
  - an observation digest that has not changed since that pass
  - no proposed families or members awaiting review
- **`plan_lineage_work`**, run at the deep stage, handles each approved family under the current algorithm version:
  - If the representative has no eligible receipt, it enqueues one representative full job (`lineage_role: representative`).
  - Once that receipt exists, it enqueues one `delta-analysis` job per distinct variant content. The payload carries the family, the representative receipt, the edge, and at most `max_delta_items` changed set items; truncation is flagged. A `representative_analysis` reuse record is written.
  - Priority is `max(10, 100 − 20·(product_families−1) − 10·exposed)`, so components shared across product families are claimed first.
- **No full duplicate analysis.** `select_for_deep(variant)` is refused while the variant's family is approved and current and its representative has an eligible receipt.
- **Bounds still apply.** All lineage jobs go through `_enqueue`, so the following govern them exactly as they govern baseline jobs:
  - budgets: run, stage, family, and artifact
  - `max_jobs`, `max_deep_selections` (which counts full jobs only), and `max_delta_jobs`
  - retry ceilings, stop conditions, and closeout blocking
- **Receipts.** Successful middle, deep, and delta jobs write analysis receipts:
  - `outcome` (findings, negative, or inconclusive)
  - `checked_scope` and `checked_digests` from the submission
  - for delta jobs, a delta receipt from the submission's `delta: {outcome, changed_items}`

## Reuse rules

| Knowledge | Rule |
|---|---|
| Exact bytes (tier 0) | One content object and one middle job. Every occurrence stays queryable. Applicability rows inherit only the byte-invariant gates (`code_path`, `version_constraints`); configuration, exposure, and preconditions stay pending for each occurrence. |
| Representative analysis | Reused for variants only as the *basis* for a bounded delta job; it never replaces that job. |
| Findings | `propagate_finding` creates `candidate_applicable` rows for every occurrence of the origin content and of each approved variant. A worker reporting the same root cause on a variant is attached to the canonical finding as a candidate row; it does not create a new finding. |
| Validated on another variant | Only when every gate (`code_path`, `version_constraints`, `configuration`, `exposure`, `preconditions`) passes with a tool/human receipt. The state then becomes `applicable`, and `validated_on_target` is true only if the origin finding is `validated`. |
| Negative states | `not_present` / `fixed` need a failed code or version gate. `unreachable` needs a failed exposure or precondition gate. `not_applicable` needs any failed gate. `unknown` needs a receipt. None of them generalize to sibling rows. |
| Negative analysis | `reuse_negative_result` needs a negative, non-derived receipt that declares at least one `code:*` and at least one `config:*` scoped digest. The target must have tool/human `scoped_digest` observations equal for **every** declared scope; for code scopes, identical bytes also count. |
| Attack chain | A shared component node is linked once per family or unit (idempotent). Entry, reachability, and exposure nodes and their edges are product-specific. `reuse_chain_node` refuses products that do not ship the component; otherwise it creates a new candidate edge with fresh `unknown` preconditions copied from a template edge. An edge is `confirmed` only when all its preconditions are satisfied, and `refuted` if any is unsatisfied. Model actors cannot decide preconditions. |

## Algorithm-version invalidation

`set_fingerprint_algorithm(new_version)` is operator-only. It does the following:

- marks every edge from the old version `stale`, keeping its prior status
- marks families from the old version `stale`
- marks reuse records stale
- marks lineage-derived applicability rows stale; they then refuse further gate decisions
- cancels queued or budget-blocked delta jobs planned under the old version
- cancels open lineage reviews
- refuses ingest of observations at the old version

Stale families never refuse full work and never get deltas planned. Reruns under the new version create new edges and families. Everything is ledgered, and the change survives a reopen.

## Closeout additions

| Check | Blocking? |
|---|---|
| `applicability-unresolved` (material findings with `candidate_applicable` rows) | yes |
| `applicability-unresolved-nonmaterial` | warn |
| `applicability-unknown` | warn |
| `applicability-stale` | warn |
| `attack-chain-candidate-edges` | warn |
| `lineage-stale` | warn |

Unresolved delta jobs and lineage reviews already block through `jobs-unresolved` and `pending-actions-open`.

## Concrete example

This walks through `examples/run_lineage_campaign.py`. It uses synthetic data only.

- **Fleet:**
  - router: `lr-1.0` with httpd build A, `lr-1.1` with httpd build B
  - cam: `lc-2.0` with httpd build C, plus rtspd
  - nas: `ln-1.0` with webd
  - busybox ships 4 times across 3 images, including `/rescue/bin/busybox` inside `rescue.img` at offset 65536
- **Tier 0:** busybox is one content object with 4 occurrences and one middle job.
- **Lineage:**
  - A–B and A–C pass on package@version, source paths, and function hashes (Jaccard 0.905).
  - B–C fails, because function-hash Jaccard is 0.818 and the remaining signals are all tier 2.
  - rtspd shares only metadata, so no edge is stored.
  - webd shares a single fuzzy function-hash overlap; the operator rejects it with a receipt.
  - The resulting family is {A, B, C} with representative A (the most central member).
- **Work:** one representative job on A, which returns a negative receipt for `code:upload_handler` and `config:httpd.conf`. Then two delta jobs: B is `consistent`; C is `diverged` because `code:parse_auth` was rewritten. A full repeat on C is refused.
- **Finding:** a default-credential bypass found on A is validated by a deterministic check plus a two-run replay. Propagation creates three rows. A is `applicable` after its occurrence gates; B is `applicable` after all five gates; C is `not_present`. The finding stays a single record.
- **Negative reuse:** A's upload-handler negative result is reused for B (code and config digests equal) and refused for C (config digest differs).
- **Attack chain:**
  - The shared component-weakness node is confirmed by the validated finding.
  - The router WAN edge is `confirmed`.
  - The cam LAN edge is reused, then `refuted` by a product-specific precondition.
  - nas reuse is refused, because nas does not ship httpd.
- **Staleness campaign:** changing `lite-fp-v1` to `lite-fp-v2` stales the family, cancels its delta job, and makes full analysis of the variant acceptable again.

## Limitations

- No analyzers ship with Lite: no disassembler, normalizer, function matcher, or behavior tracer. Signal quality is whatever the external analyzer provides.
- Set similarity is Jaccard within a single analyzer. Lite does not compare features across analyzers.
- Candidate generation is bounded (`max_candidate_pairs`, with truncation recorded); very large fleets need an external blocking step.
- Scheduling is file-level. Function and module units can be fingerprinted, compared, and clustered, but delta jobs target the containing content object.
- Occurrences stay `UNIQUE(image, path)`. Nested-container duplicates need distinct path strings.
- Gate outcomes are only as good as the tool/human receipts behind them. Lite enforces who can decide and what evidence is required, not the analysis itself.
