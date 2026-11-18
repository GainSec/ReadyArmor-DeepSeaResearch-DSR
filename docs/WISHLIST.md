# Single-supervisor wishlist (schema v3)

The wishlist is how the DSR analysis lane asks for missing capabilities. One persistent DSR supervisor runs on the control host; Spark supplies only remote LLM inference. The lane records what it needs instead of installing packages, building harnesses, creating MCP servers, or guessing. The supervisor triages each request and provisions or declines it. Provided capabilities are injected into later job packets, so they are reused rather than requested or rebuilt again.

Code: `refall_lite/wishlist.py` (state), `refall_lite/arcticbase/contracts.py` (vocabulary, transition/triage/capability gates), `refall_lite/arcticbase/store.py` (`wishlist_items` table, additive v1/v2→v3 migration). Requirements: `docs/architecture/09-RUNTIME-INTEGRATION-REQUIREMENTS.md`. Semantics come from the REFALL-V11 coverage-service wishlist (see `SOURCE-MAP.json` → `schema_v3_wishlist_addendum`). The coverage service, CCMA topology, and multi-agent claiming are **not** carried over.

## Roles

| Who | May |
|---|---|
| Any registered actor (normally the model worker, or the supervisor on its behalf) | `request` |
| Operator kinds (`supervisor` = the DSR supervisor, `human`) | `resolve` (triage/provide/consume/cancel/reopen), `revisit` |

There is no claiming, assignment, team, or owner election. A model actor that tries to resolve is refused, and the refusal is ledgered. Hermes stays out of the steady-state path. It acts as the `human`/operator only when the DSR supervisor cannot safely decide, and DSR keeps running if Hermes disconnects.

The wishlist is separate from `pending_actions`. Pending actions are immediate workflow decisions (budget, dead job, escalation, drift) that block closeout. Wishlist items are durable capability needs, and they do not block closeout.

## Item

`kind` ∈ `tool, mcp, dependency, environment, access, artifact, hardware, analyzer, web_search, operator_input, other`.

| Field | Meaning |
|---|---|
| `item`, `item_key` | Requested name, and its normalised identity (case/space/punctuation-insensitive; versions kept) |
| `scope_type`, `scope_ref` | `campaign` (default), `job`, `image`, `member`, `code_unit`, or `finding`. The scope must name a linked object in the same campaign. |
| `job_id … finding_id` | Optional linkage. Each link is validated to exist in this campaign. |
| `reason`, `required_for` | Why the item is needed and what it unblocks. Free text is redacted and capped at 2000 chars. |
| `blocking` | Pauses dependent work (below). Allowed only with a non-campaign scope. |
| `requested_by`, `request_count`, `history` | Original requester, recurrence count, and a bounded event history (the last 50 entries; the full trail is in the ledger) |
| `status` | `open, approved, provided, consumed, deferred, denied, cancelled, superseded` |
| `disposition`, `decision` | The supervisor's investment-triage decision (below) |
| `resolution`, `capability`, `superseded_by` | Last receipt, the provided-capability record, and the successor item |

Identity is `(campaign, scope, kind, item_key)` and is `UNIQUE`. A repeated request never inserts a new row:

| Existing status | Repeat request |
|---|---|
| `open`, `approved`, `deferred` | `deduplicated`: count+1 and `blocking` may escalate (ledger `dedup`); revisit triggers are checked |
| `consumed`, `cancelled` | `reopened` → `open` with fresh reason; the prior resolution is kept in history (ledger `reopen`) |
| `denied`, `superseded` | `refused`, but counted (ledger `request_refused`); it reopens only if its revisit trigger fires |
| `provided`, or the same kind+item is provided campaign-wide | `refused` with the existing item returned: use it (ledger `request_refused`) |

## Lifecycle and capability-investment triage

```
open ──► approved ──► provided ──► consumed ──► (open on recurrence)
  │         │            └──► provided (refresh capability/health), cancelled, superseded
  ├──► deferred ──► open (trigger fired / supervisor) | approved | provided | denied | cancelled | superseded
  ├──► denied ──► open      superseded ──► open      cancelled ──► open
```

Only the transitions above are legal (`contracts.WISH_TRANSITIONS`). A missing capability is never built or installed automatically. Moving an item into `approved`, `provided` (from open/deferred), `superseded`, `deferred`, or `denied` is an investment decision, and it needs a `decision` record. The disposition maps one-to-one onto the status and is stored durably in `wishlist_items.disposition`:

| Disposition | Status | Extra requirement |
|---|---|---|
| `provide_now` | `approved` → `provided` | Provide needs an evidence receipt and, for runnable kinds, a capability record. No revisit trigger. |
| `use_existing_alternative` | `superseded` | `superseded_by` (a wishlist item in this campaign) or `decision.alternative_ref` |
| `defer_with_trigger` | `deferred` | An objective `revisit_trigger` that is not already satisfied |
| `decline` | `denied` | Evidence receipt; trigger optional |

Every decision must include `rationale` (redacted, ≤2000 chars). It must also include an `assessment` that rates exactly `expected_value`, `time_cost`, `storage_cost`, `risk`, and `maintenance` as `none|low|medium|high`. If a `disposition` is given, it must agree with the status.

Every resolution needs a receipt. `provided` and `denied` need evidence material (`evidence_refs`, `artifact_refs`, `commands`, `source_anchors`, or `negative_tests`); other statuses need at least a `summary`. Supervisor reopen (`status=open`) clears the standing decision, so the item gets fresh triage.

### Objective revisit triggers (any-of)

| Trigger | Fires when |
|---|---|
| `request_count_at_least: N` | The model has asked N times (repeated blocker) |
| `stage_reached: <stage>` | The campaign reaches that stage (e.g. `deep`) |
| `material_finding_awaiting_validation: true` | A material-severity finding sits at hypothesis/independently_checked |
| `family_members_at_least: N` | An approved code family has ≥ N approved members (family-wide reuse opportunity) |
| `after: <epoch>` | Time has passed (time/budget window) |

Triggers are evaluated on request recurrence, inside `advance_stage` at every stage transition, and by an explicit supervisor pass (`revisit_wishes` / `wishlist revisit`). They are never evaluated on every scheduler pass. When a trigger fires, the item returns to `open` with its disposition cleared. The ledger gets a `revisit` entry whose receipt lists the fired triggers (`trigger:stage_reached=deep`), and the prior decision is kept in history. Disk-pressure and operator-priority triggers are not state-derivable inside REFALL Lite. The supervisor expresses them by reopening (`status=open`) with a receipt.

## Capability record (provided items)

The capability record is a closed, bounded schema of references only:

| Field | Requirement |
|---|---|
| `provider` | Required for runnable kinds (`tool, mcp, dependency, environment, analyzer, web_search`) |
| `version` or `commit` | Required for runnable kinds |
| `transport` | Required for runnable kinds. One of `mcp_stdio, mcp_http, cli, python, http_api, library, manual, other`. |
| `invocation_ref` or `config_ref` | Required for runnable kinds. A name/path of supervisor-held config, never its contents. |
| `provenance_url` | Required for runnable kinds. URL or `internal:` ref. |
| `project`, `license`, `storage`, `notes` | Optional strings |
| `health_status`, `health_checked_at` | Optional. `health_status` is `unknown|healthy|degraded|unhealthy`; refresh it with `provided` → `provided`. |
| `supported_inputs`, `supported_outputs` | Optional. ≤16 × ≤80 chars. |

Unknown fields, oversize values, secret-looking values (token formats, `key=value` credentials, private keys), and credential-bearing URLs (`scheme://user:pass@`) are **refused, not stored**. Refusal reasons name fields only, so a rejected secret is not copied into the ledger. Credentials stay in the supervisor's secret store, referenced by `config_ref`.

## Web search

`web_search` is a first-class provisionable kind. REFALL Lite provides no search provider and never simulates search. When the supervisor's adapter exists, it is recorded like any other capability (e.g. `transport=http_api, invocation_ref=supervisor-tool:web_search, config_ref=<secret-store name>`). Packets then expose `capabilities.web_search = {available: true, wish_id, capability}`. Until then they say `{available: false, requested: <bool>}`.

## Packet injection and blockers

`job_packet` (which now refuses a job from another campaign) carries `capabilities` (`dsr.capabilities.v1`). It covers only items whose scope applies to the job:
- campaign-wide items;
- the job itself;
- its image, or its member plus that member's images, code units, and findings.

| Packet field | Contents |
|---|---|
| `provided` | id, kind, item, scope, required_for (≤300 chars), capability |
| `requested` | Outstanding items (open/approved/deferred) with blocking flag, disposition, revisit trigger |
| `declined` | Denied/superseded items with disposition, rationale (≤300), alternative |
| `blockers`, `truncated`, `web_search` | Blocking ids; per-list overflow counts (each list is capped at 25); search availability |
| `rules` | Use provided capabilities first; do not install/build tools or create MCP servers; request missing ones; do not re-request listed items; continue with a recorded limitation when an item is declined or deferred |

A `blocking` item pauses only the work that depends on it. `claim_job` skips queued jobs whose scope matches an outstanding blocking item and reports them as `wishlist_blocked`. All other jobs stay claimable. A campaign-wide blocker is rejected for that reason. When the blocker is provided, declined, superseded, or cancelled, the dependent job becomes claimable again. A deferred blocker keeps its dependents paused, which also holds that stage's gate, so prefer `decline` when work can proceed with a limitation.

`status()` reports wishlist counts per status plus `open_blocking`. Wishlist ledger entries are report-neutral: they do not make a drafted report stale.

## Audit and telemetry

Every accepted or refused policy decision is a ledger entry of kind `wishlist`. The actions are `request`, `dedup`, `reopen`, `request_refused`, `resolve`, `resolve_refused`, and `revisit`. Each entry is written in the same transaction as the state change and emitted after COMMIT as `wishlist.<action>`; `*_refused` events are warning level. Structural input errors raise before any write: unknown campaign/actor/kind/scope, empty or oversize text, links that are malformed or belong to another campaign, and campaign-wide blockers. They surface as `api.error`, or exit code 2 on the CLI.

## API and CLI

```python
lite.request_wish(cid, actor=, kind=, item=, reason=, required_for=, scope="campaign", job_id=, image_id=,
                  member_sha256=, code_unit_id=, finding_id=, blocking=False)  # -> {accepted, outcome, reasons, wish}
lite.resolve_wish(cid, wish_id, actor=, status=, receipt=, capability=None, superseded_by=None, decision=None)
lite.revisit_wishes(cid, actor=)  # -> {evaluated, reopened}
lite.get_wish(wish_id); lite.list_wishes(cid, status=None, kind=None)
```

```bash
refall-lite wishlist request CID --actor qwen --kind mcp --item "ghidra mcp" --reason ... --required-for ... [--scope member --member SHA --blocking]
refall-lite wishlist resolve CID WISH --actor dsr-supervisor --status provided --receipt r.json --capability cap.json --decision d.json
refall-lite wishlist revisit CID --actor dsr-supervisor
refall-lite wishlist list CID [--status S --kind K]
refall-lite wishlist show WISH
```

Stdout is one JSON document. A policy refusal is `accepted: false` with exit 0. Structural errors exit 2.

## Toward the capability catalog (not built here)

Provided records are the seed of the future curated catalog: provider/version/commit/transport/invocation/config/provenance/health/I-O for mature prebuilt tools, existing MCP servers, and open-source adapters. Still to come:

- catalog discovery and population;
- the supervisor's tool/MCP adapters and live web-search adapter;
- health probing;
- parsing wishlist requests directly from worker `refall-submit` blocks (today the supervisor relays them with `requested_by` set to the model actor);
- a closeout view of open wishes.
