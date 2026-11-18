# Observability

One structured telemetry system for every operational component: REFALL Lite (API, CLI,
ArcticBase store, worker seam, model worker) and any external script that embeds the loader
(Python or Node). "Firmware Spider" is the project's former name and survives in the package
name `fwspider_telemetry` and the `FIRMWARE_SPIDER_*` environment variables. Logs are **diagnostic evidence, not authoritative
proof**: findings still have to be promoted through REFALL Lite gates.

| Piece | Where |
|---|---|
| Python package (stdlib only) | `fwspider_telemetry/` (shipped in the refall-lite wheel) |
| Node emitter (same protocol) | `fwspider_telemetry/node/fwspider-telemetry.mjs` |
| Event schema + taxonomy (183 types) | `EVENT-SCHEMA.json` = `fwspider_telemetry/event-schema.json` |
| Redaction rules (shared by both languages) | `fwspider_telemetry/redaction-rules.json`, policy in `REDACTION-POLICY.md` |
| REFALL Lite glue | `refall_lite/observability.py`, `refall_lite/model_worker.py` |
| Synthetic scenario | `examples/run_observability_scenario.py` |

## Event model

Every event is one JSON line with `schema_version` (`fwspider.event.v1`), `event_id`, UTC `ts`,
`monotonic_ns` (per process), `seq` (per run, allocated under the log-dir lock, unique across processes,
languages and restarts), `level`, `event_type`, `component`, `host`, `pid`, `run_id`, `process_id`,
optional `parent_event_id`, `campaign_id`, `job_id`, `model_call_id`, `tool_call_id`, `artifact_id`
(firmware/content object, e.g. `sha256:<hex>`), `finding_id`, `message`, sanitized `data`,
`log_artifacts` (artifact envelope refs) and `redaction` (`{count, rules, paths}` whenever anything was redacted).
Unknown event types or correlation fields raise immediately (programming error, never silently logged).

Taxonomy domains: `process run cli config telemetry log artifact api state ledger` (fallback),
the ArcticBase ledger domains (`campaign image job budget stage finding validation disposition pending
checkpoint manifest report closeout runtime lineage applicability attack_chain`), `worker model tool net
download verify monitor error scenario`. Ledger-derived event types are `<domain>.<action>`
(e.g. `job.claim`, `lineage.family_created`, `closeout.blocked`); the AST audit test proves every
`(kind, action)` written anywhere in REFALL Lite maps to a taxonomy entry.

## How REFALL Lite is instrumented

- **State transitions**: every `append_ledger` inside a transaction is buffered and emitted only after
  `COMMIT` with `ledger_seq`, `entry_hash`, `prev_hash`, actor and the (redacted) payload; `ROLLBACK`
  emits `state.rollback` listing what was discarded. Telemetry never writes canonical state.
- **API boundary**: every public `RefallLite` method is wrapped: `api.call` (pre-operation, *critical*),
  `api.result` (duration, result digest/summary), `api.error` (redacted exception, stack, cause chain,
  correlation IDs). Ledger events are children (`parent_event_id`) of the call that caused them.
  Read-only operations are recorded at debug level; nested calls are not re-logged.
- **CLI**: `process.start`, `cli.invoke` (sanitized argv, every `--file/--config/--receipt` input hashed
  and stored as a bounded redacted artifact, `config.load` for `--config`), `cli.result` / `cli.error`
  with the SHA-256 and length of exactly what was printed, `process.end`. **Stdout stays pure JSON.**
  Exit codes: 0 ok, 2 refused, 3 incompatible store, 4 observability unavailable under strict policy.
- **Worker seam** (`run_one`): `worker.run_start` (job packet artifact) -> adapter events ->
  `worker.run_end` or `worker.run_error` (exception + failure classification/retry decision).
- **Model calls** (`ModelWorker`, `fwspider_telemetry.ModelCall`): `model.call_start` (provider, model,
  endpoint alias, sampling config, template id/version, context refs) -> per request `model.request`
  (request SHA-256/length + redacted body artifact) -> `model.response` (hash, body, tokens, latency,
  status, finish reason) -> `model.tool_call` / `tool.*` / `model.tool_result` (linked by `tool_call_id`)
  -> `model.parse` (ok/errors) -> `model.retry` (reason, next action) -> `model.call_end`.
  Bodies are on by default (`FIRMWARE_SPIDER_LOG_BODIES=0` keeps hashes,
  lengths, tokens, templates and refs but stores no bodies). Only the deterministic `MockModelClient`
  ships; a real Qwen client plugs into the same `complete(request) -> dict` seam later.
  `instrumented_model_invoke` wraps any text-in/text-out `model_invoke(system, user)` seam.
- **Subprocesses** (`Telemetry.run_subprocess`): `tool.start` (sanitized argv, cwd, env allowlist +
  whole-env digest, timeout) -> `tool.end` (exit code, signal, duration, stdout/stderr artifact refs) or
  `tool.timeout` / `tool.error`. Children inherit `FIRMWARE_SPIDER_RUN_ID`, `..._PARENT_EVENT_ID`,
  `..._TOOL_CALL_ID`, campaign/job IDs, log dir and policy, so their events join the same run and chain.

## External operational scripts

Scripts outside the package (downloaders, verifiers, monitors, in Python or Node) emit into the
same log by embedding the loader. Children started through `Telemetry.run_subprocess` inherit the
run and parent ids, so their events join the same run and causal chain.

**Import/deployment path (no sys.path guessing).** The package is installed with the refall-lite wheel
(`fwspider-telemetry` console script included). External scripts embed the canonical loader
(`fwspider_telemetry/loader_snippet.py`, byte-identical copy): installed package -> `$FIRMWARE_SPIDER_TELEMETRY_PATH`
-> `<project home>/lib` for project homes that exist on the host; the vendored copy's `VENDORED.json` hashes
must match or import is refused. Produce a deployable copy with:

```bash
python3 -m fwspider_telemetry vendor --dest <home>/lib --node-dest <home>/lib/node
python3 -m fwspider_telemetry verify-vendored <home>/lib/fwspider_telemetry
```

Node scripts resolve `<home>/lib/node` the same way (hash-verified dynamic import).

## Directory layout and configuration

`FIRMWARE_SPIDER_LOG_DIR` wins; otherwise `FIRMWARE_SPIDER_PROFILE` (`local`|`spark`, two example
host profiles defined in `fwspider_telemetry/config.py`; edit them for your own hosts); otherwise host
detection (a profile's home directory exists on a matching platform); otherwise
`$FIRMWARE_SPIDER_HOME/var/log`; otherwise `~/.local/state/firmware-spider/log` (recorded as `fallback`).
The source is recorded in `run.start`, `process.start` and the manifest.

```
<log dir>/                      dirs 0700, files 0600
  .lock/owner.json              inter-process lock (Python and Node use the same mkdir protocol)
  events/ACTIVE                 active segment number
  events/current.jsonl          active JSONL segment
  events/seg-NNNNNN.jsonl.gz    closed segments (gzip, checksummed)
  events/INDEX.jsonl            hash-chained segment index (sha256 of file + uncompressed, runs/seq ranges, tombstones)
  human/current.log, human/seg-NNNNNN.log.gz   human-readable view rendered from the same events
  runs/<run_id>/state.json      per-run seq reservation + segment membership
  runs/<run_id>/manifest.json   start/end, processes (exit/status), components+git commit, runtime, config digests,
                                models, inputs/outputs by hash/path, segments, event counts, telemetry failures
  runs/<run_id>/artifacts/art_*.json   bounded artifact envelopes
```

| Variable | Default | Meaning |
|---|---|---|
| `FIRMWARE_SPIDER_TELEMETRY_POLICY` | `strict` (monitor: `degrade`) | see failure severity |
| `FIRMWARE_SPIDER_DEBUG` | `0` | debug-level events (reads, nested API calls, per-file verify, artifact writes, env name digest). Redaction is identical. |
| `FIRMWARE_SPIDER_LOG_BODIES` | `1` | store redacted model/tool bodies |
| `FIRMWARE_SPIDER_MAX_ARTIFACT_BYTES` | 262144 | artifact body bound (explicit `truncated`, lengths, hashes) |
| `FIRMWARE_SPIDER_LOG_ROTATE_BYTES` | 67108864 | segment size |
| `FIRMWARE_SPIDER_LOG_RETENTION_SEGMENTS` / `_DAYS` | unlimited | retention (index keeps tombstones with checksums) |
| `FIRMWARE_SPIDER_LOG_COMPRESS` / `_FSYNC` | `1` / `0` | gzip closed segments / fsync each write |
| `FIRMWARE_SPIDER_DEADLETTER_DIR` | `$TMPDIR/fwspider-deadletter-<uid>` | dead-letter spool |
| `FIRMWARE_SPIDER_REDACT_PATTERNS` | none | extra regexes (JSON list or file path) |
| `FIRMWARE_SPIDER_RUN_ID`, `_PARENT_EVENT_ID`, `_CAMPAIGN_ID`, `_JOB_ID`, `_TOOL_CALL_ID`, `_MODEL_CALL_ID` | set by parents | context propagation |

Event data larger than 16 KiB moves to an `event-data` artifact; the event keeps `_bounded`, hash, lengths
and the ref. Raw binary is never stored: `describe_binary` records path, size, sha256/sha1/md5, sniffed
type, offset/length and a 64-byte hex preview.

## Failure severity (logging failure is never silent)

| When | strict (default) | degrade |
|---|---|---|
| Log dir unusable at process start | refuse before any canonical work (`ObservabilityError`; CLI / verifier / downloader exit 4; DB never opened) | stderr notice + dead-letter, continue |
| Pre-operation event fails (`api.call`, `cli.invoke`, `tool.start`, `model.request`, `model.call_start`) | operation refused before it touches state | dead-letter, continue |
| Post-commit event fails (ledger events, results) | state is kept; event dead-lettered; stderr notice; never raises | same |
| Dead-letter also fails | full redacted event written to stderr | same |

Sequence numbers are reserved before the append, so a failed append leaves a gap equal to the
dead-letter record's `reserved_seq` (never a duplicate). `fwspider-telemetry recover --deadletter-dir D`
re-imports dead-lettered events with new seqs and `data._deadletter` provenance.

## Query recipes

```bash
T="python3 -m fwspider_telemetry --log-dir $FIRMWARE_SPIDER_LOG_DIR"
$T verify                                   # schema, per-run seq, artifact refs+hashes, segment checksums, manifests, 0600
$T query --run RUN_ID                       # human view of one run in exact seq order (--json for raw)
$T chain --job JOB_ID                       # tree: api.call -> job.claim -> worker.run_start -> model.* -> tool.* -> job.succeed
$T chain --model-call MC_ID --json          # one model interaction with tool calls/results
$T chain --tool-call TC_ID                  # one subprocess/tool and its ancestors
$T query --campaign CID --type job. --level warning
$T run RUN_ID                               # manifest + state + resolved segments
$T artifact RUN_ID ART_REF                  # bounded redacted body + hashes
$T render > human.log                       # regenerate the human log from JSONL
zcat events/seg-*.jsonl.gz | jq -c 'select(.run_id=="RUN_ID")' ; jq -c 'select(.level=="error")' events/current.jsonl
```

## Incident-debug workflow

1. `verify` the log dir; note `seq_gaps` (each must correspond to a dead-letter record) and problems.
2. Find the run: `run RUN_ID` (manifest status `running` with a process lacking `ended_at` = crashed process).
3. `query --run RUN_ID --level warning` for refusals, retries, rollbacks, telemetry failures.
4. `chain --job` / `--model-call` / `--tool-call` to walk from the failing event to its cause; open
   referenced artifacts for request/response/stdout/stderr bodies.
5. Cross-check canonical state with `refall-lite ledger verify CID` and `ledger list` — the ledger is
   authoritative; telemetry events carry the matching `ledger_seq`/`entry_hash`.
6. Recover dead-lettered events if any, and re-run `verify`.

## Verification

- `python3 -m pytest -q` (or `python3 -m unittest discover -s tests -t .`) runs the REFALL Lite and
  telemetry suites, including redaction, log-outage and crash-recovery cases.
- `python3 examples/run_observability_scenario.py` runs one campaign across three processes and
  reconstructs it, in order, from the JSONL alone.
