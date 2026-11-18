# Deep Sea Research (DSR)

Deep Sea Research is a prototype for running model-driven vulnerability hunts over firmware and
source code without trusting the model's word for anything. A language model does the hunting. A
small, deterministic engine decides what counts: every job is bounded, every state change is
ledgered, and a finding only moves up the evidence ladder when its mechanical facts have been
reproduced independently of the model that proposed it.

This repository is the generic core of DSR. It contains no targets, no findings and no
target-specific prompts.

**Status: research prototype.** It runs and is tested, but interfaces change without notice and
nothing here is hardened for multi-user or hostile environments.

## What is in here

| Part | Where | What it does |
|---|---|---|
| REFALL Lite | `refall_lite/` | Campaign state in one SQLite file: bounded jobs with leases and retries, budgets, stop conditions, stage gates, findings and evidence tiers, a hash-chained ledger, reports and closeout. |
| Hunt pipeline | `refall_lite/corpus_hunt*.py`, `opencode_worker.py`, `verify.py`, `host_verify.py` | Ingests one image or file, runs one model-driven hunt on it, then re-derives and checks each finding before any promotion. |
| CVE prior-art check | `refall_lite/cve_prior_art.py` | Identifies a binary's component and version, then asks NVD whether a finding is already a disclosed CVE. Such findings are kept as leads, not promoted as new. |
| Lineage and reuse | `refall_lite/lineage.py`, `reuse.py` | Recognises the same or closely related code across many firmware images so that work on one copy can be reused, with per-occurrence applicability checks. |
| Telemetry | `fwspider_telemetry/` | Structured JSONL logging of every state change, model call, tool call and subprocess, with redaction. Python and Node emitters share one schema. |
| Operator scripts | `scripts/` | `hunt_generic.py` runs one hunt on one file, driven by environment variables. `run_mvp_slice.py` runs hunt, verify and promote on one image. |
| Examples | `examples/` | Three synthetic end-to-end campaigns and an advisory methodology pack. They need no model. |

## How a hunt works

1. **Ingest.** The target file is hashed and registered in a fresh campaign. Identical files are
   deduplicated by SHA-256.
2. **Hunt.** One [OpenCode](https://opencode.ai) session is started against the target with a
   restricted set of reverse-engineering tools (REA, driving Ghidra) and a priority list. The model
   must end with a structured submission. A submission that does not parse or does not satisfy
   the gate is refused, and the refusal is recorded with its reasons.
3. **Record.** Accepted findings enter at the lowest tier, `hypothesis`, with the claim the model
   made: addresses, bytes, call paths and source anchors.
4. **Verify.** A fresh model re-derives the mechanical facts from the claim alone, without the
   first model's narrative. The host separately extracts the same facts with real tools. Promotion
   to `independently_checked` needs the claim, the re-derivation and the host facts to agree. The
   comparison is set and graph membership only; it never judges whether something is a
   vulnerability.
5. **Prior art.** `cve_prior_art` identifies a binary's component and asks public CVE data
   whether a finding is already disclosed. A match is recorded with the `known_cve` disposition
   and a replayable receipt. This is a library the host code calls before promoting; the bundled
   scripts do not call it for you.
6. **Close out.** The engine reports what was claimed, what was refused and why, and what remains
   open. Closeout blockers must be resolved with receipts; there is no override.

The tier ladder is `hypothesis` → `independently_checked` → `validated`. The dispositions
`rejected`, `duplicate` and `known_cve` each need a typed receipt. Models can propose; only a
registered tool or human actor can promote.

## Requirements

- Python 3.11 or newer. The package has no runtime dependencies beyond the standard library.
- `pytest` for the test suite. Everything except the one live test also runs under `unittest`.
- Live hunts only:
  - an OpenAI-compatible chat endpoint serving a model of your choice;
  - the `opencode` CLI on `PATH`;
  - the REA MCP server (`rea mcp`) and a Ghidra install for binary targets.

The tests and the examples need none of the live components.

## Quick start

```bash
# run the tests from the repository root (no install needed)
python3 -m pytest -q

# or in a fresh environment
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest -q
```

Synthetic end-to-end campaigns, no model required:

```bash
python3 examples/run_synthetic_campaign.py     --workdir /tmp/dsr-synthetic
python3 examples/run_lineage_campaign.py       --workdir /tmp/dsr-lineage
python3 examples/run_observability_scenario.py --workdir /tmp/dsr-observability
```

The state store is driven through the Python API (`from refall_lite import RefallLite`) or the
CLI:

```bash
python3 -m refall_lite --db /tmp/dsr.sqlite --help
```

## Running a live hunt

`scripts/hunt_generic.py` hunts one file. Everything about the target comes from the environment,
so the script itself stays generic.

```bash
cat > /tmp/priorities.txt <<'EOF'
Priority, highest first: (1) memory corruption in parsers of received data;
(2) authentication bypass; (3) other logic bugs.
EOF

DSR_ROOT=/path/to/unpacked/target \
DSR_MEMBER=usr/sbin/some-daemon \
DSR_FAMILY=my-target \
DSR_DB=/tmp/my-target.db \
DSR_PRIORITIES_FILE=/tmp/priorities.txt \
DSR_TIMEOUT_S=3600 \
DSR_SPARK_BASE_URL=http://127.0.0.1:8000/v1 \
DSR_SPARK_MODEL=your-model-name \
python3 scripts/hunt_generic.py
```

| Variable | Meaning |
|---|---|
| `DSR_ROOT` | Directory the hunter works in. |
| `DSR_MEMBER` | Target file, relative to `DSR_ROOT`. |
| `DSR_FAMILY` | Label for the campaign. |
| `DSR_DB` | Campaign database. **It is deleted and recreated on every run.** |
| `DSR_PRIORITIES_FILE` | Text that replaces the default hunt priorities. |
| `DSR_TIMEOUT_S` | Hunt budget in seconds (default 10800). |
| `DSR_SPARK_BASE_URL`, `DSR_SPARK_MODEL`, `DSR_SPARK_API_KEY` | The model endpoint, model name and key. "Spark" is the name of the inference host in the reference deployment; any OpenAI-compatible endpoint works. |
| `DSR_REA_COMMAND` | REA MCP command (default `rea mcp`). |
| `GHIDRA_INSTALL_DIR`, `JAVA_HOME` | Passed through to REA when set. |

The script never starts the model endpoint. It probes it and exits with `DSR_RESULT=BRAIN_DOWN` if
it is not answering. The last line it prints is always `DSR_RESULT=<COMPLETE|TIMEOUT|ERROR|BRAIN_DOWN>`,
so a queue script can grep the outcome.

A hunt run this way stops at step 3 above: findings are recorded as hypotheses. Treat them as
unverified claims until you have checked them yourself or run them through the verify step
(`scripts/run_mvp_slice.py`, `refall_lite/verify.py`).

## What to expect from the output

Model-proposed findings are leads, not results. In our own use, a large share of raw hunt claims
turn out to be wrong or unreachable when a person reads the code: checks done by a caller, the
wrong version compared, severities overstated. The design assumes this. Nothing in this repository
should be read as evidence that a claim is true until it has passed the verification gate or a
human review.

## Layout

```
refall_lite/          state engine, hunt pipeline, verification, lineage, storage, CLI
  arcticbase/         contracts and the SQLite store
fwspider_telemetry/   structured logging (Python package and Node emitter)
scripts/              operator entry points for live hunts
examples/             synthetic campaigns and an advisory methodology pack
tests/                unit and end-to-end tests (offline)
docs/                 reference documentation
EVENT-SCHEMA.json     telemetry event schema
```

Reference documentation:

- `docs/REFALL-LITE.md`: the state engine, its schema versions, migration and known gaps
- `docs/REFALL-LITE-ARCHITECTURE.md`: jobs, budgets, stop conditions, gates
- `docs/ARCTICBASE-SUBSET.md`: the state-layer contracts
- `docs/LINEAGE-AND-REUSE.md`: code-family recognition and reuse rules
- `docs/WISHLIST.md`: how a model asks for a missing capability instead of improvising one
- `docs/STORAGE-AND-CLEANUP.md`: artifact registry, retention and cleanup
- `docs/OBSERVABILITY.md` and `docs/REDACTION-POLICY.md`: telemetry and what is redacted

## Names you will meet in the code

- **REFALL Lite**: the state engine. It is a clean-room, standard-library reimplementation of the
  state layer of a larger internal system (REFALL), which is not part of this release.
- **ArcticBase**: the name of that state layer.
- **Hermes**: the supervisor role, the actor that enqueues work and triages requests. Any operator
  or agent can play it.
- **Spark**, **Qwen**: the inference host and model family used in the reference deployment. They
  appear as actor names and in environment variable names; neither is required.
- **Firmware Spider**: the project's former name. It survives in `fwspider_telemetry` and the
  `FIRMWARE_SPIDER_*` environment variables.
- **REA**: the reverse-engineering MCP server the hunter uses to drive Ghidra.

## Not included

This release is the engine and the hunt pipeline. It does not include:

- any target, corpus, firmware image, finding or target-specific prompt;
- the autonomous assurance runtime and the methodology-pack builder used internally;
- deployment tooling, corpus acquisition tooling, or a user interface.

## Responsible use

DSR is a tool for finding vulnerabilities so they can be fixed. Use it only on software and
devices you own or are authorised to test, and report what you find to the affected vendor or
maintainer before publishing. See `SECURITY.md`.

## License

MIT. See `LICENSE`.
