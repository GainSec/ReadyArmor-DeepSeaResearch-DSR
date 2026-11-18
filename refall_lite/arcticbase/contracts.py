"""ArcticBase REFALL contracts — Lite subset.

Adapted (clean-room, stdlib only) from REFALL-V11
``arcticbase/backend/src/arctic_base/refall/contracts.py`` and
``promotion_gates.py``. See SOURCE-MAP.json for exact provenance.

Validation functions return a list of human-readable refusal reasons; an empty
list means accepted. This mirrors ArcticBase's "record every refusal with
reasons" behaviour instead of raising.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

LAYER_NAME = "ArcticBase REFALL state layer"
PROFILE = "lite"
SCHEMA_VERSION = 4  # v2: lineage / knowledge-reuse; v3: single-supervisor wishlist; v4: artifact registry + cleanup (all additive)

# --- identities -------------------------------------------------------------


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))


def stable_id(prefix: str, payload: dict[str, Any]) -> str:
    """ArcticBase ``stable_id``: prefix + first 24 hex of sha256(canonical JSON)."""
    return f"{prefix}_{hashlib.sha256(canonical_json(payload).encode('utf-8')).hexdigest()[:24]}"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def normalize_sha256(value: object) -> str:
    """Return lowercase 64-hex digest or '' (ArcticBase ``_normalize_sha256``)."""
    text = str(value or "").strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1]
    return text if _HEX64.match(text) else ""


# --- closed vocabularies ----------------------------------------------------

ACTOR_KINDS = {"model", "supervisor", "tool", "human"}
# Workers that may claim jobs.
CLAIMING_KINDS = {"model", "tool"}
# Operator-side authority (stage advance, stop, budget, escalation approval).
OPERATOR_KINDS = {"supervisor", "human"}
# Only non-model actors can promote evidence. Hermes (supervisor) is itself
# model-driven, so its conclusions are not an independent check.
INDEPENDENT_KINDS = {"tool", "human"}

STAGES = ["inventory", "middle", "deep", "fuzz_ready"]

JOB_ACTIVE = {"queued", "claimed"}
JOB_UNRESOLVED = {"queued", "claimed", "blocked", "budget_blocked"}
JOB_STATUSES = JOB_ACTIVE | {"succeeded", "cancelled", "dead", "blocked", "budget_blocked"}

TIERS = {"hypothesis": 0, "independently_checked": 1, "validated": 2}
# known_cve: the finding's vuln is an already-disclosed CVE in an identified
# component -- not novel, so it is NOT promoted, but it is saved as an actionable
# lead (terminal disposition, receipt carries the component/version/CVE refs).
DISPOSITIONS = {"rejected", "duplicate", "known_cve"}
FINDING_STATES = set(TIERS) | DISPOSITIONS

CHECKER_KINDS = {"deterministic_tool", "deterministic_replay", "human_review"}
REJECT_RECEIPTS = {"non_reachability_proof", "scope_boundary", "replay_failed", "operator_override"}
DUPLICATE_RECEIPTS = {"duplicate_evidence"}
KNOWN_CVE_RECEIPTS = {"prior_art_cve"}

PENDING_TERMINAL = {"done", "deferred", "cancelled"}
PENDING_OPEN = {"open", "claimed"}

# ArcticBase LEDGER_KINDS, narrowed + Lite additions.
LEDGER_KINDS = {
    "campaign",
    "image",
    "job",
    "finding",
    "validation",
    "disposition-transition",
    "pending-action",
    "budget",
    "stage-gate",
    "runtime-event",
    "checkpoint",
    "manifest",
    "report",
    "closeout-gate",
    "lineage",
    "applicability",
    "attack-chain",
    "wishlist",
    "storage",
}
# Ledger kinds that do not make a drafted report stale (the report does not embed wishlist state).
REPORT_NEUTRAL_KINDS = {"report", "closeout-gate", "runtime-event", "checkpoint", "manifest", "wishlist", "storage"}

DEFAULT_MATERIAL_SEVERITIES = {"medium", "high", "critical"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}

RECEIPT_MATERIAL_KEYS = ("evidence_refs", "source_anchors", "artifact_refs", "commands", "negative_tests")


# --- receipts ---------------------------------------------------------------


def receipt_has_material(receipt: object) -> bool:
    """ArcticBase EvidenceReceipt rule: at least one material list is non-empty."""
    if not isinstance(receipt, dict):
        return False
    for key in RECEIPT_MATERIAL_KEYS:
        value = receipt.get(key)
        if isinstance(value, list) and any(str(v).strip() for v in value):
            return True
        if isinstance(value, str) and value.strip():
            return True
    return False


# --- redaction ("Keep secrets redacted. Note presence only.") ------------------

REDACTED = "[REDACTED]"
_SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abpr]-[A-Za-z0-9-]{10,})\b"), REDACTED),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|bearer)(\s*[=:]\s*|\s+)([^\s\"',;]{4,})"),
     lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}"),
]


def redact(value: Any) -> Any:
    """Recursively redact secret-looking values from worker-supplied data before persistence."""
    if isinstance(value, str):
        for pattern, repl in _SECRET_PATTERNS:
            value = pattern.sub(repl, value)  # type: ignore[arg-type]
        return value
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    return value


# --- anchors (promotion_gates._source_path) ---------------------------------


def anchor_path(ref: object) -> str:
    """Normalise a source anchor to a relative path; '' if unusable/escaping."""
    text = str(ref or "").strip()
    if not text or "://" in text:
        return ""
    if text.startswith("source:"):
        text = text.split(":", 1)[1]
    if "::" in text:
        text = text.split("::", 1)[0]
    match = re.match(r"^(.*?):\d+(?:(?:-\d+)|(?::\d+))?$", text)
    if match:
        text = match.group(1)
    text = text.lstrip("/")
    if not text or text.startswith("../") or "/../" in f"/{text}":
        return ""
    return text


def string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


# --- finding candidate gate -------------------------------------------------


def evaluate_finding_candidate(candidate: dict) -> list[str]:
    """Entry gate for any finding (ArcticBase FindingCandidate + promotion_gates)."""
    reasons: list[str] = []
    if not str(candidate.get("title") or "").strip():
        reasons.append("missing title")
    anchors = string_list(candidate.get("source_anchors"))
    artifacts = string_list(candidate.get("artifact_refs"))
    evidence = [e for e in (candidate.get("evidence") or []) if e]
    if not evidence and not anchors and not artifacts:
        reasons.append("missing evidence, source anchors, or artifact refs")
    elif not evidence:
        reasons.append("missing evidence")
    if not str(candidate.get("confidence") or "").strip():
        reasons.append("missing confidence")
    if not anchors and not artifacts:
        reasons.append("missing source anchors or artifact refs")
    for anchor in anchors:
        if not anchor_path(anchor):
            reasons.append(f"unusable or escaping source anchor: {anchor}")
    severity = str(candidate.get("severity") or "").lower()
    if severity not in SEVERITIES:
        reasons.append(f"bad severity {candidate.get('severity')!r}")
    if not (normalize_sha256(candidate.get("member_sha256")) or candidate.get("image_id")):
        reasons.append("finding must anchor to member_sha256 or image_id")
    return reasons


def finding_dedup_key(campaign_id: str, candidate: dict) -> str:
    """ArcticBase ``_finding_dedup_key`` adapted: component -> member SHA-256."""
    def norm(value: object) -> str:
        return re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).strip()

    parts = [
        campaign_id,
        norm(candidate.get("vuln_class") or "unknown"),
        norm(candidate.get("title")),
        normalize_sha256(candidate.get("member_sha256")) or str(candidate.get("image_id") or ""),
    ]
    return "dedup:" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


# --- transition gate --------------------------------------------------------


def evaluate_transition(
    finding: dict,
    *,
    to: str,
    actor: dict,
    receipt_type: str | None,
    receipt: dict,
    duplicate_of: str | None,
    duplicate_exists: bool,
) -> list[str]:
    """Promotion / disposition gate. Returns refusal reasons (empty = accept).

    Adapted from ArcticBase ``CoverageStore.transition_finding``: every
    upward move and every suppressive move needs a typed receipt with material.
    Lite additions: actor-kind enforcement, no tier skipping, checker != creator,
    and deterministic replay agreement for ``validated``.
    """
    reasons: list[str] = []
    current = finding["tier"]
    kind = actor["kind"]
    if to not in FINDING_STATES:
        return [f"bad target state {to}"]
    if current in DISPOSITIONS or current == "validated":
        return [f"finding is terminal at {current}"]
    if to == current:
        return [f"finding already {current}"]

    if to in TIERS:
        if TIERS[to] != TIERS[current] + 1:
            reasons.append(f"{to} requires current tier {_prev_tier(to)} (no tier skipping); finding is {current}")
        if kind not in INDEPENDENT_KINDS:
            reasons.append(f"actor kind {kind} cannot promote; model conclusions stay provisional until a tool/human check")
        if actor["id"] == finding.get("created_by"):
            reasons.append("independent check cannot be performed by the finding creator")
        checker_kind = str(receipt.get("checker_kind") or "")
        if checker_kind not in CHECKER_KINDS:
            reasons.append(f"receipt checker_kind must be one of {sorted(CHECKER_KINDS)}")
        if not receipt_has_material(receipt):
            reasons.append("promotion requires receipt evidence refs, anchors, artifacts, or commands")
        if to == "independently_checked":
            if receipt_type not in {"independent_check", "deterministic_replay"}:
                reasons.append("independently_checked requires independent_check or deterministic_replay receipt")
        if to == "validated":
            if receipt_type != "deterministic_replay":
                reasons.append("validated requires deterministic_replay receipt")
            if not string_list(receipt.get("commands")):
                reasons.append("deterministic replay requires commands")
            if not string_list(receipt.get("artifact_refs")):
                reasons.append("deterministic replay requires artifact_refs")
            replays = receipt.get("replays") if isinstance(receipt.get("replays"), list) else []
            digests = [normalize_sha256(r.get("output_sha256")) for r in replays if isinstance(r, dict)]
            if len(digests) < 2:
                reasons.append("deterministic replay requires at least 2 replays")
            elif not all(digests):
                reasons.append("replay output_sha256 values must be sha256 hex")
            elif len(set(digests)) != 1:
                reasons.append("replay outputs differ; not reproducible")
        return reasons

    # dispositions (suppressive): require typed receipt + material, non-model actor
    if kind == "model":
        reasons.append("model actors cannot dispose findings; submit evidence instead")
    if not receipt_type:
        reasons.append("suppressive transition requires receipt_type")
    if not receipt_has_material(receipt):
        reasons.append("suppressive transition requires receipt evidence refs or anchors")
    if to == "rejected" and receipt_type and receipt_type not in REJECT_RECEIPTS:
        reasons.append(f"rejected requires one of {sorted(REJECT_RECEIPTS)}")
    if to == "duplicate":
        if receipt_type and receipt_type not in DUPLICATE_RECEIPTS:
            reasons.append("duplicate requires duplicate_evidence receipt")
        if not duplicate_of:
            reasons.append("duplicate transition requires duplicate_of")
        elif not duplicate_exists:
            reasons.append("duplicate_of does not reference a finding in this campaign")
        elif duplicate_of == finding["id"]:
            reasons.append("finding cannot duplicate itself")
    if to == "known_cve" and receipt_type and receipt_type not in KNOWN_CVE_RECEIPTS:
        reasons.append(f"known_cve requires one of {sorted(KNOWN_CVE_RECEIPTS)}")
    return reasons


def _prev_tier(tier: str) -> str:
    rank = TIERS[tier] - 1
    return next(name for name, value in TIERS.items() if value == rank)


# --- resume preflight (runtime_state.resume_preflight) ----------------------


def resume_preflight(expected: dict[str, str], current: dict[str, str] | None) -> dict:
    changes = []
    actual = {str(k): str(v) for k, v in (current or {}).items()}
    if actual:
        for key, want in sorted(expected.items()):
            got = actual.get(key)
            if got is None:
                changes.append({"path": key, "expected": want, "actual": None, "reason": "missing"})
            elif got != want:
                changes.append({"path": key, "expected": want, "actual": got, "reason": "changed"})
        for key, got in sorted(actual.items()):
            if key not in expected:
                changes.append({"path": key, "expected": None, "actual": got, "reason": "added"})
    return {
        "accepted": not changes,
        "status": "accepted" if not changes else "drift",
        "checked": bool(actual),
        "changes": changes,
    }


# --- wishlist (single-supervisor capability requests; schema v3) ---------------
#
# Semantics adapted from REFALL-V11 coverage_service wishlist (researchers record what they NEED instead
# of guessing; provided items are injected into later preflight). DSR has one model lane under one
# supervisor: any registered actor may request, only operator kinds resolve; there is no claiming,
# assignment, team or owner model. See docs/WISHLIST.md.

WISH_KINDS = {"tool", "mcp", "dependency", "environment", "access", "artifact", "hardware", "analyzer",
              "web_search", "operator_input", "other"}
# Kinds that are runnable capabilities: a `provided` resolution must carry capability metadata.
CAPABILITY_KINDS = {"tool", "mcp", "dependency", "environment", "analyzer", "web_search"}
WISH_STATUSES = {"open", "approved", "provided", "consumed", "deferred", "denied", "cancelled", "superseded"}
WISH_SCOPES = ("campaign", "job", "image", "member", "code_unit", "finding")
# Recurrence of an equivalent request: dedup into outstanding items, reopen dormant ones; provided/declined items
# refuse (declined ones count the recurrence so a request_count_at_least revisit trigger can fire).
WISH_DEDUP = {"open", "approved", "deferred"}
WISH_REOPEN = {"consumed", "cancelled"}
WISH_DECLINED = {"denied", "superseded"}
WISH_OUTSTANDING = ("open", "approved", "deferred")
WISH_TRANSITIONS: dict[str, set[str]] = {
    "open": {"approved", "provided", "deferred", "denied", "cancelled", "superseded"},
    "approved": {"provided", "deferred", "denied", "cancelled", "superseded"},
    "deferred": {"open", "approved", "provided", "denied", "cancelled", "superseded"},
    "provided": {"provided", "consumed", "cancelled", "superseded"},  # provided->provided refreshes capability/health
    "consumed": {"open"},
    "denied": {"open"},
    "cancelled": {"open"},
    "superseded": {"open"},
}

# Capability investment triage. A disposition is the
# supervisor's decision on a missing capability; it maps 1:1 onto the lifecycle status it produces and is stored
# durably beside it (wishlist_items.disposition / .decision).
DISPOSITION_STATUSES = {"provide_now": {"approved", "provided"}, "use_existing_alternative": {"superseded"},
                        "defer_with_trigger": {"deferred"}, "decline": {"denied"}}
STATUS_DISPOSITION = {st: d for d, sts in DISPOSITION_STATUSES.items() for st in sts}
ASSESSMENT_FACTORS = ("expected_value", "time_cost", "storage_cost", "risk", "maintenance")
ASSESSMENT_LEVELS = {"none", "low", "medium", "high"}
# Objective revisit triggers (any-of). Evaluated on request recurrence, at stage transitions, and on an explicit
# supervisor revisit pass; never on every scheduler pass.
TRIGGER_KEYS = {"request_count_at_least", "stage_reached", "material_finding_awaiting_validation",
                "family_members_at_least", "after"}

CAPABILITY_TRANSPORTS = {"mcp_stdio", "mcp_http", "cli", "python", "http_api", "library", "manual", "other"}
CAPABILITY_HEALTH = {"unknown", "healthy", "degraded", "unhealthy"}
# Closed, bounded capability record: field -> max string length (lists: max items x max item length).
CAPABILITY_STR_FIELDS = {"provider": 120, "project": 200, "version": 80, "commit": 80, "transport": 20,
                         "invocation_ref": 300, "config_ref": 300, "provenance_url": 500, "health_status": 20,
                         "license": 80, "storage": 200, "notes": 500}
CAPABILITY_LIST_FIELDS = {"supported_inputs": (16, 80), "supported_outputs": (16, 80)}
CAPABILITY_NUM_FIELDS = {"health_checked_at"}
WISH_TEXT_MAX = 2000
WISH_ITEM_MAX = 200
_CREDENTIAL_URL = re.compile(r"://[^/\s:@]+:[^/\s@]+@")


def normalize_wish_item(item: object) -> str:
    """Normalised identity of a requested item: case/space/punctuation-insensitive, versions kept."""
    return re.sub(r"[^a-z0-9.+@/:]+", "-", str(item or "").strip().lower()).strip("-")[:WISH_ITEM_MAX]


def _secret_like(value: str) -> bool:
    return redact(value) != value or bool(_CREDENTIAL_URL.search(value))


def evaluate_capability(kind: str, capability: object, *, require: bool) -> tuple[dict, list[str]]:
    """Validate a provided-capability record. Returns (clean record, refusal reasons).

    The record is a closed schema of bounded references; it never carries credential values. Reasons name
    fields only, never values, so a refused secret is not copied into the ledger.
    """
    if capability in (None, {}):
        return {}, ([f"provided {kind} requires capability metadata (provider, version|commit, transport, "
                     "invocation_ref|config_ref, provenance_url)"] if require else [])
    if not isinstance(capability, dict):
        return {}, ["capability must be an object"]
    reasons: list[str] = []
    clean: dict[str, Any] = {}
    for key, value in capability.items():
        if key in CAPABILITY_STR_FIELDS:
            if not isinstance(value, str) or not value.strip():
                reasons.append(f"capability.{key} must be a non-empty string")
            elif len(value) > CAPABILITY_STR_FIELDS[key]:
                reasons.append(f"capability.{key} exceeds {CAPABILITY_STR_FIELDS[key]} chars")
            elif _secret_like(value):
                reasons.append(f"capability.{key} looks like a credential; store a config_ref to the supervisor's secret store instead")
            else:
                clean[key] = value.strip()
        elif key in CAPABILITY_LIST_FIELDS:
            n, width = CAPABILITY_LIST_FIELDS[key]
            if not isinstance(value, list) or len(value) > n or not all(isinstance(v, str) and 0 < len(v) <= width for v in value):
                reasons.append(f"capability.{key} must be a list of at most {n} strings of at most {width} chars")
            elif any(_secret_like(v) for v in value):
                reasons.append(f"capability.{key} looks like a credential")
            else:
                clean[key] = list(value)
        elif key in CAPABILITY_NUM_FIELDS:
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                reasons.append(f"capability.{key} must be a non-negative epoch timestamp")
            else:
                clean[key] = float(value)
        else:
            reasons.append(f"capability field {key!r} is not allowed (closed schema; credentials are never stored)")
    if "transport" in clean and clean["transport"] not in CAPABILITY_TRANSPORTS:
        reasons.append(f"capability.transport must be one of {sorted(CAPABILITY_TRANSPORTS)}")
    if "health_status" in clean and clean["health_status"] not in CAPABILITY_HEALTH:
        reasons.append(f"capability.health_status must be one of {sorted(CAPABILITY_HEALTH)}")
    if require:
        for need in (("provider",), ("version", "commit"), ("transport",), ("invocation_ref", "config_ref"), ("provenance_url",)):
            if not any(k in clean for k in need):
                reasons.append(f"provided {kind} capability requires {'|'.join(need)}")
    return clean, reasons


def evaluate_revisit_trigger(trigger: object, *, state: dict) -> tuple[dict, list[str]]:
    """Validate a revisit trigger against current campaign state (it must not already be satisfied)."""
    if not isinstance(trigger, dict) or not trigger:
        return {}, ["revisit_trigger must be an object with at least one of " + ", ".join(sorted(TRIGGER_KEYS))]
    reasons, clean = [], {}
    for key, value in trigger.items():
        if key not in TRIGGER_KEYS:
            reasons.append(f"unknown revisit trigger {key!r}; objective triggers are {sorted(TRIGGER_KEYS)}")
        elif key in {"request_count_at_least", "family_members_at_least"}:
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                reasons.append(f"revisit_trigger.{key} must be a positive integer")
            else:
                clean[key] = value
        elif key == "stage_reached":
            if value not in STAGES:
                reasons.append(f"revisit_trigger.stage_reached must be one of {STAGES}")
            else:
                clean[key] = value
        elif key == "material_finding_awaiting_validation":
            if value is not True:
                reasons.append("revisit_trigger.material_finding_awaiting_validation must be true")
            else:
                clean[key] = True
        elif isinstance(value, bool) or not isinstance(value, (int, float)):
            reasons.append("revisit_trigger.after must be an epoch timestamp")
        else:
            clean[key] = float(value)
    if not reasons:
        fired = fired_triggers(clean, state)
        if fired:
            reasons.append(f"revisit trigger already satisfied ({', '.join(fired)}); choose a future trigger or decide now")
    return clean, reasons


def fired_triggers(trigger: dict, state: dict) -> list[str]:
    """Which triggers hold for ``state`` = {request_count, stage, material_awaiting, max_family_members, now}."""
    fired = []
    if "request_count_at_least" in trigger and state["request_count"] >= trigger["request_count_at_least"]:
        fired.append(f"request_count_at_least={trigger['request_count_at_least']}")
    if "stage_reached" in trigger and STAGES.index(state["stage"]) >= STAGES.index(trigger["stage_reached"]):
        fired.append(f"stage_reached={trigger['stage_reached']}")
    if trigger.get("material_finding_awaiting_validation") and state["material_awaiting"]:
        fired.append("material_finding_awaiting_validation")
    if "family_members_at_least" in trigger and state["max_family_members"] >= trigger["family_members_at_least"]:
        fired.append(f"family_members_at_least={trigger['family_members_at_least']}")
    if "after" in trigger and state["now"] >= trigger["after"]:
        fired.append(f"after={trigger['after']}")
    return fired


def evaluate_wish_resolution(wish: dict, *, to: str, actor: dict, receipt: object, capability: object,
                             superseded_by: dict | None, decision: object, state: dict) -> tuple[dict, dict, list[str]]:
    """Single-supervisor resolution + investment-triage gate.

    Returns (clean capability, clean decision, refusal reasons; empty = accept). Moving an item into
    approved/provided/superseded/deferred/denied is a triage decision and needs a disposition record:
    {disposition (optional; derived from status), rationale, assessment{expected_value,time_cost,storage_cost,
    risk,maintenance}, revisit_trigger (required for defer_with_trigger), alternative_ref}.
    """
    reasons: list[str] = []
    current = wish["status"]
    if actor["kind"] not in OPERATOR_KINDS:
        reasons.append(f"actor kind {actor['kind']} cannot resolve wishlist items; the operator/human supervisor resolves")
    if to not in WISH_STATUSES:
        return {}, {}, reasons + [f"unknown wishlist status {to!r}"]
    if to not in WISH_TRANSITIONS[current]:
        reasons.append(f"illegal wishlist transition {current} -> {to}")
    material = receipt_has_material(receipt)
    summary = isinstance(receipt, dict) and bool(str(receipt.get("summary") or "").strip())
    if to in {"provided", "denied"} and not material:
        reasons.append(f"{to} requires a receipt with evidence_refs, artifact_refs, commands, or source_anchors")
    elif not (material or summary):
        reasons.append("resolution requires a receipt with a summary or evidence")
    clean: dict = {}
    if to == "provided":
        clean, cap_reasons = evaluate_capability(wish["kind"], capability, require=wish["kind"] in CAPABILITY_KINDS)
        reasons.extend(cap_reasons)
    elif capability not in (None, {}):
        reasons.append("capability metadata is only accepted with status provided")
    dec: dict = {}
    triage = to in STATUS_DISPOSITION and not (to == "provided" and current in {"approved", "provided"})  # provide_now already decided
    if not triage:
        if decision not in (None, {}):
            reasons.append(f"a disposition decision is not accepted for {current} -> {to}")
    elif not isinstance(decision, dict):
        reasons.append(f"{to} is a capability-investment decision and requires a decision record "
                       "(rationale, assessment, revisit_trigger when deferring)")
    else:
        disposition = decision.get("disposition") or STATUS_DISPOSITION[to]
        if disposition not in DISPOSITION_STATUSES:
            reasons.append(f"disposition must be one of {sorted(DISPOSITION_STATUSES)}")
        elif to not in DISPOSITION_STATUSES[disposition]:
            reasons.append(f"disposition {disposition} produces status {sorted(DISPOSITION_STATUSES[disposition])}, not {to}")
        unknown = sorted(set(decision) - {"disposition", "rationale", "assessment", "revisit_trigger", "alternative_ref"})
        if unknown:
            reasons.append(f"unknown decision fields {unknown}")
        rationale = redact(str(decision.get("rationale") or "")).strip()
        if not rationale or len(rationale) > WISH_TEXT_MAX:
            reasons.append(f"decision.rationale is required (at most {WISH_TEXT_MAX} chars)")
        assessment = decision.get("assessment")
        if not isinstance(assessment, dict) or set(assessment) != set(ASSESSMENT_FACTORS) \
                or any(v not in ASSESSMENT_LEVELS for v in assessment.values()):
            reasons.append(f"decision.assessment must rate exactly {list(ASSESSMENT_FACTORS)} as {sorted(ASSESSMENT_LEVELS)}")
        trigger: dict = {}
        if decision.get("revisit_trigger") not in (None, {}):
            trigger, trig_reasons = evaluate_revisit_trigger(decision["revisit_trigger"], state=state)
            reasons.extend(trig_reasons)
        elif disposition == "defer_with_trigger":
            reasons.append("defer_with_trigger requires an objective revisit_trigger")
        if disposition == "provide_now" and trigger:
            reasons.append("provide_now does not take a revisit_trigger")
        alternative = decision.get("alternative_ref")
        if alternative is not None and (not isinstance(alternative, str) or not alternative.strip()
                                        or len(alternative) > 300 or _secret_like(alternative)):
            reasons.append("decision.alternative_ref must be a non-secret reference of at most 300 chars")
        if disposition == "use_existing_alternative" and not (superseded_by or alternative):
            reasons.append("use_existing_alternative requires superseded_by (a wishlist item) or decision.alternative_ref")
        dec = {"disposition": disposition, "rationale": rationale, "assessment": assessment, "revisit_trigger": trigger or None,
               "alternative_ref": alternative.strip() if isinstance(alternative, str) else None}
    if superseded_by and superseded_by["id"] == wish["id"]:
        reasons.append("a wishlist item cannot supersede itself")
    return clean, dec, reasons


# --- storage: artifact registry, retention/cleanup, disk pressure (schema v4) -----------------------------------------
#
# One DSR supervisor on the control host (Spark is remote inference only and owns no storage). Artifacts are campaign-scoped registrations of files/directories that live
# under explicitly configured storage roots. Only `managed` roots are ever mutated; `retained` roots (e.g. the verified
# corpus) may be registered but are never touched; the `quarantine` root receives same-filesystem atomic renames.
# See docs/STORAGE-AND-CLEANUP.md.

ROOT_ROLES = {"managed", "retained", "quarantine"}
ARTIFACT_CLASSES = ("canonical", "source", "regenerable", "diagnostic", "ephemeral")
PROTECTED_CLASSES = {"canonical", "source"}  # never part of any cleanup plan, whatever the request says
CLEANABLE_CLASSES = ("ephemeral", "regenerable", "diagnostic")
CLASS_RANK = {"ephemeral": 0, "regenerable": 1, "diagnostic": 2, "source": 3, "canonical": 4}
ARTIFACT_STATES = {"present", "quarantined", "purged", "missing"}
# Closed artifact kind vocabulary -> minimum retention class (registering weaker is refused).
ARTIFACT_KIND_MIN_CLASS = {
    **dict.fromkeys(("state_db", "ledger", "manifest", "checkpoint", "evidence", "validation_receipt",
                     "applicability_decision", "lineage_decision", "closeout"), "canonical"),
    **dict.fromkeys(("firmware", "dump", "representative", "variant", "crash_sample", "harness", "repro_script"), "source"),
    **dict.fromkeys(("extraction_tree", "decompiler_output", "decompiler_db", "embedding", "index", "graph",
                     "rendered_report", "log", "log_segment", "trace", "partial_download", "temp_workspace",
                     "test_cache", "bytecode_cache", "overlay", "debug_artifact", "scratch", "other"), "ephemeral"),
}
ARTIFACT_KINDS = set(ARTIFACT_KIND_MIN_CLASS)
REF_TYPES = {"finding", "job", "artifact", "run", "manifest", "checkpoint", "report", "closeout", "replay", "external"}
HOLD_KINDS = {"lease", "hold"}
STORAGE_INTENTS = {"none", "light", "heavy"}  # only an explicitly declared `heavy` intent is pressure-gated
PRESSURE_LEVELS = ("normal", "high", "critical", "emergency")
# level -> (storage-heavy claims may start, existing storage-heavy work should pause, emergency stop before exhaustion)
PRESSURE_GUIDANCE = {"normal": (True, False, False), "high": (False, False, False),
                     "critical": (False, True, False), "emergency": (False, True, True)}
DEFAULT_THRESHOLDS = {
    "high": {"min_free_fraction": 0.15, "min_free_bytes": 0},
    "critical": {"min_free_fraction": 0.08, "min_free_bytes": 0},
    "emergency": {"min_free_fraction": 0.03, "min_free_bytes": 1 << 30},
    "max_sample_age_s": 900,
}
CLEANUP_POLICY_DEFAULTS: dict[str, Any] = {
    "classes": list(CLEANABLE_CLASSES),
    "min_age_s": {"ephemeral": 3600, "regenerable": 86400, "diagnostic": 7 * 86400},
    "evidence_diagnostic_min_age_s": 30 * 86400,  # diagnostics linked to findings/evidence are kept longer
    "quarantine_retention_s": 86400,  # purge is refused until a quarantined body has aged this long
    "max_candidates": 500,
    "target_reclaim_bytes": None,
    "hash_verify_max_bytes": 256 << 20,  # files up to this size are re-hashed at apply/restore/purge
}
STORAGE_TEXT_MAX = 2000
STORAGE_REF_MAX = 500
LABELS_MAX = 16


def storage_text(value: object, field: str, limit: int = STORAGE_TEXT_MAX) -> str:
    """Redacted, bounded, non-empty free text (structural error otherwise)."""
    text = redact(str(value or "")).strip()
    if not text:
        raise ValueError(f"storage {field} required")
    if len(text) > limit:
        raise ValueError(f"storage {field} exceeds {limit} chars")
    return text


def storage_ref_reasons(value: object, field: str, limit: int = STORAGE_REF_MAX) -> list[str]:
    """A reference (path/command/config name) must be a bounded string with no credential-looking content.
    Reasons name the field only so a refused secret is never copied into the ledger."""
    if not isinstance(value, str) or not value.strip():
        return [f"{field} must be a non-empty string"]
    if len(value) > limit:
        return [f"{field} exceeds {limit} chars"]
    if _secret_like(value):
        return [f"{field} looks like a credential; store a reference to the supervisor's secret store instead"]
    return []


def evaluate_provenance(producer: object) -> tuple[dict, list[str], list[str]]:
    """Producer/provenance record. Returns (clean, refusal reasons, missing-for-rebuild list).

    Regenerable eligibility needs the generator identity (tool + version|commit), every input's sha256, the config
    hash, and a rebuild reference; the output hash is the artifact's own sha256. Missing pieces do not refuse the
    registration, they make the artifact ineligible for cleanup (fail closed)."""
    if producer in (None, {}):
        return {}, [], ["tool", "version|commit", "inputs", "config_sha256", "rebuild_ref"]
    if not isinstance(producer, dict):
        return {}, ["producer must be an object"], []
    allowed = {"tool", "version", "commit", "config_ref", "config_sha256", "rebuild_ref", "inputs", "actor"}
    reasons = [f"producer field {k!r} is not allowed (closed schema)" for k in sorted(set(producer) - allowed)]
    clean: dict[str, Any] = {}
    for key in ("tool", "version", "commit", "config_ref", "rebuild_ref", "actor"):
        if key in producer:
            bad = storage_ref_reasons(producer[key], f"producer.{key}", 300)
            reasons += bad
            if not bad:
                clean[key] = producer[key].strip()
    if "config_sha256" in producer:
        if normalize_sha256(producer["config_sha256"]):
            clean["config_sha256"] = normalize_sha256(producer["config_sha256"])
        else:
            reasons.append("producer.config_sha256 must be sha256 hex")
    if "inputs" in producer:
        inputs = producer["inputs"]
        if not isinstance(inputs, list) or len(inputs) > 64:
            reasons.append("producer.inputs must be a list of at most 64 input references")
        else:
            clean_inputs = []
            for i, item in enumerate(inputs):
                if not isinstance(item, dict) or set(item) - {"artifact_id", "sha256", "ref"}:
                    reasons.append(f"producer.inputs[{i}] must be {{artifact_id?, sha256?, ref?}}")
                    continue
                entry = {}
                if item.get("sha256") is not None:
                    if not normalize_sha256(item["sha256"]):
                        reasons.append(f"producer.inputs[{i}].sha256 must be sha256 hex")
                        continue
                    entry["sha256"] = normalize_sha256(item["sha256"])
                for key in ("artifact_id", "ref"):
                    if item.get(key) is not None:
                        bad = storage_ref_reasons(item[key], f"producer.inputs[{i}].{key}", 300)
                        reasons += bad
                        if not bad:
                            entry[key] = item[key].strip()
                if not entry.get("artifact_id") and not entry.get("sha256"):
                    reasons.append(f"producer.inputs[{i}] needs artifact_id or sha256")
                    continue
                clean_inputs.append(entry)
            clean["inputs"] = clean_inputs
    missing = [name for name, ok in (
        ("tool", "tool" in clean), ("version|commit", "version" in clean or "commit" in clean),
        ("inputs", bool(clean.get("inputs"))), ("config_sha256", "config_sha256" in clean),
        ("rebuild_ref", "rebuild_ref" in clean)) if not ok]
    return clean, reasons, missing


def evaluate_cleanup_policy(policy: object) -> tuple[dict, list[str]]:
    """Normalise a cleanup policy over CLEANUP_POLICY_DEFAULTS. Returns (snapshot, refused_classes).

    Unknown keys / bad values are structural errors (raise). Requested canonical/source classes are not an error:
    they are stripped and reported, because protected material is never eligible whatever the request says."""
    if policy is None:
        policy = {}
    if not isinstance(policy, dict):
        raise ValueError("cleanup policy must be an object")
    unknown = sorted(set(policy) - set(CLEANUP_POLICY_DEFAULTS))
    if unknown:
        raise ValueError(f"unknown cleanup policy keys: {unknown}")
    out = json.loads(canonical_json(CLEANUP_POLICY_DEFAULTS))
    refused: list[str] = []
    if "classes" in policy:
        classes = policy["classes"]
        if not isinstance(classes, list) or not classes or any(c not in ARTIFACT_CLASSES for c in classes):
            raise ValueError(f"cleanup policy classes must be a non-empty list drawn from {list(ARTIFACT_CLASSES)}")
        refused = sorted({c for c in classes if c in PROTECTED_CLASSES})
        out["classes"] = [c for c in CLEANABLE_CLASSES if c in classes]
    if "min_age_s" in policy:
        ages = policy["min_age_s"]
        if not isinstance(ages, dict) or set(ages) - set(CLEANABLE_CLASSES):
            raise ValueError(f"cleanup policy min_age_s keys must be drawn from {list(CLEANABLE_CLASSES)}")
        out["min_age_s"].update(ages)
    for key in ("evidence_diagnostic_min_age_s", "quarantine_retention_s", "max_candidates", "hash_verify_max_bytes"):
        if key in policy:
            out[key] = policy[key]
    if policy.get("target_reclaim_bytes") is not None:
        out["target_reclaim_bytes"] = policy["target_reclaim_bytes"]
    nums = [*out["min_age_s"].values(), out["evidence_diagnostic_min_age_s"], out["quarantine_retention_s"],
            out["max_candidates"], out["hash_verify_max_bytes"]] + ([out["target_reclaim_bytes"]] if out["target_reclaim_bytes"] is not None else [])
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0 for v in nums):
        raise ValueError("cleanup policy ages/limits must be non-negative numbers")
    if not 1 <= out["max_candidates"] <= 10_000:
        raise ValueError("cleanup policy max_candidates must be within 1..10000")
    return out, refused


def evaluate_thresholds(thresholds: object) -> dict:
    """Merge + validate disk-pressure thresholds; levels must be monotonic (emergency strictest)."""
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be an object")
    unknown = sorted(set(thresholds) - set(DEFAULT_THRESHOLDS))
    if unknown:
        raise ValueError(f"unknown threshold keys: {unknown}")
    out = json.loads(canonical_json(DEFAULT_THRESHOLDS))
    for level in PRESSURE_LEVELS[1:]:
        spec = thresholds.get(level)
        if spec is None:
            continue
        if not isinstance(spec, dict) or set(spec) - {"min_free_fraction", "min_free_bytes"}:
            raise ValueError(f"threshold {level} must be {{min_free_fraction, min_free_bytes}}")
        out[level].update(spec)
    if "max_sample_age_s" in thresholds:
        out["max_sample_age_s"] = thresholds["max_sample_age_s"]
    for level in PRESSURE_LEVELS[1:]:
        frac, free = out[level]["min_free_fraction"], out[level]["min_free_bytes"]
        if isinstance(frac, bool) or not isinstance(frac, (int, float)) or not 0 <= frac < 1:
            raise ValueError(f"threshold {level}.min_free_fraction must be within [0, 1)")
        if isinstance(free, bool) or not isinstance(free, int) or free < 0:
            raise ValueError(f"threshold {level}.min_free_bytes must be a non-negative integer")
    # fractions must tighten toward emergency; byte floors are independent (0 = no floor for that level)
    if not out["high"]["min_free_fraction"] >= out["critical"]["min_free_fraction"] >= out["emergency"]["min_free_fraction"]:
        raise ValueError("thresholds must be monotonic: high.min_free_fraction >= critical >= emergency")
    age = out["max_sample_age_s"]
    if isinstance(age, bool) or not isinstance(age, (int, float)) or age <= 0:
        raise ValueError("max_sample_age_s must be a positive number")
    return out


def pressure_level(total: int, free: int, thresholds: dict) -> str:
    """Strictest level whose condition holds: free fraction below min_free_fraction OR free bytes below min_free_bytes."""
    frac = (free / total) if total > 0 else 0.0
    level = "normal"
    for name in PRESSURE_LEVELS[1:]:
        spec = thresholds[name]
        if frac < spec["min_free_fraction"] or free < spec["min_free_bytes"]:
            level = name
    return level
