"""Provider-neutral worker protocol and adapter seam.

Adapted from REFALL-V11 ``ref_all_executor/structured_submit.py`` (fenced
``refall-submit`` envelope, required fields, never-fabricate backfill),
``runtime_invocation.py`` (failure taxonomy) and ``contract_payloads.py``.

The seam is deliberately thin: an adapter is anything with ``worker_id`` and
``run(packet) -> str | dict``. Hermes chooses which adapter/model to use and
when to call ``run_one``; REFALL Lite never selects or plans for models.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Protocol, runtime_checkable

SUBMIT_SCHEMA = "refall-lite.submit.v1"
LEGACY_SCHEMA = "refall.submit.v1"
SUBMIT_RE = re.compile(r"```refall-submit\s*\n(.*?)\n```", re.DOTALL | re.IGNORECASE)
SUBMIT_TYPES = {"job_result", "failure"}
LEGACY_TYPES = {"task_result_submit": "job_result", "finding_submit": "job_result", "evidence_delta_submit": "job_result"}
BACKFILL_FIELDS = ("job_id", "campaign_id", "produced_by")

RETRYABLE = {
    "provider_timeout", "provider_rate_limited", "provider_unavailable", "transport_error", "session_lost",
    "output_truncated", "missing_terminal_submit", "malformed_terminal_submit", "lease_expired", "unknown_failure",
}
NON_RETRYABLE = {"capability_missing", "scope_blocked", "operator_stop", "tool_execution_error", "plan_validation_error", "submission_validation_error", "transport_ambiguous", "budget_exhausted", "tool_error", "evidence_blocked", "endpoint_unavailable"}


def classify_failure(status: str) -> dict:
    s = str(status or "").strip().lower()
    if s in RETRYABLE | NON_RETRYABLE:
        cls = s
    elif "truncat" in s or "length" in s:
        cls = "output_truncated"
    elif "capability" in s:
        cls = "capability_missing"
    elif "scope" in s:
        cls = "scope_blocked"
    elif "operator" in s and "stop" in s:
        cls = "operator_stop"
    elif "tool" in s:
        cls = "tool_execution_error"
    elif "transport" in s or "connection" in s:
        cls = "transport_error"
    elif "unavailable" in s:
        cls = "provider_unavailable"
    elif "timeout" in s:
        cls = "provider_timeout"
    elif "rate" in s or "429" in s:
        cls = "provider_rate_limited"
    elif "lost" in s:
        cls = "session_lost"
    else:
        cls = "unknown_failure"
    retryable = cls in RETRYABLE
    nxt = ("bounded_plan_correction_required" if cls == "plan_validation_error"
           else "retry_with_repair_prompt" if cls in {"missing_terminal_submit", "malformed_terminal_submit"}
           else "retry_with_compact_submit" if cls == "output_truncated"
           else "retry_provider" if retryable else "operator_attention")
    return {"failure_class": cls, "retryable": retryable, "next_action": nxt}


def backfill_envelope(payload: dict, defaults: dict) -> dict:
    """Fill only loop-owned bookkeeping. Evidence is never fabricated: bare
    source_anchors may be restructured into evidence entries, nothing more."""
    out = dict(payload)
    for key in BACKFILL_FIELDS:
        if not out.get(key) and defaults.get(key):
            out[key] = defaults[key]
    if out.get("type") == "job_result":
        out.setdefault("limitations", [])
        if not out.get("confidence"):
            out["confidence"] = "low"
        if not out.get("evidence"):
            anchors = [a for a in out.get("source_anchors") or [] if isinstance(a, str) and a.strip()]
            if anchors:
                claim = str(out.get("summary") or "").strip() or "worker submission"
                out["evidence"] = [{"kind": "source_anchor", "ref": a, "claim": claim} for a in anchors]
    return out


def _normalize_legacy(payload: dict) -> dict:
    if payload.get("schema") != LEGACY_SCHEMA:
        return payload
    out = dict(payload)
    out["type"] = LEGACY_TYPES.get(str(payload.get("type")), payload.get("type"))
    if not out.get("job_id"):
        out["job_id"] = payload.get("task_id") or payload.get("unit_id")
    return out


def validate_submission(p: dict) -> list[str]:
    errors = []
    for key in ("schema", "type", "status", "summary", "job_id", "produced_by"):
        if not p.get(key):
            errors.append(f"missing required field: {key}")
    if p.get("schema") not in {SUBMIT_SCHEMA, LEGACY_SCHEMA}:
        errors.append(f"unsupported schema: {p.get('schema')}")
    if p.get("type") not in SUBMIT_TYPES:
        errors.append(f"unsupported submit type: {p.get('type')}")
    if "cost_units" in p:
        c = p["cost_units"]
        if not isinstance(c, (int, float)) or isinstance(c, bool) or c < 0:
            errors.append("cost_units must be a non-negative number")
    if p.get("type") == "job_result":
        if not p.get("evidence"):
            errors.append("evidence-bearing submission requires evidence")
        if not p.get("confidence"):
            errors.append("evidence-bearing submission requires confidence")
        if not isinstance(p.get("limitations"), list):
            errors.append("evidence-bearing submission requires limitations list")
        if not (p.get("source_anchors") or p.get("artifact_refs")):
            errors.append("evidence-bearing submission requires source_anchors or artifact_refs")
        if p.get("findings") is not None and not isinstance(p.get("findings"), list):
            errors.append("findings must be a list")
    return errors


_HEX_LITERAL_RE = re.compile(r"(?<=[\[\s,:])0x[0-9A-Fa-f]+")


def _salvage_json_hex(block: str) -> str:
    """Quote bare hex literals in JSON value position so json.loads accepts them.

    The brain sometimes emits e.g. `"from":0x105178` in xrefs/offsets, which is
    invalid JSON and drops the WHOLE submission (losing real findings). Quoting the
    literal (-> "0x105178") parses; downstream checkers accept hex addresses as
    strings. Only runs after a strict json.loads has already failed.
    """
    return _HEX_LITERAL_RE.sub(lambda m: '"' + m.group(0) + '"', block)


def parse_submission(submission: dict | str, defaults: dict | None = None) -> tuple[dict | None, list[str]]:
    if isinstance(submission, dict):
        payload: Any = submission
    else:
        blocks = SUBMIT_RE.findall(submission or "")
        if not blocks:
            return None, ["missing refall-submit block"]
        try:
            payload = json.loads(blocks[-1])
        except json.JSONDecodeError:
            try:  # models emit bare hex literals (0x105178) in xrefs/offsets -> salvage
                payload = json.loads(_salvage_json_hex(blocks[-1]))
            except json.JSONDecodeError as exc:
                return None, [f"malformed refall-submit JSON: {exc}"]
    if not isinstance(payload, dict):
        return None, ["refall-submit payload must be an object"]
    payload = _normalize_legacy(payload)
    payload = backfill_envelope(payload, defaults or {})
    return payload, validate_submission(payload)


def result_payload(*, summary: str, evidence: list[dict], confidence: str, artifact_refs: list[str] | None = None,
                   source_anchors: list[str] | None = None, limitations: list[str] | None = None,
                   findings: list[dict] | None = None, cost_units: float = 1, status: str = "done") -> dict:
    """Worker-side helper (adapted from REFALL contract_payloads.task_result_submit)."""
    return {"schema": SUBMIT_SCHEMA, "type": "job_result", "status": status, "summary": summary,
            "evidence": evidence, "confidence": confidence, "artifact_refs": artifact_refs or [],
            "source_anchors": source_anchors or [], "limitations": limitations or [], "findings": findings or [],
            "cost_units": cost_units}


def render_submission(payload: dict) -> str:
    return "```refall-submit\n" + json.dumps(payload, sort_keys=True) + "\n```"


@runtime_checkable
class WorkerAdapter(Protocol):
    worker_id: str

    def run(self, packet: dict) -> str | dict: ...


class CallableWorker:
    """Wrap any callable (Hermes->Qwen client, Claude/Codex CLI shim, deterministic tool)."""

    def __init__(self, worker_id: str, fn: Callable[[dict], str | dict]) -> None:
        self.worker_id = worker_id
        self.fn = fn

    def run(self, packet: dict) -> str | dict:
        return self.fn(packet)


def _exception_status(exc: BaseException) -> str:
    if isinstance(exc, TimeoutError):
        return "provider_timeout"
    if isinstance(exc, ConnectionError):
        return "transport_error"
    return f"{type(exc).__name__}: {exc}"


def run_one(lite: Any, campaign_id: str, adapter: WorkerAdapter, *, stage: str | None = None) -> dict:
    """Single bounded step: claim -> packet -> adapter.run -> submit/fail. No looping, no planning.

    Telemetry: worker.run_start (packet artifact) -> [adapter's model/tool events] -> worker.run_end,
    or worker.run_error with the redacted exception and the failure classification/retry decision.
    """
    from .observability import resolve_telemetry
    tel = getattr(lite, "telemetry", None) or resolve_telemetry(None)
    claim = lite.claim_job(campaign_id, worker=adapter.worker_id, stage=stage)
    if not claim["claimed"]:
        tel.emit("worker.idle", {"worker_id": adapter.worker_id, "stage": stage, "reason": claim["reason"]},
                 campaign_id=campaign_id, component="refall-lite.worker")
        return {"claimed": False, "accepted": False, "reason": claim["reason"]}
    job = claim["job"]
    with tel.bind(campaign_id=campaign_id, job_id=job["id"]):
        packet = lite.job_packet(campaign_id, job["id"])
        start = tel.emit("worker.run_start", {"worker_id": adapter.worker_id, "adapter": type(adapter).__name__,
                                              "stage": job["stage"], "kind": job["kind"], "attempt": job["attempts"],
                                              "packet": tel.artifact("job-packet", packet)},
                         component="refall-lite.worker")
        with tel.bind(parent_event_id=(start or {}).get("event_id")):
            try:
                output = adapter.run(packet)
            except Exception as exc:  # adapter/provider failure is data, not a crash
                status = _exception_status(exc)
                tel.exception(exc, event_type="worker.run_error", retry=classify_failure(status),
                              data={"worker_id": adapter.worker_id}, component="refall-lite.worker")
                res = lite.fail_job(campaign_id, job["id"], job["claim_token"], status=status, error=str(exc))
                return {"claimed": True, **res, "accepted": False, "failure_recorded": res["accepted"]}
            res = lite.submit_result(campaign_id, job["id"], job["claim_token"], output)
            tel.emit("worker.run_end", {"worker_id": adapter.worker_id, "accepted": res["accepted"],
                                        "errors": res.get("errors"), "finding_ids": res.get("finding_ids"),
                                        "output": tel.artifact("worker-output", output)},
                     level="info" if res["accepted"] else "warning", component="refall-lite.worker")
    return {"claimed": True, **res}
