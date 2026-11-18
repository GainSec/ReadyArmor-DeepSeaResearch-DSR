"""REFALL Lite <-> fwspider_telemetry glue.

* Every ArcticBase ledger append is buffered inside its transaction and emitted as a
  canonical event (``<domain>.<action>``) only after COMMIT; a ROLLBACK emits
  ``state.rollback`` listing what was discarded. Canonical state is never changed by telemetry.
* Every public ``RefallLite`` operation is wrapped: ``api.call`` (pre-operation, critical:
  refused under the strict policy if it cannot be recorded) -> ``api.result`` / ``api.error``.
  Read-only operations are recorded only in debug mode. Nested calls are not re-logged
  (except in debug mode) so one API call = one envelope.
"""
from __future__ import annotations

import functools
import inspect
import time
from contextvars import ContextVar
from typing import Any, Callable

from fwspider_telemetry import SCHEMA, TAXONOMY, NullTelemetry, Telemetry, digest, get_telemetry

COMPONENT = "refall-lite"
KIND_DOMAIN: dict[str, str] = SCHEMA["ledger_kind_domains"]

# Read-only operations: debug-level envelopes only.
READ_OPS = {
    "actor", "list_actors", "get_campaign", "list_campaigns", "get_pending_action", "list_pending_actions", "budget_usage",
    "get_job", "list_jobs", "job_packet", "get_manifest", "list_checkpoints", "resume_preflight", "status", "get_image", "list_images",
    "get_member", "member_occurrences", "get_finding", "list_findings", "finding_occurrences", "list_transitions",
    "get_report", "get_closeout", "lineage_config", "get_code_unit", "list_code_units", "unit_observations", "get_edge",
    "list_similarity_edges", "get_family", "list_families", "family_of", "list_delta_jobs", "list_analysis_receipts",
    "list_delta_receipts", "list_reuse", "lineage", "reusable_knowledge", "get_applicability", "list_applicability",
    "attack_chain", "store_info", "ledger", "verify_ledger", "get_wish", "list_wishes", "get_artifact", "list_artifacts",
    "list_storage_roots", "storage_thresholds", "storage_inventory", "storage_status", "get_cleanup_plan",
    "list_cleanup_plans", "validate_cleanup_plan", "preview_cleanup",
}
# Gate evaluations are reads but are workflow decisions: always recorded.
GATE_OPS = {"stage_gate", "closeout_gate"}
ARG_IDS = {"cid": "campaign_id", "campaign_id": "campaign_id", "job_id": "job_id", "finding_id": "finding_id",
           "member_sha256": "artifact_id", "sha256": "artifact_id"}
_depth: ContextVar[int] = ContextVar("refall_lite_api_depth", default=0)


def resolve_telemetry(telemetry: Telemetry | bool | None) -> Telemetry:
    if telemetry is False:
        return NullTelemetry(COMPONENT)
    if telemetry is None or telemetry is True:
        from . import __version__
        return get_telemetry(COMPONENT, version=__version__)
    return telemetry


def ledger_event_type(kind: str, action: str) -> str:
    et = f"{KIND_DOMAIN.get(kind, kind)}.{action}"
    return et if et in TAXONOMY else "ledger.unmapped"


def _artifact_id(value: Any) -> str | None:
    if isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value):
        return f"sha256:{value}"
    return None


def ledger_ids(campaign_id: str, payload: dict) -> dict:
    ids = {"campaign_id": campaign_id,
           "job_id": payload.get("job_id") or payload.get("source_job_id"),
           "finding_id": payload.get("finding_id") or payload.get("source_finding_id"),
           "artifact_id": next((a for a in (_artifact_id(payload.get(k)) for k in
                                ("member_sha256", "content_sha256", "image_sha256", "sha256")) if a), None)}
    if not ids["artifact_id"] and payload.get("image_id"):
        ids["artifact_id"] = str(payload["image_id"])
    return {k: v for k, v in ids.items() if isinstance(v, str) and v}


def emit_ledger(tel: Telemetry, entry: dict, payload: dict) -> None:
    et = ledger_event_type(entry["kind"], entry["action"])
    tel.emit(et, {"ledger_kind": entry["kind"], "ledger_action": entry["action"], "ledger_seq": entry.get("seq"),
                  "entry_hash": entry.get("entry_hash"), "prev_hash": entry.get("prev_hash"), "actor": entry.get("actor"),
                  "ledger_entry_id": entry.get("id"), "payload": payload},
             message=f"{entry['kind']}/{entry['action']}", component="refall-lite.arcticbase",
             **ledger_ids(entry["campaign_id"], payload))


def _summary(result: Any) -> dict:
    out: dict[str, Any] = {"type": type(result).__name__}
    if isinstance(result, dict):
        for k in ("id", "accepted", "claimed", "passed", "advanced", "status", "reason", "enqueued", "deduplicated",
                  "finding_ids", "reclaimed", "errors", "reasons", "merged", "image_id", "new_members", "state", "outcome",
                  "wishlist_blocked", "storage_paused", "executed", "idempotent", "level", "emergency_stop", "sample_id"):
            if k in result:
                out[k] = result[k]
        if isinstance(result.get("job"), dict):
            out["job"] = {k: result["job"].get(k) for k in ("id", "status", "attempts", "stage")}
        if isinstance(result.get("finding"), dict):
            out["finding"] = {k: result["finding"].get(k) for k in ("id", "tier", "severity")}
        if isinstance(result.get("wish"), dict):
            out["wish"] = {k: result["wish"].get(k) for k in ("id", "kind", "status", "request_count")}
        if isinstance(result.get("artifact"), dict):
            out["artifact"] = {k: result["artifact"].get(k) for k in ("id", "retention_class", "state", "sha256", "size_bytes")}
        if isinstance(result.get("plan"), dict):
            out["plan"] = {k: result["plan"].get(k) for k in ("id", "status", "expected_reclaim_bytes", "plan_sha256")}
    elif isinstance(result, list):
        out["length"] = len(result)
    return out


def _wrap(name: str, fn: Callable) -> Callable:
    sig = inspect.signature(fn)
    level = "debug" if name in READ_OPS else None

    @functools.wraps(fn)
    def wrapper(self, *args: Any, **kwargs: Any) -> Any:
        tel: Telemetry = self.telemetry
        depth = _depth.get()
        if depth and not tel.config.debug:
            token = _depth.set(depth + 1)
            try:
                return fn(self, *args, **kwargs)
            finally:
                _depth.reset(token)
        try:
            bound = sig.bind(self, *args, **kwargs)
            arguments = {k: v for k, v in bound.arguments.items() if k != "self"}
        except TypeError:
            arguments = {"args": list(args), "kwargs": kwargs}
        ids = {}
        for arg, field in ARG_IDS.items():
            v = arguments.get(arg)
            if isinstance(v, str) and v:
                ids[field] = _artifact_id(v) or v if field == "artifact_id" else v
        lvl = "debug" if depth else level
        t0 = time.monotonic_ns()
        start = tel.emit("api.call", {"operation": name, "arguments": arguments, "nested": bool(depth)}, level=lvl,
                         critical=True, component="refall-lite.api", **ids)
        token = _depth.set(depth + 1)
        try:
            with tel.bind(parent_event_id=(start or {}).get("event_id"), **ids):
                result = fn(self, *args, **kwargs)
        except BaseException as exc:
            tel.exception(exc, event_type="api.error",
                          data={"operation": name, "duration_ms": round((time.monotonic_ns() - t0) / 1e6, 3)},
                          parent_event_id=(start or {}).get("event_id"), **ids)
            raise
        finally:
            _depth.reset(token)
        tel.emit("api.result", {"operation": name, "duration_ms": round((time.monotonic_ns() - t0) / 1e6, 3),
                                "result_sha256": digest(result if isinstance(result, (str, bytes)) else
                                                        __import__("json").dumps(result, sort_keys=True, default=str)),
                                "result": _summary(result), **({"result_full": result} if tel.config.debug else {})},
                 level=lvl, component="refall-lite.api", parent_event_id=(start or {}).get("event_id"), **ids)
        return result
    wrapper.__fwspider_instrumented__ = True  # type: ignore[attr-defined]
    return wrapper


def instrument_api(cls: type) -> type:
    """Wrap every public method defined on cls and its mixins (excluding lifecycle dunders)."""
    for klass in reversed(cls.__mro__):
        for name, fn in list(vars(klass).items()):
            if name.startswith("_") or not inspect.isfunction(fn) or name in {"close"}:
                continue
            current = getattr(cls, name)
            if getattr(current, "__fwspider_instrumented__", False):
                continue
            setattr(cls, name, _wrap(name, current))
    return cls


def instrumented_operations(cls: type) -> list[str]:
    return sorted(n for n in dir(cls) if not n.startswith("_") and getattr(getattr(cls, n), "__fwspider_instrumented__", False))
