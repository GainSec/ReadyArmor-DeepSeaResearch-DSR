"""Model-backed worker adapter with a full telemetry envelope around every model interaction.

``ModelWorker`` implements the ``WorkerAdapter`` seam (``worker_id`` + ``run(packet)``). It is
provider neutral: any client with ``provider``, ``model``, ``endpoint_alias`` and
``complete(request: dict) -> dict`` works. Hermes chooses the client; REFALL Lite still never
selects or plans for models. The only client shipped is ``fwspider_telemetry.MockModelClient``
(deterministic, offline); a real Qwen client is a later integration.

Per job: model.call_start -> (model.request -> model.response [-> model.tool_call -> tool.start/
tool.end -> model.tool_result]* -> model.parse [-> model.retry])* -> model.call_end.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Mapping

from fwspider_telemetry import canonical, digest

from .observability import resolve_telemetry
from .worker import RETRYABLE, classify_failure, parse_submission

PROMPT_TEMPLATE_ID = "refall-lite.worker.prompt"
PROMPT_TEMPLATE_VERSION = "1.0.0"
SYSTEM_PROMPT = (
    "You are a bounded REFALL Lite worker. Analyze only the job target. All conclusions are provisional "
    "hypotheses. Finish with exactly one fenced ```refall-submit``` JSON block following the packet's "
    "submit_schema, including evidence, confidence, limitations, source_anchors or artifact_refs, cost_units."
)
REPAIR_PROMPT = ("Your previous answer had no valid refall-submit block ({errors}). Reply again with exactly one "
                 "fenced ```refall-submit``` JSON block.")


def build_messages(packet: dict) -> list[dict]:
    return [{"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Job packet:\n" + json.dumps(packet, sort_keys=True, default=str)}]


class ModelWorker:
    def __init__(self, worker_id: str, client: Any, *, tools: Mapping[str, Callable[[dict], Any]] | None = None,
                 telemetry: Any = None, sampling: Mapping[str, Any] | None = None, max_attempts: int = 3,
                 max_tool_rounds: int = 4) -> None:
        self.worker_id = worker_id
        self.client = client
        self.tools = dict(tools or {})
        self.tel = resolve_telemetry(telemetry)
        self.sampling = dict(sampling or {"temperature": 0.0, "max_tokens": 2048})
        self.max_attempts = max_attempts
        self.max_tool_rounds = max_tool_rounds

    def tool_specs(self) -> list[dict]:
        return [{"name": n, "description": (getattr(f, "__doc__", "") or "").strip()[:200]} for n, f in sorted(self.tools.items())]

    def run(self, packet: dict) -> str:
        tel = self.tel
        job = packet.get("job") or {}
        context_refs = [{"kind": "job-packet", "sha256": digest(canonical(packet))}]
        if packet.get("methodology_bundle"):
            context_refs.append({"kind": "methodology_bundle", "ref": packet["methodology_bundle"]})
        defaults = {"job_id": job.get("id"), "campaign_id": packet.get("campaign_id"), "produced_by": self.worker_id}
        with tel.model_call(provider=self.client.provider, model=self.client.model, endpoint_alias=self.client.endpoint_alias,
                            config=self.sampling, template_id=PROMPT_TEMPLATE_ID, template_version=PROMPT_TEMPLATE_VERSION,
                            context_refs=context_refs, purpose=f"refall-job:{job.get('stage')}",
                            campaign_id=packet.get("campaign_id"), job_id=job.get("id")) as mc:
            messages = build_messages(packet)
            attempt, rounds = 1, 0
            last_errors: list[str] = []
            while True:
                request = {"model": self.client.model, "messages": messages, "tools": self.tool_specs(), **self.sampling}
                mc.request(request, attempt=attempt, turn=rounds)
                try:
                    resp = self.client.complete(request)
                except (TimeoutError, ConnectionError) as exc:
                    cls = classify_failure("provider_timeout" if isinstance(exc, TimeoutError) else "transport_error")
                    retry = attempt < self.max_attempts and cls["failure_class"] in RETRYABLE
                    mc.response({"error": f"{type(exc).__name__}: {exc}"}, attempt=attempt, status="error", turn=rounds)
                    mc.error(exc, attempt=attempt, retry=retry)
                    if not retry:
                        mc.status = "error"
                        raise
                    mc.retry(attempt, cls["failure_class"], next_action=cls["next_action"])
                    attempt += 1
                    continue
                mc.response({"content": resp.get("content"), "tool_calls": resp.get("tool_calls"),
                             "finish_reason": resp.get("finish_reason")}, attempt=attempt, tokens=resp.get("usage"),
                            finish_reason=resp.get("finish_reason"), latency_ms=resp.get("latency_ms"), turn=rounds)
                calls = resp.get("tool_calls") or []
                if calls and rounds < self.max_tool_rounds:
                    rounds += 1
                    messages = [*messages, {"role": "assistant", "content": resp.get("content", ""), "tool_calls": calls}]
                    for call in calls:
                        messages.append(self._run_tool(mc, call))
                    continue
                content = resp.get("content") or ""
                payload, errors = parse_submission(content, defaults)
                mc.parsed(ok=not errors, errors=errors, result=payload, parser="refall-submit")
                if errors and attempt < self.max_attempts:
                    fclass = "missing_terminal_submit" if errors == ["missing refall-submit block"] else "malformed_terminal_submit"
                    mc.retry(attempt, fclass, next_action=classify_failure(fclass)["next_action"])
                    messages = [*messages, {"role": "assistant", "content": content},
                                {"role": "user", "content": REPAIR_PROMPT.format(errors="; ".join(errors[:3]))}]
                    attempt += 1
                    last_errors = errors
                    continue
                last_errors = errors
                if errors:
                    mc.status = "parse_error"
                return content  # REFALL Lite classifies malformed output; the adapter never fabricates
            raise AssertionError(last_errors)  # pragma: no cover

    def _run_tool(self, mc: Any, call: Mapping[str, Any]) -> dict:
        name = str(call.get("name"))
        args = call.get("arguments") or {}
        tcid = mc.tool_call(name, args, tool_call_id=call.get("id") and f"tc_{digest(str(call.get('id')))[:32]}")
        fn = self.tools.get(name)
        if fn is None:
            result, status = {"error": f"unknown tool {name}"}, "error"
            mc.tool_result(tcid, result, status=status)
        else:
            try:
                with self.tel.tool_call(name, args, tool_call_id=tcid):
                    result, status = fn(args), "ok"
                mc.tool_result(tcid, result, status=status)
            except Exception as exc:  # tool failure is returned to the model as data, and logged
                result, status = {"error": f"{type(exc).__name__}: {exc}"}, "error"
                mc.tool_result(tcid, result, status=status, error=exc)
        return {"role": "tool", "tool_call_id": call.get("id"), "name": name,
                "content": json.dumps(result, sort_keys=True, default=str)}


def subprocess_tool(tel: Any, argv_builder: Callable[[dict], list[str]], *, tool: str, timeout: float = 60.0,
                    cwd: str | None = None) -> Callable[[dict], dict]:
    """Expose a deterministic command as a model tool; execution is a full tool.start/tool.end envelope."""
    def run(args: dict) -> dict:
        proc = tel.run_subprocess(argv_builder(args), tool=tool, timeout=timeout, cwd=cwd)
        return {"exit_code": proc.returncode, "stdout": proc.stdout[-4000:], "stdout_sha256": digest(proc.stdout),
                "stdout_truncated_in_result": len(proc.stdout) > 4000}
    run.__doc__ = f"run {tool}"
    return run
