"""Model-call envelope: provider-neutral logging of every request/response/tool call/retry/parse.

Usage::

    with tel.model_call(provider="qwen", model="qwen3", endpoint_alias="spark-qwen", config={...},
                        template_id="refall-lite.worker", template_version="1.0.0",
                        context_refs=[...]) as mc:
        mc.request(body, attempt=1)
        resp = client.complete(body)
        mc.response(resp_body, attempt=1, tokens={...}, finish_reason="stop", status="ok")
        tcid = mc.tool_call("name", args)
        mc.tool_result(tcid, result, status="ok")
        mc.parsed(ok=True, errors=[])

Bodies are redacted and stored as bounded artifacts unless ``log_bodies`` is off; hashes
and lengths are always recorded.
"""
from __future__ import annotations

import time
from typing import Any, Mapping

from .core import canonical, digest, exception_data, new_id


class ModelCall:
    def __init__(self, tel, *, provider: str, model: str, endpoint_alias: str, config: Mapping[str, Any] | None = None,
                 template_id: str | None = None, template_version: str | None = None,
                 context_refs: list | None = None, purpose: str | None = None, **ids: Any) -> None:
        self.tel = tel
        self.model_call_id = new_id("mc")
        self.meta = {"provider": provider, "model": model, "endpoint_alias": endpoint_alias,
                     "config": dict(config or {}), "template_id": template_id, "template_version": template_version,
                     "context_refs": list(context_refs or []), "purpose": purpose}
        self.ids = {k: v for k, v in ids.items() if v}
        self.attempts = 0
        self.requests = 0
        self.tokens = {"prompt": 0, "completion": 0, "total": 0}
        self.latency_ms = 0.0
        self.status = "open"
        self.tool_calls: list[str] = []
        self._t_req: dict[int, int] = {}
        self._bind = None
        self.start_event: dict | None = None

    # context manager ------------------------------------------------------------------
    def __enter__(self) -> "ModelCall":
        self._bind = self.tel.bind(model_call_id=self.model_call_id, **self.ids)
        self._bind.__enter__()
        self.start_event = self.tel.emit("model.call_start", self.meta, critical=True)
        self._pbind = self.tel.bind(parent_event_id=(self.start_event or {}).get("event_id"))
        self._pbind.__enter__()
        self.tel.update_manifest(lambda m: m["models"].append({k: self.meta[k] for k in ("provider", "model", "endpoint_alias", "template_version")})
                                 if {k: self.meta[k] for k in ("provider", "model", "endpoint_alias", "template_version")} not in m["models"] else None)
        return self

    def __exit__(self, et, ev, tb) -> None:
        try:
            if ev is not None:
                self.status = "error"
                self.tel.exception(ev, event_type="model.error", data={"attempt": self.attempts, "fatal": True})
            elif self.status == "open":
                self.status = "ok"
            self.tel.emit("model.call_end", {"status": self.status, "attempts": self.attempts, "requests": self.requests,
                                             "tokens": dict(self.tokens), "latency_ms_total": round(self.latency_ms, 3),
                                             "tool_calls": list(self.tool_calls)},
                          level="info" if self.status == "ok" else "warning")
        finally:
            self._pbind.__exit__(et, ev, tb)
            self._bind.__exit__(et, ev, tb)

    # events ---------------------------------------------------------------------------
    def _body(self, kind: str, body: Any) -> dict:
        text = body if isinstance(body, str) else canonical(self.tel.redactor.redact(body))
        red = self.tel.redactor.redact_text(text)
        out = {"sha256": digest(red), "length": len(red.encode("utf-8")), "body_logged": bool(self.tel.config.log_bodies)}
        if self.tel.config.log_bodies:
            out["artifact"] = self.tel.artifact(kind, body if not isinstance(body, str) else body)
        return out

    def request(self, body: Any, *, attempt: int | None = None, turn: int = 0) -> dict | None:
        self.requests += 1
        if attempt is not None:
            self.attempts = max(self.attempts, attempt)
        a = attempt or self.requests
        b = self._body("model-request", body)
        self._t_req[self.requests] = time.monotonic_ns()
        return self.tel.emit("model.request", {"attempt": a, "turn": turn, "request_index": self.requests,
                                               "request_sha256": b["sha256"], "request_length": b["length"],
                                               "body_logged": b["body_logged"], "request_body": b.get("artifact"),
                                               "endpoint_alias": self.meta["endpoint_alias"]}, critical=True)

    def response(self, body: Any, *, attempt: int | None = None, tokens: Mapping[str, Any] | None = None,
                 finish_reason: str | None = None, status: str = "ok", http_status: int | None = None,
                 latency_ms: float | None = None, turn: int = 0) -> dict | None:
        t0 = self._t_req.get(self.requests)
        lat = latency_ms if latency_ms is not None else (round_ms(time.monotonic_ns() - t0) if t0 else None)
        self.latency_ms += lat or 0.0
        tok = {"prompt": int((tokens or {}).get("prompt_tokens", (tokens or {}).get("prompt", 0)) or 0),
               "completion": int((tokens or {}).get("completion_tokens", (tokens or {}).get("completion", 0)) or 0)}
        tok["total"] = int((tokens or {}).get("total_tokens", tok["prompt"] + tok["completion"]) or 0)
        for k in tok:
            self.tokens[k] += tok[k]
        b = self._body("model-response", body)
        return self.tel.emit("model.response", {"attempt": attempt or self.requests, "turn": turn,
                                                "request_index": self.requests, "response_sha256": b["sha256"],
                                                "response_length": b["length"], "body_logged": b["body_logged"],
                                                "response_body": b.get("artifact"), "latency_ms": lat, "status": status,
                                                "http_status": http_status, "finish_reason": finish_reason, "tokens": tok},
                             level="info" if status == "ok" else "warning")

    def tool_call(self, name: str, arguments: Any, *, tool_call_id: str | None = None) -> str:
        tcid = tool_call_id or new_id("tc")
        self.tool_calls.append(tcid)
        self.tel.emit("model.tool_call", {"name": name, "arguments_sha256": digest(canonical(self.tel.redactor.redact(arguments))),
                                          "arguments": self.tel.artifact("model-tool-arguments", arguments)
                                          if self.tel.config.log_bodies else None,
                                          "request_index": self.requests}, tool_call_id=tcid)
        return tcid

    def tool_result(self, tool_call_id: str, result: Any, *, status: str = "ok", error: BaseException | None = None) -> None:
        data = {"status": status, "result_sha256": digest(canonical(self.tel.redactor.redact(result))),
                "result": self.tel.artifact("model-tool-result", result) if self.tel.config.log_bodies else None}
        if error is not None:
            data["exception"] = exception_data(error)
        self.tel.emit("model.tool_result", data, tool_call_id=tool_call_id, level="info" if status == "ok" else "warning")

    def retry(self, attempt: int, reason: str, *, delay_s: float = 0.0, next_action: str | None = None) -> None:
        self.tel.emit("model.retry", {"attempt": attempt, "next_attempt": attempt + 1, "reason": reason,
                                      "delay_s": delay_s, "next_action": next_action})

    def error(self, exc: BaseException, *, attempt: int, retry: bool) -> None:
        self.tel.exception(exc, event_type="model.error", retry={"will_retry": retry}, data={"attempt": attempt})

    def parsed(self, *, ok: bool, errors: list | None = None, result: Any = None, parser: str | None = None) -> None:
        self.tel.emit("model.parse", {"ok": ok, "errors": list(errors or []), "parser": parser,
                                      "result_sha256": digest(canonical(result)) if result is not None else None,
                                      "request_index": self.requests}, level="info" if ok else "warning")
        if not ok:
            self.status = "parse_error"
        elif self.status in {"open", "parse_error"}:
            self.status = "ok"


def round_ms(ns: int) -> float:
    return round(ns / 1e6, 3)


class MockModelClient:
    """Deterministic scripted model for tests and synthetic scenarios. Never touches the network.

    ``script`` items: a dict response ``{"content": str, "tool_calls": [...], "finish_reason": str}``
    or an exception instance to raise. Token counts are whitespace-word counts so they are stable.
    """

    provider = "mock"

    def __init__(self, script: list, *, model: str = "mock-qwen-deterministic", endpoint_alias: str = "mock://local",
                 latency_ms: float = 1.0) -> None:
        self.script = list(script)
        self.model = model
        self.endpoint_alias = endpoint_alias
        self.latency_ms = latency_ms
        self.requests: list[dict] = []

    def complete(self, request: dict) -> dict:
        self.requests.append(request)
        if not self.script:
            raise RuntimeError("mock model script exhausted")
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        prompt_words = sum(len(str(m.get("content", "")).split()) for m in request.get("messages", []))
        content = item.get("content", "")
        return {"model": self.model, "content": content, "tool_calls": item.get("tool_calls", []),
                "finish_reason": item.get("finish_reason", "tool_calls" if item.get("tool_calls") else "stop"),
                "usage": {"prompt_tokens": prompt_words, "completion_tokens": len(content.split()),
                          "total_tokens": prompt_words + len(content.split())},
                "latency_ms": self.latency_ms}


def instrumented_model_invoke(tel, client, *, template_id: str, template_version: str, config: Mapping | None = None,
                              context_refs: list | None = None, **ids: Any):
    """Adapter for text-in/text-out seams such as a ``model_invoke(system, user) -> str`` callable.

    Every call is wrapped in a full ModelCall envelope. The wrapped callable is not imported or modified.
    """
    def invoke(system: str, user: str) -> str:
        with tel.model_call(provider=getattr(client, "provider", "unknown"), model=getattr(client, "model", "unknown"),
                            endpoint_alias=getattr(client, "endpoint_alias", "unknown"), config=config,
                            template_id=template_id, template_version=template_version,
                            context_refs=context_refs, purpose="text-seam", **ids) as mc:
            body = {"messages": [{"role": "system", "content": system}, {"role": "user", "content": user}], **dict(config or {})}
            mc.request(body, attempt=1)
            resp = client.complete(body)
            mc.response({"content": resp.get("content"), "finish_reason": resp.get("finish_reason")}, attempt=1,
                        tokens=resp.get("usage"), finish_reason=resp.get("finish_reason"),
                        latency_ms=resp.get("latency_ms"))
            mc.parsed(ok=True, parser="passthrough-text")
            return resp.get("content", "")
    return invoke
