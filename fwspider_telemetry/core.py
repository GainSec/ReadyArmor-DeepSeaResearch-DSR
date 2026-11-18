"""Telemetry emitter: events, correlation context, artifacts, exceptions, subprocesses, process lifecycle."""
from __future__ import annotations

import contextvars
import hashlib
import json
import os
import platform
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .config import ObservabilityError, TelemetryConfig
from .redaction import REDACTED, RedactionReport, Redactor
from .sink import FILE_MODE, LogDir, sha256_bytes

SCHEMA_PATH = Path(__file__).with_name("event-schema.json")
SCHEMA: dict = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
SCHEMA_VERSION: str = SCHEMA["schema_version"]
TAXONOMY: dict[str, dict] = SCHEMA["event_types"]
LEVELS: list[str] = SCHEMA["levels"]
ARTIFACT_SCHEMA = SCHEMA["artifact_envelope"]["schema_version"]
DEADLETTER_SCHEMA = "fwspider.deadletter.v1"
ID_FIELDS = ("campaign_id", "job_id", "model_call_id", "tool_call_id", "artifact_id", "finding_id")
ENV_IDS = {"campaign_id": "FIRMWARE_SPIDER_CAMPAIGN_ID", "job_id": "FIRMWARE_SPIDER_JOB_ID",
           "model_call_id": "FIRMWARE_SPIDER_MODEL_CALL_ID", "tool_call_id": "FIRMWARE_SPIDER_TOOL_CALL_ID"}
MAGIC = [  # (offset, bytes, type)
    (0, b"\x7fELF", "elf"), (0, b"\x1f\x8b", "gzip"), (0, b"PK\x03\x04", "zip"), (0, b"hsqs", "squashfs-le"),
    (0, b"sqsh", "squashfs-be"), (0, b"UBI#", "ubi"), (0, b"\x27\x05\x19\x56", "uimage"), (0, b"HDR0", "trx"),
    (0, b"070701", "cpio-newc"), (0, b"\xfd7zXZ\x00", "xz"), (0, b"BZh", "bzip2"), (0, b"\x5d\x00\x00", "lzma"),
    (0, b"MZ", "pe"), (0, b"\x85\x19", "jffs2-le"), (0, b"\x19\x85", "jffs2-be"), (0, b"\x45\x3d\xcd\x28", "cramfs"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"), (0, b"ANDROID!", "android-boot"), (0, b"\xd0\x0d\xfe\xed", "dtb"),
    (257, b"ustar", "tar"), (0, b"\x89PNG", "png"), (0, b"%PDF", "pdf"),
]

_ctx: contextvars.ContextVar[dict] = contextvars.ContextVar("fwspider_telemetry_ctx", default={})


def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def new_run_id() -> str:
    return f"run_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:12]}"


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def digest(value: Any) -> str:
    data = value if isinstance(value, bytes) else (value if isinstance(value, str) else canonical(value)).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def git_commit(start: Path) -> str | None:
    """Read HEAD without spawning git (works for dev checkouts; None for installed wheels)."""
    for d in [Path(start).resolve(), *Path(start).resolve().parents]:
        head = d / ".git" / "HEAD"
        if head.is_file():
            ref = head.read_text().strip()
            if ref.startswith("ref: "):
                p = d / ".git" / ref[5:]
                if p.is_file():
                    return p.read_text().strip()
                packed = d / ".git" / "packed-refs"
                if packed.is_file():
                    for ln in packed.read_text().splitlines():
                        if ln.endswith(" " + ref[5:]):
                            return ln.split()[0]
                return None
            return ref
    return None


def exception_data(exc: BaseException, *, retry: Any = None) -> dict:
    chain = []
    seen: set[int] = set()
    cur: BaseException | None = exc
    relation = "raised"
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        chain.append({"relation": relation, "type": f"{type(cur).__module__}.{type(cur).__qualname__}", "message": str(cur)})
        if cur.__cause__ is not None:
            cur, relation = cur.__cause__, "cause"
        elif cur.__context__ is not None and not cur.__suppress_context__:
            cur, relation = cur.__context__, "context"
        else:
            cur = None
    stack = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return {"type": chain[0]["type"], "message": str(exc), "stack": stack.splitlines(), "cause_chain": chain,
            "retry": retry}


def _artifact_refs(value: Any, depth: int = 0) -> list[str]:
    """All log-artifact refs anywhere in event data (so the verifier can resolve every one)."""
    out: list[str] = []
    if depth > 8:
        return out
    if isinstance(value, dict):
        ref = value.get("artifact_ref")
        if isinstance(ref, str) and ref.startswith("art_"):
            out.append(ref)
        for v in value.values():
            out += _artifact_refs(v, depth + 1)
    elif isinstance(value, list):
        for v in value:
            out += _artifact_refs(v, depth + 1)
    return out


def _sniff(head: bytes) -> str:
    for off, magic, kind in MAGIC:
        if head[off:off + len(magic)] == magic:
            return kind
    if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head[:512]):
        return "text"
    return "data"


class Telemetry:
    """One instance per process (see ``get_telemetry``); safe across threads."""

    def __init__(self, component: str, *, config: TelemetryConfig | None = None, run_id: str | None = None,
                 version: str | None = None, redactor: Redactor | None = None,
                 env: Mapping[str, str] | None = None) -> None:
        env = os.environ if env is None else env
        self.component = component
        self.config = config or TelemetryConfig.from_env(env)
        self.redactor = redactor or Redactor([*self.config.extra_redact_patterns])
        self.sink = LogDir(self.config.log_dir, rotate_bytes=self.config.rotate_bytes, compress=self.config.compress,
                           fsync=self.config.fsync, retention_segments=self.config.retention_segments,
                           retention_days=self.config.retention_days, lock_timeout_s=self.config.lock_timeout_s,
                           stale_lock_s=self.config.stale_lock_s)
        self.run_id = run_id or env.get("FIRMWARE_SPIDER_RUN_ID") or new_run_id()
        self.joined_run = bool(run_id is None and env.get("FIRMWARE_SPIDER_RUN_ID"))
        self.process_id = new_id("proc")
        self.host = socket.gethostname()
        self.pid = os.getpid()
        self.version = version
        self.parent_event_id = env.get("FIRMWARE_SPIDER_PARENT_EVENT_ID") or None
        self.base_ids = {k: env.get(v) for k, v in ENV_IDS.items() if env.get(v)}
        self.failures = 0
        self.last_failure: dict | None = None
        self.started = False
        self.ended = False
        self._start_lock = threading.RLock()
        self._t0 = time.monotonic_ns()
        self._prev_excepthook = None
        self.deadletter_path = self.config.deadletter_dir / f"deadletter-{self.host}-{self.pid}-{self.process_id[-8:]}.jsonl"

    # ------------------------------------------------------------------ context
    @contextmanager
    def bind(self, **ids: Any) -> Iterator[dict]:
        cur = dict(_ctx.get())
        cur.update({k: v for k, v in ids.items() if v is not None})
        token = _ctx.set(cur)
        try:
            yield cur
        finally:
            _ctx.reset(token)

    def context(self) -> dict:
        return {**self.base_ids, **_ctx.get()}

    def subprocess_env(self, env: Mapping[str, str] | None = None, **ids: Any) -> dict[str, str]:
        out = dict(os.environ if env is None else env)
        ctx = {**self.context(), **{k: v for k, v in ids.items() if v}}
        out["FIRMWARE_SPIDER_RUN_ID"] = self.run_id
        out["FIRMWARE_SPIDER_LOG_DIR"] = str(self.config.log_dir)
        out["FIRMWARE_SPIDER_TELEMETRY_POLICY"] = self.config.policy
        out["FIRMWARE_SPIDER_DEBUG"] = "1" if self.config.debug else "0"
        out["FIRMWARE_SPIDER_LOG_BODIES"] = "1" if self.config.log_bodies else "0"
        for key, var in ENV_IDS.items():
            if ctx.get(key):
                out[var] = str(ctx[key])
            else:
                out.pop(var, None)
        parent = ctx.get("parent_event_id")
        if parent:
            out["FIRMWARE_SPIDER_PARENT_EVENT_ID"] = parent
        return out

    # ------------------------------------------------------------------ core emit
    def enabled(self, level: str) -> bool:
        return level != "debug" or self.config.debug

    def emit(self, event_type: str, data: Mapping[str, Any] | None = None, *, level: str | None = None,
             message: str = "", component: str | None = None, critical: bool = False,
             parent_event_id: str | None = None, log_artifacts: Sequence[str] = (), **ids: Any) -> dict | None:
        spec = TAXONOMY.get(event_type)
        if spec is None:
            raise ValueError(f"unknown telemetry event_type {event_type!r}; add it to event-schema.json")
        lvl = level or spec["level"]
        if lvl not in LEVELS:
            raise ValueError(f"unknown level {lvl!r}")
        unknown = set(ids) - set(ID_FIELDS)
        if unknown:
            raise ValueError(f"unknown correlation fields {sorted(unknown)}")
        if not self.enabled(lvl):
            return None
        with self._start_lock:  # other threads wait until process.start is written
            need_start = not self.started
        if need_start and event_type not in {"process.start", "process.resume", "run.start"}:
            self.start_process()
        ev: dict | None = None
        try:
            ev = self._build(event_type, dict(data or {}), lvl, message, component, parent_event_id, log_artifacts, ids)
            return self.sink.write_event(ev, on_rotate=self._after_rotate)
        except ObservabilityError:
            raise
        except Exception as exc:  # observability failure: visible, dead-lettered, never silent
            self._failure(exc, ev, event_type, critical)
            return None

    def _build(self, event_type: str, data: dict, level: str, message: str, component: str | None,
               parent_event_id: str | None, log_artifacts: Sequence[str], ids: dict) -> dict:
        report = RedactionReport()
        data = self.redactor.redact(data, report, "$.data")
        message = self.redactor.redact_text(message or "", report, "$.message")
        arts = list(log_artifacts) + _artifact_refs(data)
        size = len(canonical(data).encode("utf-8"))
        if size > self.config.max_inline_bytes:
            ref = self.artifact("event-data", data, content_type="application/json", already_redacted=True)
            arts.append(ref["artifact_ref"])
            data = {"_bounded": True, "reason": f"data exceeded max_inline_bytes={self.config.max_inline_bytes}",
                    "artifact_ref": ref["artifact_ref"], "sha256": ref["sha256"], "original_length": ref["original_length"],
                    "stored_length": ref["stored_length"], "truncated": ref["truncated"], "keys": sorted(data)[:50]}
        ctx = self.context()
        merged = {k: ctx.get(k) for k in ID_FIELDS}
        merged.update({k: v for k, v in ids.items() if k in ID_FIELDS and v is not None})
        ev = {
            "schema_version": SCHEMA_VERSION, "event_id": new_id("ev"), "ts": utc_ts(),
            "monotonic_ns": time.monotonic_ns(), "seq": 0, "level": level, "event_type": event_type,
            "component": component or self.component, "host": self.host, "pid": self.pid, "run_id": self.run_id,
            "process_id": self.process_id,
            "parent_event_id": parent_event_id or ctx.get("parent_event_id") or self.parent_event_id,
            **merged, "message": message or None, "data": data,
            "log_artifacts": sorted(set(arts)) or None, "redaction": report.as_dict(),
        }
        return ev

    def _after_rotate(self, rot: dict) -> None:
        closed = rot.get("closed") or {}
        if not closed:
            return
        ev = self._build("log.rotate", {"closed_segment": closed.get("name"), "sha256": closed.get("sha256"),
                                        "uncompressed_sha256": closed.get("uncompressed_sha256"),
                                        "events": closed.get("events"), "compressed": closed.get("compressed"),
                                        "index_entry_sha256": closed.get("entry_sha256")},
                         "notice", "", "fwspider-telemetry", None, (), {})
        self.sink.write_event(ev)
        for d in rot.get("deleted") or []:
            ev = self._build("log.retention_delete", {"segment": d.get("name"), "sha256": d.get("sha256"),
                                                      "events": d.get("events"), "runs": d.get("runs")},
                             "notice", "", "fwspider-telemetry", None, (), {})
            self.sink.write_event(ev)

    # ------------------------------------------------------------------ failures
    def _failure(self, exc: BaseException, ev: dict | None, event_type: str, critical: bool) -> None:
        self.failures += 1
        info = {"error": f"{type(exc).__name__}: {self.redactor.redact_text(str(exc))}", "event_type": event_type,
                "log_dir": str(self.config.log_dir), "policy": self.config.policy, "failures": self.failures,
                "deadletter": str(self.deadletter_path)}
        self.last_failure = info
        record = {"schema_version": DEADLETTER_SCHEMA, "ts": utc_ts(), "reason": info["error"], "critical": critical,
                  "reserved_seq": (ev or {}).get("seq") or None, "event": ev}
        dead_ok = True
        try:
            self.config.deadletter_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.deadletter_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, FILE_MODE)
            try:
                os.write(fd, (json.dumps(record, ensure_ascii=False, default=str) + "\n").encode("utf-8"))
            finally:
                os.close(fd)
        except Exception as dexc:  # last resort: the event itself goes to stderr
            dead_ok = False
            info["deadletter_error"] = f"{type(dexc).__name__}: {dexc}"
        try:
            notice = {"fwspider_telemetry_failure": info}
            if not dead_ok:
                notice["event"] = ev
            if self.failures <= 3 or self.failures % 100 == 0 or not dead_ok:
                sys.stderr.write(json.dumps(notice, default=str) + "\n")
                sys.stderr.flush()
        except Exception:  # pragma: no cover - stderr closed; nothing further possible
            pass
        if critical and self.config.policy == "strict":
            raise ObservabilityError(f"telemetry unavailable ({info['error']}); refusing operation under strict policy") from exc

    # ------------------------------------------------------------------ process lifecycle
    def start_process(self, argv: Sequence[str] | None = None, *, kind: str = "process", install_hooks: bool = False,
                      extra: Mapping[str, Any] | None = None) -> dict | None:
        with self._start_lock:
            if self.started:
                return None
            self.started = True
            argv = list(sys.argv if argv is None else argv)
            try:
                self.sink.ensure()
                state = self.sink.read_state(self.run_id)
            except Exception as exc:
                self._failure(exc, None, "process.start", critical=True)
                state = {}
            existing = bool(state.get("seq"))
            if not existing:
                self.emit("run.start", {"run_id": self.run_id, "log_dir": str(self.config.log_dir),
                                        "log_dir_source": self.config.log_dir_source, "profile": self.config.profile},
                          critical=True)
            data = {
                "kind": kind, "argv": self.redactor.sanitize_argv(argv), "cwd": os.getcwd(),
                "env": self.redactor.env_summary(None, debug=self.config.debug),
                "runtime": {"python": sys.version.split()[0], "implementation": platform.python_implementation(),
                            "platform": sys.platform, "machine": platform.machine()},
                "component_version": self.version, "config": self.config.effective(),
                "joined_run": self.joined_run, "prior_events_in_run": int(state.get("seq", 0)),
                **dict(extra or {}),
            }
            etype = "process.resume" if existing and not self.parent_event_id else "process.start"
            ev = self.emit(etype, data, critical=True)
            self._manifest_process_start(argv)
            if install_hooks:
                self.install_hooks()
            return ev

    def _manifest_process_start(self, argv: Sequence[str]) -> None:
        def mutate(m: dict) -> None:
            m["processes"].append({"process_id": self.process_id, "component": self.component, "pid": self.pid,
                                   "host": self.host, "started_at": utc_ts(), "ended_at": None, "exit_code": None,
                                   "status": "running", "argv_sha256": digest(list(map(str, argv))),
                                   "parent_event_id": self.parent_event_id})
            m["components"][self.component] = {"version": self.version, "git_commit": git_commit(Path(__file__).parent)}
            m["runtime"] = {"python": sys.version.split()[0], "platform": sys.platform}
            m["log_dir"] = str(self.config.log_dir)
            m["log_dir_source"] = self.config.log_dir_source
        self.update_manifest(mutate)

    def update_manifest(self, mutate) -> None:
        try:
            self.sink.update_manifest(self.run_id, mutate)
        except Exception as exc:
            self._failure(exc, None, "manifest.update", critical=False)

    def install_hooks(self, signals: Sequence[int] = (signal.SIGTERM, signal.SIGHUP)) -> None:
        prev = sys.excepthook
        self._prev_excepthook = prev

        def hook(etype, value, tb):  # pragma: no cover - exercised in subprocess tests
            try:
                self.crash(value)
            finally:
                prev(etype, value, tb)
        sys.excepthook = hook
        if threading.current_thread() is threading.main_thread():
            for sig in signals:
                try:
                    signal.signal(sig, self._on_signal)
                except (ValueError, OSError):
                    pass

    def _on_signal(self, signum, frame) -> None:  # pragma: no cover - exercised in subprocess tests
        self.emit("process.signal", {"signal": signal.Signals(signum).name})
        self.end_process(128 + signum, status="signalled")
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    def crash(self, exc: BaseException) -> None:
        if self.ended:
            return
        self.emit("process.crash", {"exception": exception_data(exc)})
        self.end_process(1, status="crashed")

    def end_process(self, exit_code: int | None = 0, *, status: str | None = None, data: Mapping | None = None) -> None:
        if self.ended:
            return
        self.ended = True
        st = status or ("ok" if exit_code == 0 else "error")
        self.emit("process.end", {"exit_code": exit_code, "status": st,
                                  "duration_ms": round((time.monotonic_ns() - self._t0) / 1e6, 3),
                                  "telemetry_failures": self.failures, **dict(data or {})},
                  level="info" if exit_code == 0 else "warning")

        def mutate(m: dict) -> None:
            for pr in m["processes"]:
                if pr["process_id"] == self.process_id:
                    pr.update(ended_at=utc_ts(), exit_code=exit_code, status=st)
            m["telemetry_failures"] = int(m.get("telemetry_failures", 0)) + self.failures
        self.update_manifest(mutate)

    def end_run(self, status: str, **data: Any) -> None:
        self.emit("run.end", {"status": status, **data})
        self.update_manifest(lambda m: m.update(closed_status=status))

    @contextmanager
    def guard(self, argv: Sequence[str] | None = None, *, kind: str = "script", install_hooks: bool = True) -> Iterator["Telemetry"]:
        """Process wrapper: start, then end/crash/signal with the real exit status."""
        self.start_process(argv, kind=kind, install_hooks=install_hooks)
        try:
            yield self
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
            if not isinstance(exc.code, int) and exc.code is not None:
                self.emit("error.exception", {"exception": exception_data(exc), "exit_message": str(exc.code)},
                          level="error")
            self.end_process(code)
            raise
        except KeyboardInterrupt as exc:
            self.emit("process.signal", {"signal": "SIGINT", "exception": exception_data(exc)})
            self.end_process(130, status="interrupted")
            raise
        except BaseException as exc:
            self.crash(exc)
            raise
        else:
            self.end_process(0)

    # ------------------------------------------------------------------ helpers
    def record_config(self, name: str, source: str, value: Any, **ids: Any) -> str:
        d = "sha256:" + digest(value)
        self.emit("config.load", {"name": name, "source": source, "digest": d, "effective": value}, **ids)
        self.update_manifest(lambda m: m["config_digests"].__setitem__(name, d))
        return d

    def record_io(self, direction: str, role: str, *, path: str | None = None, sha256: str | None = None,
                  size: int | None = None, ref: str | None = None) -> None:
        item = {"role": role, "path": path, "sha256": sha256, "size": size, "ref": ref}
        key = "inputs" if direction == "input" else "outputs"
        self.update_manifest(lambda m: m[key].append(item) if item not in m[key] else None)

    def exception(self, exc: BaseException, *, event_type: str = "error.exception", retry: Any = None,
                  level: str | None = None, message: str = "", data: Mapping | None = None, **ids: Any) -> dict | None:
        ctx = {**self.context(), **{k: v for k, v in ids.items() if v}}
        payload = {"exception": exception_data(exc, retry=retry), "retry": retry,
                   "affected_ids": {k: ctx.get(k) for k in ID_FIELDS if ctx.get(k)}, **dict(data or {})}
        return self.emit(event_type, payload, level=level, message=message or f"{type(exc).__name__}", **ids)

    def artifact(self, kind: str, content: Any, *, content_type: str | None = None, already_redacted: bool = False,
                 max_bytes: int | None = None) -> dict:
        """Store a bounded, redacted artifact envelope. Returns its summary (never the body)."""
        max_bytes = max_bytes or self.config.max_artifact_bytes
        ref = new_id("art")
        report = RedactionReport()
        binary = None
        if isinstance(content, (bytes, bytearray)):
            raw = bytes(content)
            try:
                text = raw.decode("utf-8")
                if "\x00" in text:
                    raise UnicodeDecodeError("utf-8", raw, 0, 1, "NUL byte")
                content, pre_len = text, len(raw)
            except UnicodeDecodeError:
                binary = {"length": len(raw), "sha256": sha256_bytes(raw), "type": _sniff(raw[:600]),
                          "preview_hex": raw[: self.redactor_preview()].hex()}
                content, pre_len = None, len(raw)
        if binary is None:
            if isinstance(content, str):
                pre_len = len(content.encode("utf-8"))
                text = content if already_redacted else self.redactor.redact_text(content, report, "$.body")
                ctype = content_type or "text/plain"
            else:
                obj = content if already_redacted else self.redactor.redact(content, report, "$.body")
                text = json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=1, default=str)
                pre_len = len(text.encode("utf-8"))
                ctype = content_type or "application/json"
            full = text.encode("utf-8")
            stored = full[:max_bytes].decode("utf-8", errors="ignore").encode("utf-8") if len(full) > max_bytes else full
            env = {"schema_version": ARTIFACT_SCHEMA, "artifact_ref": ref, "kind": kind, "created_at": utc_ts(),
                   "run_id": self.run_id, "process_id": self.process_id, "context": self.context(),
                   "content_type": ctype, "encoding": "utf-8",
                   "sha256": sha256_bytes(full), "original_length": len(full), "pre_redaction_length": pre_len,
                   "stored_length": len(stored), "stored_sha256": sha256_bytes(stored),
                   "truncated": len(stored) < len(full), "max_bytes": max_bytes,
                   "redaction": report.as_dict() or {"count": 0}, "body": stored.decode("utf-8")}
        else:
            env = {"schema_version": ARTIFACT_SCHEMA, "artifact_ref": ref, "kind": kind, "created_at": utc_ts(),
                   "run_id": self.run_id, "process_id": self.process_id, "context": self.context(),
                   "content_type": "application/octet-stream", "encoding": None, "sha256": binary["sha256"],
                   "original_length": binary["length"], "pre_redaction_length": binary["length"], "stored_length": 0,
                   "stored_sha256": sha256_bytes(b""), "truncated": binary["length"] > 0, "max_bytes": max_bytes,
                   "redaction": {"count": 0}, "body": None,
                   "binary": {"type": binary["type"], "preview_hex": binary["preview_hex"],
                              "note": "raw binary bodies are never stored; preview is bounded hex"}}
        summary = {"artifact_ref": ref, "sha256": env["sha256"], "original_length": env["original_length"],
                   "stored_length": env["stored_length"], "truncated": env["truncated"],
                   "path": f"runs/{self.run_id}/artifacts/{ref}.json", "redactions": env["redaction"].get("count", 0)}
        try:
            self.sink.write_artifact(self.run_id, ref, env)
        except Exception as exc:
            self._failure(exc, {"artifact": summary}, "artifact.write", critical=False)
            summary["write_failed"] = True
        if self.config.debug:
            self.emit("artifact.write", {k: summary[k] for k in ("artifact_ref", "sha256", "original_length",
                                                                  "stored_length", "truncated")} | {"kind": kind})
        return summary

    def redactor_preview(self) -> int:
        from .redaction import RULES
        return int(RULES.get("binary_preview_bytes", 64))

    def describe_binary(self, path: str | os.PathLike, *, offset: int = 0, length: int | None = None,
                        role: str = "firmware", emit: bool = True, **ids: Any) -> dict:
        """Path/size/hashes/type/bounded hex preview. Raw bytes never leave this function."""
        p = Path(path)
        st = p.stat()
        hs = {"sha256": hashlib.sha256(), "sha1": hashlib.sha1(), "md5": hashlib.md5()}
        head = b""
        remaining = length
        with open(p, "rb") as f:
            f.seek(offset)
            while True:
                n = 1 << 20 if remaining is None else min(1 << 20, remaining)
                if n <= 0:
                    break
                chunk = f.read(n)
                if not chunk:
                    break
                if len(head) < 600:
                    head += chunk[: 600 - len(head)]
                for h in hs.values():
                    h.update(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
        out = {"path": str(p), "size": st.st_size, "offset": offset, "length": length if length is not None else st.st_size - offset,
               **{k: h.hexdigest() for k, h in hs.items()}, "type": _sniff(head),
               "preview_hex": head[: self.redactor_preview()].hex(), "role": role}
        if emit:
            self.emit("artifact.binary_describe", out, **ids)
        return out

    # ------------------------------------------------------------------ operations / tools
    @contextmanager
    def span(self, start_type: str, end_type: str, error_type: str, data: Mapping[str, Any] | None = None, *,
             critical: bool = True, end_data=None, level: str | None = None, **ids: Any) -> Iterator[dict]:
        """Generic start/end/error envelope; nested events get parent_event_id = start event."""
        t0 = time.monotonic_ns()
        start = self.emit(start_type, dict(data or {}), critical=critical, level=level, **ids)
        holder: dict = {"start": start, "end_data": {}}
        with self.bind(parent_event_id=(start or {}).get("event_id"), **ids):
            try:
                yield holder
            except BaseException as exc:
                self.exception(exc, event_type=error_type, data={"duration_ms": round((time.monotonic_ns() - t0) / 1e6, 3),
                                                                 **{k: v for k, v in (data or {}).items() if k in ("operation", "tool", "name")}})
                raise
            else:
                payload = {**{k: v for k, v in (data or {}).items() if k in ("operation", "tool", "name")},
                           "duration_ms": round((time.monotonic_ns() - t0) / 1e6, 3), **holder["end_data"]}
                self.emit(end_type, payload, level=level)

    @contextmanager
    def tool_call(self, tool: str, arguments: Any = None, **ids: Any) -> Iterator[dict]:
        """In-process tool invocation envelope (tool.start / tool.end / tool.error)."""
        tcid = ids.pop("tool_call_id", None) or new_id("tc")
        args_art = self.artifact("tool-arguments", arguments) if arguments is not None else None
        with self.span("tool.start", "tool.end", "tool.error",
                       {"tool": tool, "argv": [tool], "in_process": True, "arguments": args_art},
                       tool_call_id=tcid, **ids) as holder:
            holder["tool_call_id"] = tcid
            holder["end_data"] = {"exit_code": 0, "stdout": None, "stderr": None}
            yield holder

    def run_subprocess(self, argv: Sequence[Any], *, tool: str | None = None, cwd: str | os.PathLike | None = None,
                       env: Mapping[str, str] | None = None, timeout: float | None = None, input: Any = None,
                       text: bool = True, check: bool = False, **ids: Any) -> subprocess.CompletedProcess:
        """subprocess.run with a full envelope. Caller still receives complete stdout/stderr."""
        tcid = ids.pop("tool_call_id", None) or new_id("tc")
        argv = [str(a) for a in argv]
        with self.bind(tool_call_id=tcid, **{k: v for k, v in ids.items() if v}):
            child_env = self.subprocess_env(env)
            start = self.emit("tool.start", {
                "tool": tool or Path(argv[0]).name, "argv": self.redactor.sanitize_argv(argv),
                "cwd": str(cwd or os.getcwd()), "env": self.redactor.env_summary(child_env, debug=self.config.debug),
                "timeout_s": timeout, "stdin": self.artifact("stdin", input) if input is not None else None,
            }, critical=True)
            if start:
                child_env["FIRMWARE_SPIDER_PARENT_EVENT_ID"] = start["event_id"]
            child_env["FIRMWARE_SPIDER_TOOL_CALL_ID"] = tcid
            t0 = time.monotonic_ns()
            parent = (start or {}).get("event_id")
            try:
                proc = subprocess.run(argv, cwd=cwd, env=child_env, timeout=timeout, input=input,
                                      capture_output=True, text=text)
            except subprocess.TimeoutExpired as exc:
                self.emit("tool.timeout", {"tool": tool or Path(argv[0]).name, "timeout_s": timeout,
                                           "duration_ms": round((time.monotonic_ns() - t0) / 1e6, 3),
                                           "stdout": self.artifact("stdout", exc.stdout or ""),
                                           "stderr": self.artifact("stderr", exc.stderr or "")},
                          parent_event_id=parent)
                raise
            except OSError as exc:
                self.exception(exc, event_type="tool.error", data={"tool": tool or Path(argv[0]).name},
                               parent_event_id=parent)
                raise
            rc = proc.returncode
            self.emit("tool.end", {"tool": tool or Path(argv[0]).name, "exit_code": rc,
                                   "signal": signal.Signals(-rc).name if rc < 0 and -rc in signal.Signals._value2member_map_ else None,
                                   "duration_ms": round((time.monotonic_ns() - t0) / 1e6, 3),
                                   "stdout": self.artifact("stdout", proc.stdout if proc.stdout is not None else ""),
                                   "stderr": self.artifact("stderr", proc.stderr if proc.stderr is not None else "")},
                      level="info" if rc == 0 else "warning", parent_event_id=parent)
            if check and rc:
                raise subprocess.CalledProcessError(rc, argv, proc.stdout, proc.stderr)
            return proc

    def model_call(self, **kw: Any):
        from .model import ModelCall
        return ModelCall(self, **kw)


class NullTelemetry(Telemetry):
    """Explicit opt-out (``telemetry=False``). Emits nothing; used only when a caller asks for it."""

    def __init__(self, component: str = "null") -> None:  # noqa: D401 - no sink
        self.component = component
        self.run_id = "run_null"
        self.process_id = "proc_" + "0" * 32
        self.failures = 0
        self.started = True
        self.ended = True
        self.base_ids = {}
        self.parent_event_id = None
        self.config = TelemetryConfig(log_dir=Path(os.devnull))
        self.redactor = Redactor()

    def emit(self, event_type: str, data=None, **kw: Any) -> dict | None:
        if event_type not in TAXONOMY:
            raise ValueError(f"unknown telemetry event_type {event_type!r}")
        return None

    def artifact(self, kind: str, content: Any, **kw: Any) -> dict:
        return {"artifact_ref": None, "sha256": digest(content if isinstance(content, (str, bytes)) else canonical(content))}

    def update_manifest(self, mutate) -> None:
        return None

    def start_process(self, *a: Any, **kw: Any) -> None:
        return None

    def end_process(self, *a: Any, **kw: Any) -> None:
        return None


_default: Telemetry | None = None
_default_lock = threading.Lock()


def get_telemetry(component: str = "firmware-spider", **kw: Any) -> Telemetry:
    """Process-wide default emitter configured from the environment (created lazily)."""
    global _default
    with _default_lock:
        if _default is None or _default.pid != os.getpid():
            _default = Telemetry(component, **kw)
        return _default


def set_telemetry(tel: Telemetry | None) -> None:
    global _default
    with _default_lock:
        _default = tel


def redacted(value: Any) -> Any:
    return Redactor().redact(value)


__all__ = ["Telemetry", "NullTelemetry", "get_telemetry", "set_telemetry", "exception_data", "SCHEMA", "TAXONOMY",
           "SCHEMA_VERSION", "REDACTED", "digest", "canonical", "new_id", "utc_ts"]
