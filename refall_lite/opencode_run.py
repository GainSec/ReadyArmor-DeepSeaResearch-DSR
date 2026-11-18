"""Per-lead OpenCode invocation + JSONL parse (stdlib only)."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from refall_lite.worker import parse_submission


@dataclass
class OpenCodeResult:
    exit_code: int
    timed_out: bool
    final_text: str
    tool_calls: list[str] = field(default_factory=list)
    submit_payload: dict | None = None
    raw_events: list[dict] = field(default_factory=list)


def build_config(workdir: str, *, model: str, base_url: str, api_key: str, rea_command: list[str],
                 rea_env: dict, enabled_rea_tools: list[str]) -> dict:
    provider_id, _, model_id = model.partition("/")
    if not model_id:
        provider_id, model_id = "spark", model
    return {
        "$schema": "https://opencode.ai/config.json",
        "model": f"{provider_id}/{model_id}",
        "provider": {
            provider_id: {
                "npm": "@ai-sdk/openai-compatible",
                "name": provider_id,
                "options": {"baseURL": base_url, "apiKey": api_key},
                "models": {model_id: {"name": model_id}},
            }
        },
        "mcp": {"rea": {"type": "local", "command": list(rea_command), "environment": dict(rea_env),
                        "enabled": True}},
        "tools": {"rea_*": False, **{f"rea_{t}": True for t in enabled_rea_tools}},
    }


def _as_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value or ""


def _parse_events(stdout: str) -> tuple[list[dict], str, list[str]]:
    events: list[dict] = []
    texts: list[str] = []
    tools: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        events.append(event)
        part = event.get("part") if isinstance(event.get("part"), dict) else event
        ptype = part.get("type")
        if ptype == "text":
            texts.append(part.get("text") or "")
        elif ptype in ("tool", "tool-call", "tool_call", "tool_use"):
            name = part.get("tool") or part.get("name") or part.get("toolName")
            if name:
                tools.append(str(name))
    return events, "".join(texts), tools


def run_opencode(prompt: str, *, workdir: str, config: dict, timeout_s: float,
                 env: dict | None = None) -> OpenCodeResult:
    with tempfile.TemporaryDirectory(prefix="opencode-xdg-") as xdg:
        cfg_dir = Path(xdg) / "opencode"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "opencode.json").write_text(json.dumps(config))
        run_env = dict(os.environ if env is None else env)
        run_env["XDG_CONFIG_HOME"] = xdg
        argv = ["opencode", "run", "--dir", workdir, "--format", "json", "--auto", prompt]
        try:
            proc = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=timeout_s, env=run_env)
        except subprocess.TimeoutExpired as exc:
            events, text, tools = _parse_events(_as_text(exc.stdout))
            payload = parse_submission(text)[0] if text else None
            return OpenCodeResult(exit_code=-1, timed_out=True, final_text=text, tool_calls=tools,
                                  submit_payload=payload, raw_events=events)
    events, text, tools = _parse_events(_as_text(proc.stdout))
    payload = parse_submission(text)[0]
    return OpenCodeResult(exit_code=proc.returncode, timed_out=False, final_text=text, tool_calls=tools,
                          submit_payload=payload, raw_events=events)
