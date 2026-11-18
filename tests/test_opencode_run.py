import json
import subprocess
from types import SimpleNamespace

from refall_lite import opencode_run
from refall_lite.opencode_run import build_config, run_opencode

SUBMIT = {"schema": "refall.submit.v1", "type": "job_result", "status": "done", "summary": "canned",
          "evidence": [], "confidence": "low"}
_TEXT = "done\n```refall-submit\n" + json.dumps(SUBMIT) + "\n```"
CANNED_JSONL = "\n".join([
    json.dumps({"type": "text", "part": {"type": "text", "text": "working. "}}),
    "",
    "not json at all",
    json.dumps({"type": "tool_use", "part": {"type": "tool", "tool": "rea_open_binary", "state": {}}}),
    json.dumps({"type": "text", "part": {"type": "text", "text": _TEXT}}),
]) + "\n"


def test_build_config_is_deny_by_default_with_specific_enables():
    cfg = build_config("/w", model="spark/Q", base_url="http://x/v1", api_key="k",
                       rea_command=["rea", "mcp"], rea_env={}, enabled_rea_tools=["open_binary", "list_strings"])
    assert cfg["tools"]["rea_*"] is False
    assert cfg["tools"]["rea_open_binary"] is True
    assert cfg["tools"]["rea_list_strings"] is True
    assert cfg["provider"]["spark"]["options"]["baseURL"] == "http://x/v1"


def test_run_opencode_closes_stdin_and_parses_jsonl(monkeypatch):
    captured = {}

    def fake_run(argv, **kw):
        captured.update(kw)
        captured["argv"] = argv
        return SimpleNamespace(stdout=CANNED_JSONL, stderr="", returncode=0)

    monkeypatch.setattr(opencode_run.subprocess, "run", fake_run)
    res = run_opencode("hi", workdir="/w", config={}, timeout_s=30)
    assert captured["stdin"] is opencode_run.subprocess.DEVNULL
    assert res.submit_payload["summary"] == "canned"
    assert "rea_open_binary" in res.tool_calls
    assert res.exit_code == 0 and not res.timed_out
    assert len(res.raw_events) == 3


def test_run_opencode_timeout_sets_timed_out(monkeypatch):
    def fake_run(argv, **kw):
        raise subprocess.TimeoutExpired(argv, 1, output=b"", stderr=b"")

    monkeypatch.setattr(opencode_run.subprocess, "run", fake_run)
    res = run_opencode("hi", workdir="/w", config={}, timeout_s=1)
    assert res.timed_out is True
    assert res.submit_payload is None
