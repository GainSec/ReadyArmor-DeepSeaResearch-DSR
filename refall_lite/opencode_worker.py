"""WorkerAdapter that runs one curated opencode session per job packet."""
from __future__ import annotations

import posixpath
from typing import Callable

from .opencode_run import build_config, run_opencode
from .rea_toolmap import hunt_tools
from .worker import SUBMIT_SCHEMA, result_payload


def _methods(bundle) -> list[dict]:
    if isinstance(bundle, dict):
        bundle = bundle.get("methods") or bundle.get("techniques") or []
    return [m for m in bundle if isinstance(m, dict)] if isinstance(bundle, list) else []


def _select_technique(packet: dict) -> dict:
    methods = _methods(packet.get("methodology_bundle"))
    wanted = ((packet.get("job") or {}).get("payload") or {}).get("technique_id")
    for m in methods:
        if wanted and m.get("id") == wanted:
            return m
    return methods[0] if methods else {}


def _target_path(packet: dict, workdir: str | None) -> str:
    target = packet.get("target") or {}
    item = target.get("member") or target.get("image") or {}
    rel = item.get("path") or item.get("name")
    if not rel:
        # Engine member rows carry no path; the on-disk relpath lives in occurrences.
        for occ in target.get("occurrences_sample") or []:
            if isinstance(occ, dict) and occ.get("path"):
                rel = occ["path"]
                break
    if not rel:
        rel = target.get("ref") or ""
    if workdir and rel:
        return posixpath.join(workdir, rel.lstrip("/"))
    return rel


PRIORITIES = ("Priority, highest first: (1) remote command/code/terminal injection; "
              "(2) remotely-ingested injection (file received, file upload, parsing of received data); "
              "(3) services exposed over the internet or LAN; (4) other memory-safety or logic bugs.")
OPTIONAL_HEADER = ("Optional reference ideas from the methodology pack (use if relevant to THIS target, "
                   "otherwise ignore and use your own judgment):")


def build_objective(packet: dict, workdir: str | None = None, *, priorities: str | None = None) -> tuple[str, dict]:
    technique = _select_technique(packet)
    path = _target_path(packet, workdir)
    target = packet.get("target") or {}
    ideas = [technique] if technique else []
    ideas += [m for m in _methods(packet.get("methodology_bundle")) if m is not technique]
    block = ""
    if ideas[:2]:
        parts = []
        for m in ideas[:2]:
            steps = "\n".join(f"    {i}. {s}" for i, s in enumerate(m.get("ordered_steps") or [], 1))
            parts.append(f"  - {m.get('id')}: {m.get('label', '')}\n{steps}".rstrip())
        block = OPTIONAL_HEADER + "\n" + "\n".join(parts) + "\n\n"
    prompt = (
        f"Reverse-engineer the target {target.get('type', 'file')} at {path} to find NOVEL security "
        "vulnerabilities. Analyze it however you judge best using the available REA tools.\n"
        f"Target ref: {target.get('ref')} (family: {target.get('family')})\n\n"
        f"{priorities or PRIORITIES}\n\n"
        f"{block}"
        "Only assert a finding you can ground in REA tool output. All conclusions are provisional "
        "until independently checked; mark confidence honestly and do not claim validation.\n"
        "Finish with exactly one fenced ```refall-submit block containing JSON with schema "
        f"\"{SUBMIT_SCHEMA}\", type \"job_result\", status, summary, evidence, confidence, "
        "limitations, source_anchors or artifact_refs, cost_units, and a top-level `findings` array.\n"
        "CRITICAL: report EVERY distinct vulnerability as one object in the `findings` array — a vulnerability "
        "placed only in `evidence`/`summary` is NOT recorded by the harness. Each `findings` object must have: "
        "`title`; `severity` (one of info, low, medium, high, critical); `vuln_class`; `confidence`; and a "
        "structured `claim` whose facts use EXACTLY these shapes so a deterministic checker can re-derive "
        "them: `bytes` = array of {\"offset\": <int file offset>, \"hex\": \"<lowercase hex of the ACTUAL "
        "bytes at that offset>\"} (for a binary, resolve the address to a file offset and give the real "
        "opcode/string bytes — never prose); `call_path` = array of [from, to] address/symbol edges; `xrefs` "
        "= array of {\"from\": <addr>, \"target\": <addr>}. For a source/script target, give byte anchors only "
        "(file offset + hex of the source bytes) and omit call_path/xrefs. Include per-finding `source_anchors` "
        "or `artifact_refs` (e.g. file:line or address). If you find no real vulnerability, submit an empty "
        "`findings` array.\n"
    )
    return prompt, technique


def _normalize_cost_units(payload: dict) -> None:
    """Models sometimes emit cost_units as a numeric string ("6"); the strict D1 gate
    rejects the whole submission over it, losing real findings. Coerce a numeric string
    to a number, and drop a value that cannot be parsed (cost_units is optional)."""
    if "cost_units" not in payload:
        return
    c = payload["cost_units"]
    if isinstance(c, bool) or isinstance(c, (int, float)):
        return
    if isinstance(c, str):
        try:
            f = float(c.strip())
        except (ValueError, AttributeError):
            payload.pop("cost_units", None)
            return
        payload["cost_units"] = int(f) if f.is_integer() else f
        return
    payload.pop("cost_units", None)


class OpenCodeWorker:
    def __init__(self, worker_id: str, *, model: str, base_url: str, api_key: str, rea_command: list[str],
                 rea_env: dict, workdir_for: Callable[[dict], str], runner=run_opencode,
                 timeout_s: int = 1800, priorities: str | None = None) -> None:
        self.worker_id = worker_id
        self.model, self.base_url, self.api_key = model, base_url, api_key
        self.rea_command, self.rea_env = rea_command, rea_env
        self.workdir_for, self.runner, self.timeout_s = workdir_for, runner, timeout_s
        self.priorities = priorities

    def run(self, packet: dict) -> str | dict:
        workdir = self.workdir_for(packet)
        prompt, technique = build_objective(packet, workdir, priorities=self.priorities)
        cfg = build_config(workdir, model=self.model, base_url=self.base_url, api_key=self.api_key,
                           rea_command=self.rea_command, rea_env=self.rea_env,
                           enabled_rea_tools=hunt_tools())
        res = self.runner(prompt, workdir=workdir, config=cfg, timeout_s=self.timeout_s)
        if res.timed_out:
            return result_payload(status="provider_timeout", summary=f"opencode timed out after {self.timeout_s}s",
                                  evidence=[], confidence="low", limitations=["spark timeout"])
        if res.submit_payload:
            _normalize_cost_units(res.submit_payload)
            tid = technique.get("id")
            if tid and isinstance(res.submit_payload.get("findings"), list):
                for f in res.submit_payload["findings"]:
                    if isinstance(f, dict):
                        f.setdefault("technique_id", tid)
            return res.submit_payload
        return result_payload(status="missing_terminal_submit", summary="agent finished without a submission",
                              evidence=[], confidence="low",
                              limitations=["agent produced no refall-submit block"])
