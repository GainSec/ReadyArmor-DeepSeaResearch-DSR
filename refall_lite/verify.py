"""Independent verification pass + engine-enforced promotion (D1).

A fresh model re-derives the mechanical facts of a candidate finding from the
claim alone (no first-agent narrative). ``check_consistency`` then compares
claim vs re-derivation vs REA facts with pure set/graph membership logic - it
never judges whether something is a vulnerability. ``promote_or_hold`` is run
by the HOST using a registered tool/human actor (never a model); the engine
enforces the tier ladder and receipt shape.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable

from .opencode_run import build_config, run_opencode
from .rea_toolmap import hunt_tools
from .worker import SUBMIT_SCHEMA, result_payload

MECHANICAL_KEYS = ("bytes", "call_path", "xrefs")


@dataclass
class VerdictResult:
    ok: bool
    reasons: list[str] = field(default_factory=list)


def _claim_of(finding: dict) -> dict:
    claim = finding.get("claim") or {}
    return {k: claim[k] for k in ("bytes", "call_path", "xrefs", "sink", "input_source") if claim.get(k)}


def rederive_prompt(finding: dict) -> tuple[str, dict]:
    """Prompt with ONLY target + required evidence; no description/evidence narrative."""
    claim = _claim_of(finding)
    target = finding.get("member_sha256") or finding.get("target") or "(see workdir)"
    prompt = (
        f"Independently verify mechanical facts about target (member sha256): {target}\n"
        "You have not seen any prior analysis. Using ONLY the REA tools, reproduce each item below "
        "from the binary itself. Do not assume any item is true.\n\n"
        f"Items to reproduce:\n{json.dumps(claim, indent=2, sort_keys=True)}\n\n"
        "For each: read the exact bytes at the stated offsets, confirm each call-path edge via the "
        "call graph, confirm each xref, and identify the sink and input source.\n"
        "Finish with exactly one fenced ```refall-submit block containing JSON with schema "
        f"\"{SUBMIT_SCHEMA}\", type \"job_result\", status, summary, evidence, confidence, "
        "limitations, cost_units, and the keys bytes, call_path, xrefs (same shapes as above) holding "
        "ONLY what you actually observed.\n"
    )
    return prompt, claim


def _edge(e) -> tuple:
    return tuple(e) if isinstance(e, (list, tuple)) else (e.get("from"), e.get("to"))


def _xref(x) -> tuple:
    return (x.get("from"), x.get("target"))


def _check(claim: dict, rederived: dict, rea_facts: dict) -> list[str]:
    reasons: list[str] = []
    facts_bytes = {int(k): str(v).lower() for k, v in (rea_facts.get("bytes") or {}).items()}
    graph = {_edge(e) for e in rea_facts.get("call_graph") or []}
    fx = {_xref(x) for x in rea_facts.get("xrefs") or []}
    re_bytes = {(int(b["offset"]), str(b["hex"]).lower()) for b in rederived.get("bytes") or []}
    re_edges = {_edge(e) for e in rederived.get("call_path") or []}
    re_xrefs = {_xref(x) for x in rederived.get("xrefs") or []}

    for b in claim.get("bytes") or []:
        off, hx = int(b["offset"]), str(b["hex"]).lower()
        if (off, hx) not in re_bytes:
            reasons.append(f"bytes at {off:#x} not re-derived")
        if not facts_bytes.get(off, "").startswith(hx):
            reasons.append(f"bytes {hx} at {off:#x} not supported by REA facts")
    for e in claim.get("call_path") or []:
        e = _edge(e)
        if e not in re_edges:
            reasons.append(f"call edge {e[0]}->{e[1]} not re-derived")
        if e not in graph:
            reasons.append(f"call edge {e[0]}->{e[1]} absent from REA call graph")
    for x in claim.get("xrefs") or []:
        x = _xref(x)
        if x not in re_xrefs:
            reasons.append(f"xref {x[0]}->{x[1]} not re-derived")
        if x not in fx:
            reasons.append(f"xref {x[0]}->{x[1]} absent from REA xrefs")
    return reasons


def check_consistency(claim: dict, rederived: dict, rea_facts: dict) -> VerdictResult:
    """Mechanical only. ok iff every claimed fact is re-derived AND supported by rea_facts.
    A claim with no mechanical facts never verifies; malformed input fails, never raises."""
    try:
        if not any((claim or {}).get(k) for k in MECHANICAL_KEYS):
            return VerdictResult(False, ["no mechanical facts to verify"])
        reasons = _check(claim, rederived or {}, rea_facts or {})
    except Exception as exc:  # malformed entries -> clean failing verdict
        return VerdictResult(False, [f"malformed claim/rederivation: {type(exc).__name__}: {exc}"])
    return VerdictResult(not reasons, reasons)


def host_rea_facts(finding: dict, *, rea_query: Callable[[str, dict], object]) -> dict:
    """Host-side fact extraction: query REA (injected ``rea_query(op, args)``) for each claimed
    item and assemble ``rea_facts`` in the shape ``check_consistency`` consumes. Contains ONLY what
    ``rea_query`` returned; a missing/failed answer omits that item (-> claim unsupported -> hold).

    Ops: ``read_bytes {offset, length}`` -> hex str; ``build_call_path {edge: [from, to]}`` -> edges
    list (or a truthy edge pair) confirming the edge; ``xrefs {from, target}`` -> list of
    ``{from, target}`` dicts."""
    claim = (finding or {}).get("claim") or {}
    facts: dict = {}

    def ask(op, args):
        try:
            return rea_query(op, args)
        except Exception:
            return None

    for b in claim.get("bytes") or []:
        off, hx = int(b["offset"]), str(b["hex"])
        got = ask("read_bytes", {"offset": off, "length": len(hx) // 2})
        if isinstance(got, str) and got:
            facts.setdefault("bytes", {})[off] = got
    for e in claim.get("call_path") or []:
        edge = _edge(e)
        got = ask("build_call_path", {"edge": list(edge)})
        for g in got or []:
            if not isinstance(g, str):
                facts.setdefault("call_graph", []).append(list(_edge(g)))
        if got and all(isinstance(g, str) for g in got):  # bare ["from","to"] pair
            facts.setdefault("call_graph", []).append(list(_edge(got)))
    for x in claim.get("xrefs") or []:
        got = ask("xrefs", {"from": x.get("from"), "target": x.get("target")})
        for g in got or []:
            if isinstance(g, dict):
                facts.setdefault("xrefs", []).append({"from": g.get("from"), "target": g.get("target")})
    return facts


class VerifyWorker:
    """Model-actor WorkerAdapter: fresh re-derivation session. Never promotes."""

    def __init__(self, worker_id: str, *, model: str, base_url: str, api_key: str, rea_command: list[str],
                 rea_env: dict, workdir_for: Callable[[dict], str], runner=run_opencode,
                 timeout_s: int = 1800) -> None:
        self.worker_id = worker_id
        self.model, self.base_url, self.api_key = model, base_url, api_key
        self.rea_command, self.rea_env = rea_command, rea_env
        self.workdir_for, self.runner, self.timeout_s = workdir_for, runner, timeout_s

    def run(self, packet: dict) -> str | dict:
        workdir = self.workdir_for(packet)
        finding = packet.get("finding") or {}
        prompt, claim = rederive_prompt(finding)
        cfg = build_config(workdir, model=self.model, base_url=self.base_url, api_key=self.api_key,
                           rea_command=self.rea_command, rea_env=self.rea_env,
                           enabled_rea_tools=hunt_tools())
        res = self.runner(prompt, workdir=workdir, config=cfg, timeout_s=self.timeout_s)
        if res.timed_out:
            return result_payload(status="provider_timeout", summary=f"verify timed out after {self.timeout_s}s",
                                  evidence=[], confidence="low", limitations=["verify timeout"])
        sub = res.submit_payload
        if not sub:
            return result_payload(status="missing_terminal_submit", summary="verifier produced no submission",
                                  evidence=[], confidence="low", limitations=["no refall-submit block"])
        rederived = {k: sub[k] for k in MECHANICAL_KEYS if k in sub}
        evidence = list(sub.get("evidence") or []) or [
            {"kind": "rederivation", "ref": "verify:" + str(finding.get("id") or "candidate"),
             "claim": str(sub.get("summary") or "re-derived")}]
        return result_payload(
            summary=str(sub.get("summary") or "independent re-derivation"), evidence=evidence,
            confidence="low", artifact_refs=list(sub.get("artifact_refs") or []),
            source_anchors=list(sub.get("source_anchors") or []),
            limitations=["model re-derivation; promotion requires deterministic consistency check by host"],
            findings=[{"claim": claim, "rederived": rederived}])


def _receipt_material(claim: dict, rederived: dict) -> dict:
    """Receipt fields built only from re-derived facts that match the claim."""
    refs: list[str] = []
    cmds: list[str] = []
    anchors: list[str] = []
    claimed_b = {(int(b["offset"]), str(b["hex"]).lower()) for b in claim.get("bytes") or []}
    for b in rederived.get("bytes") or []:
        key = (int(b["offset"]), str(b["hex"]).lower())
        if key in claimed_b:
            refs.append(f"bytes:{key[0]:#x}:{key[1]}")
            cmds.append(f"read_bytes offset={key[0]:#x} -> {key[1]}")
    claimed_e = {_edge(e) for e in claim.get("call_path") or []}
    for e in rederived.get("call_path") or []:
        if _edge(e) in claimed_e:
            refs.append(f"call_edge:{_edge(e)[0]}->{_edge(e)[1]}")
            anchors.append(f"{_edge(e)[0]}->{_edge(e)[1]}")
    claimed_x = {_xref(x) for x in claim.get("xrefs") or []}
    for x in rederived.get("xrefs") or []:
        if _xref(x) in claimed_x:
            refs.append(f"xref:{_xref(x)[0]}->{_xref(x)[1]}")
            anchors.append(f"xref {_xref(x)[0]}->{_xref(x)[1]}")
    out = {"evidence_refs": refs, "commands": cmds, "source_anchors": anchors}
    return {k: v for k, v in out.items() if v}


def promote_or_hold(lite, cid: str, finding_id: str, *, actor: str, claim: dict, rederived: dict,
                    rea_facts: dict) -> dict:
    """Compute the verdict here; promote hypothesis -> independently_checked only on a fresh ok.

    ``actor`` must be a registered tool/human actor distinct from the finding's
    creator; the engine enforces this and the receipt shape."""
    def hold(reasons):
        return {"promoted": False, "held": True, "reasons": list(reasons),
                "tier": lite.get_finding(finding_id)["tier"]}

    verdict = check_consistency(claim, rederived, rea_facts)
    if not verdict.ok:
        return hold(verdict.reasons)
    try:
        material = _receipt_material(claim, rederived)
    except Exception as exc:
        return hold([f"malformed rederivation: {type(exc).__name__}: {exc}"])
    if not material.get("evidence_refs"):
        return hold(["no mechanical material in re-derivation"])
    receipt = {"checker_kind": "deterministic_tool", **material}
    res = lite.transition_finding(cid, finding_id, actor=actor, to="independently_checked",
                                  receipt_type="independent_check", receipt=receipt)
    if not res.get("accepted"):
        return hold(res.get("reasons") or ["transition refused"])
    return {"promoted": True, "held": False, "reasons": [], "tier": res["finding"]["tier"],
            "transition_id": res.get("transition_id"), "receipt": receipt}
