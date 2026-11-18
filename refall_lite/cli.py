"""refall-lite CLI. Every invocation opens the ArcticBase store, acts, and closes it.

All output is JSON on stdout. Errors print {"error": ...} and exit 2 (3: incompatible store,
4: observability unavailable under the strict policy -> refused before any canonical work).
Diagnostics go to the central telemetry sink (FIRMWARE_SPIDER_LOG_DIR), never to stdout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from fwspider_telemetry import ObservabilityError, digest

from .arcticbase.store import IncompatibleStoreError
from .observability import resolve_telemetry
from .service import RefallLite

FILE_ARGS = ("config", "file", "receipt", "hashes", "fields", "preconditions", "capability", "decision", "producer", "labels",
             "policy", "thresholds")


def _load(path: str | None) -> Any:
    if not path:
        return {}
    text = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text  # e.g. a worker transcript containing a fenced refall-submit block


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="refall-lite", description="REFALL Lite (ArcticBase REFALL state layer, lite profile)")
    p.add_argument("--db", default=os.environ.get("REFALL_LITE_DB", "refall-lite.sqlite"), help="state store path")
    sub = p.add_subparsers(dest="cmd", required=True)

    def cmd(name: str, *aliases: str) -> argparse.ArgumentParser:
        return sub.add_parser(name, aliases=list(aliases))

    a = cmd("actor").add_subparsers(dest="sub", required=True)
    x = a.add_parser("add"); x.add_argument("actor_id"); x.add_argument("--kind", required=True); x.add_argument("--provider")
    a.add_parser("list")

    c = cmd("campaign").add_subparsers(dest="sub", required=True)
    x = c.add_parser("create"); x.add_argument("name"); x.add_argument("--config", required=True); x.add_argument("--actor", required=True)
    x = c.add_parser("stop"); x.add_argument("cid"); x.add_argument("--actor", required=True); x.add_argument("--reason", required=True)
    c.add_parser("list")

    x = cmd("status"); x.add_argument("cid")
    x = cmd("info")

    i = cmd("image").add_subparsers(dest="sub", required=True)
    x = i.add_parser("ingest"); x.add_argument("cid"); x.add_argument("--file", required=True); x.add_argument("--actor", required=True)
    x = i.add_parser("occurrences"); x.add_argument("cid"); x.add_argument("sha256")

    j = cmd("job").add_subparsers(dest="sub", required=True)
    for name in ("enqueue-images", "enqueue-members"):
        x = j.add_parser(name); x.add_argument("cid"); x.add_argument("--stage", required=True); x.add_argument("--kind", required=True); x.add_argument("--actor", required=True)
    x = j.add_parser("claim"); x.add_argument("cid"); x.add_argument("--worker", required=True); x.add_argument("--stage")
    x = j.add_parser("packet"); x.add_argument("cid"); x.add_argument("job_id")
    x = j.add_parser("submit"); x.add_argument("cid"); x.add_argument("job_id"); x.add_argument("--token", required=True); x.add_argument("--file", required=True)
    x = j.add_parser("fail"); x.add_argument("cid"); x.add_argument("job_id"); x.add_argument("--token", required=True); x.add_argument("--status", required=True); x.add_argument("--error", default=""); x.add_argument("--cost", type=float)
    x = j.add_parser("cancel"); x.add_argument("cid"); x.add_argument("job_id"); x.add_argument("--actor", required=True); x.add_argument("--reason", required=True)
    x = j.add_parser("list"); x.add_argument("cid"); x.add_argument("--stage"); x.add_argument("--status")

    s = cmd("stage").add_subparsers(dest="sub", required=True)
    x = s.add_parser("gate"); x.add_argument("cid")
    x = s.add_parser("advance"); x.add_argument("cid"); x.add_argument("--actor", required=True)
    x = s.add_parser("select-deep"); x.add_argument("cid"); x.add_argument("sha256"); x.add_argument("--actor", required=True); x.add_argument("--reason", required=True)

    f = cmd("finding").add_subparsers(dest="sub", required=True)
    x = f.add_parser("list"); x.add_argument("cid"); x.add_argument("--tier")
    x = f.add_parser("show"); x.add_argument("finding_id")
    x = f.add_parser("record"); x.add_argument("cid"); x.add_argument("--actor", required=True); x.add_argument("--file", required=True)
    x = f.add_parser("transition"); x.add_argument("cid"); x.add_argument("finding_id"); x.add_argument("--to", required=True)
    x.add_argument("--actor", required=True); x.add_argument("--receipt-type"); x.add_argument("--receipt"); x.add_argument("--duplicate-of")
    x = f.add_parser("occurrences"); x.add_argument("finding_id")

    e = cmd("escalation").add_subparsers(dest="sub", required=True)
    x = e.add_parser("request"); x.add_argument("cid"); x.add_argument("sha256"); x.add_argument("--finding", required=True); x.add_argument("--actor", required=True); x.add_argument("--receipt", required=True)
    x = e.add_parser("approve"); x.add_argument("cid"); x.add_argument("action_id"); x.add_argument("--actor", required=True); x.add_argument("--receipt", required=True)

    pa = cmd("pending").add_subparsers(dest="sub", required=True)
    x = pa.add_parser("list"); x.add_argument("cid"); x.add_argument("--all", action="store_true")
    x = pa.add_parser("resolve"); x.add_argument("cid"); x.add_argument("action_id"); x.add_argument("--actor", required=True)
    x.add_argument("--status", required=True); x.add_argument("--receipt-type", required=True); x.add_argument("--receipt", required=True)

    b = cmd("budget").add_subparsers(dest="sub", required=True)
    x = b.add_parser("show"); x.add_argument("cid")
    x = b.add_parser("raise"); x.add_argument("cid"); x.add_argument("scope"); x.add_argument("--actor", required=True)
    x.add_argument("--max-claims", type=float); x.add_argument("--max-cost", type=float); x.add_argument("--reason", default="")

    x = cmd("manifest"); x.add_argument("cid"); x.add_argument("--run-id", required=True); x.add_argument("--actor", required=True); x.add_argument("--fields")
    x = cmd("checkpoint"); x.add_argument("cid"); x.add_argument("--stage", required=True); x.add_argument("--key", required=True)
    x.add_argument("--hashes", required=True); x.add_argument("--actor", required=True)
    x = cmd("resume"); x.add_argument("cid"); x.add_argument("--actor", required=True); x.add_argument("--hashes")

    r = cmd("report").add_subparsers(dest="sub", required=True)
    x = r.add_parser("draft"); x.add_argument("cid"); x.add_argument("--actor", required=True)
    x = r.add_parser("show"); x.add_argument("cid")

    co = cmd("closeout").add_subparsers(dest="sub", required=True)
    x = co.add_parser("check"); x.add_argument("cid")
    x = co.add_parser("run"); x.add_argument("cid"); x.add_argument("--actor", required=True)

    ln = cmd("lineage").add_subparsers(dest="sub", required=True)
    x = ln.add_parser("ingest", help="ingest fingerprint observations: {content_sha256|unit_id, observations:[...]} or a list")
    x.add_argument("cid"); x.add_argument("--file", required=True); x.add_argument("--actor", required=True)
    x = ln.add_parser("unit"); x.add_argument("cid"); x.add_argument("sha256"); x.add_argument("--actor", required=True)
    x.add_argument("--granularity", default="file"); x.add_argument("--name", default=""); x.add_argument("--parent")
    x = ln.add_parser("units"); x.add_argument("cid"); x.add_argument("--content")
    x = ln.add_parser("observations"); x.add_argument("unit_id"); x.add_argument("--all-versions", action="store_true")
    x = ln.add_parser("pass"); x.add_argument("cid"); x.add_argument("--actor", required=True)
    x = ln.add_parser("compare"); x.add_argument("cid"); x.add_argument("unit_a"); x.add_argument("unit_b"); x.add_argument("--actor", required=True)
    x = ln.add_parser("edges"); x.add_argument("cid"); x.add_argument("--unit"); x.add_argument("--status")
    for name in ("edge-approve", "edge-reject"):
        x = ln.add_parser(name); x.add_argument("cid"); x.add_argument("edge_id"); x.add_argument("--actor", required=True)
        x.add_argument("--receipt-type"); x.add_argument("--receipt")
    x = ln.add_parser("propose"); x.add_argument("cid"); x.add_argument("units", nargs="+"); x.add_argument("--actor", required=True); x.add_argument("--name")
    x = ln.add_parser("approve"); x.add_argument("cid"); x.add_argument("family_id"); x.add_argument("--actor", required=True)
    x.add_argument("--receipt-type"); x.add_argument("--receipt")
    x = ln.add_parser("reject"); x.add_argument("cid"); x.add_argument("family_id"); x.add_argument("--actor", required=True)
    x.add_argument("--receipt-type", required=True); x.add_argument("--receipt", required=True)
    x = ln.add_parser("families"); x.add_argument("cid"); x.add_argument("--status")
    x = ln.add_parser("family"); x.add_argument("family_id")
    x = ln.add_parser("representative"); x.add_argument("cid"); x.add_argument("family_id"); x.add_argument("--actor", required=True); x.add_argument("--unit")
    x = ln.add_parser("plan"); x.add_argument("cid"); x.add_argument("--actor", required=True); x.add_argument("--kind", default="deep-analysis")
    x = ln.add_parser("deltas"); x.add_argument("cid")
    x = ln.add_parser("receipts"); x.add_argument("cid"); x.add_argument("--unit"); x.add_argument("--delta", action="store_true")
    x = ln.add_parser("reuse"); x.add_argument("cid")
    x = ln.add_parser("reuse-negative"); x.add_argument("cid"); x.add_argument("receipt_id"); x.add_argument("unit_id"); x.add_argument("--actor", required=True)
    x = ln.add_parser("set-algorithm"); x.add_argument("cid"); x.add_argument("version"); x.add_argument("--actor", required=True); x.add_argument("--reason", required=True)
    x = ln.add_parser("show"); x.add_argument("cid"); x.add_argument("sha256")
    x = ln.add_parser("knowledge"); x.add_argument("cid"); x.add_argument("sha256")
    x = ln.add_parser("config"); x.add_argument("cid")

    ap = cmd("applicability").add_subparsers(dest="sub", required=True)
    x = ap.add_parser("propagate"); x.add_argument("cid"); x.add_argument("finding_id"); x.add_argument("--actor", required=True)
    x = ap.add_parser("list"); x.add_argument("cid"); x.add_argument("--finding"); x.add_argument("--state")
    x = ap.add_parser("check"); x.add_argument("cid"); x.add_argument("row_id"); x.add_argument("--gate", required=True)
    x.add_argument("--status", required=True); x.add_argument("--actor", required=True); x.add_argument("--receipt", required=True)
    x = ap.add_parser("decide"); x.add_argument("cid"); x.add_argument("row_id"); x.add_argument("--state", required=True)
    x.add_argument("--actor", required=True); x.add_argument("--receipt-type", required=True); x.add_argument("--receipt", required=True)

    ch = cmd("chain").add_subparsers(dest="sub", required=True)
    x = ch.add_parser("node"); x.add_argument("cid"); x.add_argument("--actor", required=True); x.add_argument("--kind", required=True)
    x.add_argument("--label", required=True); x.add_argument("--scope", required=True); x.add_argument("--family"); x.add_argument("--unit")
    x.add_argument("--finding"); x.add_argument("--product"); x.add_argument("--image")
    x = ch.add_parser("edge"); x.add_argument("cid"); x.add_argument("src"); x.add_argument("dst"); x.add_argument("--actor", required=True)
    x.add_argument("--relation", default="reaches"); x.add_argument("--preconditions", required=True, help="JSON list file")
    x = ch.add_parser("check"); x.add_argument("cid"); x.add_argument("precondition_id"); x.add_argument("--state", required=True)
    x.add_argument("--actor", required=True); x.add_argument("--receipt", required=True)
    x = ch.add_parser("reuse"); x.add_argument("cid"); x.add_argument("node_id"); x.add_argument("--product", required=True)
    x.add_argument("--entry-label", required=True); x.add_argument("--actor", required=True); x.add_argument("--template")
    x = ch.add_parser("show"); x.add_argument("cid"); x.add_argument("--product")

    wl = cmd("wishlist").add_subparsers(dest="sub", required=True)
    x = wl.add_parser("request", help="record a needed capability (deduplicated per campaign/scope/kind/item)")
    x.add_argument("cid"); x.add_argument("--actor", required=True); x.add_argument("--kind", required=True)
    x.add_argument("--item", required=True); x.add_argument("--reason", required=True); x.add_argument("--required-for", required=True)
    x.add_argument("--scope", default="campaign"); x.add_argument("--job"); x.add_argument("--image"); x.add_argument("--member")
    x.add_argument("--code-unit"); x.add_argument("--finding"); x.add_argument("--blocking", action="store_true")
    x = wl.add_parser("list"); x.add_argument("cid"); x.add_argument("--status"); x.add_argument("--kind")
    x = wl.add_parser("show"); x.add_argument("wish_id")
    x = wl.add_parser("resolve", help="operator/human supervisor only; provided/denied need an evidence receipt")
    x.add_argument("cid"); x.add_argument("wish_id"); x.add_argument("--actor", required=True); x.add_argument("--status", required=True)
    x.add_argument("--receipt", required=True); x.add_argument("--capability", help="JSON capability reference file (no secrets)")
    x.add_argument("--superseded-by")
    x.add_argument("--decision", help="JSON triage record: disposition, rationale, assessment, revisit_trigger, alternative_ref")
    x = wl.add_parser("revisit", help="supervisor pass: reopen deferred/declined items whose revisit trigger now holds")
    x.add_argument("cid"); x.add_argument("--actor", required=True)

    ar = cmd("artifact").add_subparsers(dest="sub", required=True)
    x = ar.add_parser("register", help="operator only: hash + snapshot a file/dir under a configured root (no body stored)")
    x.add_argument("cid"); x.add_argument("--actor", required=True); x.add_argument("--root", required=True)
    x.add_argument("--path", required=True, help="path relative to the root"); x.add_argument("--kind", required=True)
    x.add_argument("--class", dest="retention_class", required=True); x.add_argument("--media-type"); x.add_argument("--sha256")
    x.add_argument("--producer", help="JSON provenance file (tool, version|commit, inputs, config_sha256, rebuild_ref)")
    x.add_argument("--labels", help="JSON object file"); x.add_argument("--expires-at", type=float)
    for link in ("job", "image", "member", "code-unit", "finding", "run"):
        x.add_argument(f"--{link}")
    x = ar.add_parser("show"); x.add_argument("artifact_id")
    x = ar.add_parser("list"); x.add_argument("cid"); x.add_argument("--state"); x.add_argument("--class", dest="retention_class")
    x = ar.add_parser("reference"); x.add_argument("cid"); x.add_argument("artifact_id"); x.add_argument("--actor", required=True)
    x.add_argument("--ref-type", required=True); x.add_argument("--ref-id", required=True); x.add_argument("--reason", required=True)
    x = ar.add_parser("hold", help="lease (needs --expires-at) or hold; blocks cleanup while active")
    x.add_argument("cid"); x.add_argument("artifact_id"); x.add_argument("--actor", required=True); x.add_argument("--kind", required=True)
    x.add_argument("--reason", required=True); x.add_argument("--expires-at", type=float); x.add_argument("--job")
    x = ar.add_parser("release"); x.add_argument("cid"); x.add_argument("--actor", required=True); x.add_argument("--reason", required=True)
    x.add_argument("--hold"); x.add_argument("--reference")
    x = ar.add_parser("pin"); x.add_argument("cid"); x.add_argument("artifact_id"); x.add_argument("--actor", required=True)
    x.add_argument("--reason", required=True); x.add_argument("--unpin", action="store_true")

    st = cmd("storage").add_subparsers(dest="sub", required=True)
    x = st.add_parser("root-add", help="operator only; roots are immutable once configured")
    x.add_argument("name"); x.add_argument("path"); x.add_argument("--role", default="managed"); x.add_argument("--actor", required=True)
    st.add_parser("roots")
    x = st.add_parser("thresholds", help="show thresholds; with --thresholds FILE --actor A, configure them")
    x.add_argument("--thresholds"); x.add_argument("--actor")
    x = st.add_parser("inventory"); x.add_argument("--cid")
    st.add_parser("status", help="latest durable pressure sample + guidance (read-only; never samples)")
    x = st.add_parser("sample", help="operator only: take a durable disk-pressure sample"); x.add_argument("--actor", required=True)
    x = st.add_parser("intent", help="operator only: declare a job's storage intent (none|light|heavy)")
    x.add_argument("cid"); x.add_argument("job_id"); x.add_argument("--actor", required=True); x.add_argument("--intent", required=True)
    x.add_argument("--reason", required=True); x.add_argument("--estimated-bytes", type=int)
    x = st.add_parser("plan", help="read-only preview by default; --record --actor A --rationale R persists an immutable plan")
    x.add_argument("cid"); x.add_argument("--policy"); x.add_argument("--record", action="store_true")
    x.add_argument("--actor"); x.add_argument("--rationale")
    x = st.add_parser("plans"); x.add_argument("cid")
    x = st.add_parser("plan-show"); x.add_argument("plan_id")
    x = st.add_parser("validate", help="read-only dry run of a recorded plan"); x.add_argument("cid"); x.add_argument("plan_id")
    for name, ref in (("apply", "plan_id"), ("restore", "artifact_id"), ("purge", "plan_id")):
        x = st.add_parser(name, help="dry run unless --execute (operator only)")
        x.add_argument("cid"); x.add_argument(ref); x.add_argument("--actor", required=True); x.add_argument("--execute", action="store_true")

    lg = cmd("ledger").add_subparsers(dest="sub", required=True)
    x = lg.add_parser("verify"); x.add_argument("cid")
    x = lg.add_parser("list"); x.add_argument("cid"); x.add_argument("--kind")
    return p


def dispatch(lite: RefallLite, a: argparse.Namespace) -> Any:
    c, s = a.cmd, getattr(a, "sub", None)
    if c == "info":
        return lite.store_info()
    if c == "actor":
        return lite.register_actor(a.actor_id, a.kind, a.provider) if s == "add" else lite.list_actors()
    if c == "campaign":
        if s == "create":
            return lite.create_campaign(a.name, config=_load(a.config), actor=a.actor)
        if s == "stop":
            return lite.stop_campaign(a.cid, actor=a.actor, reason=a.reason)
        return lite.list_campaigns()
    if c == "status":
        return lite.status(a.cid)
    if c == "image":
        if s == "ingest":
            d = _load(a.file)
            return lite.ingest_image(a.cid, family=d["family"], name=d["name"], image_sha256=d["image_sha256"],
                                     members=d["members"], actor=a.actor, metadata=d.get("metadata"))
        return lite.member_occurrences(a.cid, a.sha256)
    if c == "job":
        if s == "enqueue-images":
            return lite.enqueue_image_jobs(a.cid, stage=a.stage, kind=a.kind, actor=a.actor)
        if s == "enqueue-members":
            return lite.enqueue_member_jobs(a.cid, stage=a.stage, kind=a.kind, actor=a.actor)
        if s == "claim":
            return lite.claim_job(a.cid, worker=a.worker, stage=a.stage)
        if s == "packet":
            return lite.job_packet(a.cid, a.job_id)
        if s == "submit":
            return lite.submit_result(a.cid, a.job_id, a.token, _load(a.file))
        if s == "fail":
            return lite.fail_job(a.cid, a.job_id, a.token, status=a.status, error=a.error, cost_units=a.cost)
        if s == "cancel":
            return lite.cancel_job(a.cid, a.job_id, actor=a.actor, reason=a.reason)
        return lite.list_jobs(a.cid, stage=a.stage, status=a.status)
    if c == "stage":
        if s == "gate":
            return lite.stage_gate(a.cid)
        if s == "advance":
            return lite.advance_stage(a.cid, actor=a.actor)
        return lite.select_for_deep(a.cid, a.sha256, actor=a.actor, reason=a.reason)
    if c == "finding":
        if s == "list":
            return lite.list_findings(a.cid, tier=a.tier)
        if s == "show":
            return lite.get_finding(a.finding_id)
        if s == "record":
            return lite.record_finding(a.cid, actor=a.actor, candidate=_load(a.file))
        if s == "transition":
            return lite.transition_finding(a.cid, a.finding_id, actor=a.actor, to=a.to, receipt_type=a.receipt_type,
                                           receipt=_load(a.receipt), duplicate_of=a.duplicate_of)
        return lite.finding_occurrences(a.finding_id)
    if c == "escalation":
        if s == "request":
            return lite.request_escalation(a.cid, a.sha256, actor=a.actor, finding_id=a.finding, receipt=_load(a.receipt))
        return lite.approve_escalation(a.cid, a.action_id, actor=a.actor, receipt=_load(a.receipt))
    if c == "pending":
        if s == "list":
            return lite.list_pending_actions(a.cid, open_only=not a.all)
        return lite.resolve_pending_action(a.cid, a.action_id, actor=a.actor, status=a.status,
                                           receipt_type=a.receipt_type, receipt=_load(a.receipt))
    if c == "budget":
        if s == "show":
            return lite.budget_usage(a.cid)
        return lite.raise_budget(a.cid, a.scope, actor=a.actor, max_claims=a.max_claims, max_cost=a.max_cost, reason=a.reason)
    if c == "manifest":
        return lite.put_manifest(a.cid, run_id=a.run_id, actor=a.actor, **(_load(a.fields) or {}))
    if c == "checkpoint":
        return lite.checkpoint(a.cid, stage=a.stage, key=a.key, input_hashes=_load(a.hashes), actor=a.actor)
    if c == "resume":
        return lite.resume(a.cid, actor=a.actor, current_hashes=_load(a.hashes) or None)
    if c == "report":
        return lite.draft_report(a.cid, actor=a.actor) if s == "draft" else lite.get_report(a.cid)
    if c == "closeout":
        return lite.closeout_gate(a.cid) if s == "check" else lite.closeout(a.cid, actor=a.actor)
    if c == "lineage":
        return _lineage(lite, a, s)
    if c == "applicability":
        if s == "propagate":
            return lite.propagate_finding(a.cid, a.finding_id, actor=a.actor)
        if s == "list":
            return lite.list_applicability(a.cid, finding_id=a.finding, state=a.state)
        if s == "check":
            return lite.record_applicability_check(a.cid, a.row_id, gate=a.gate, status=a.status, actor=a.actor, receipt=_load(a.receipt))
        return lite.decide_applicability(a.cid, a.row_id, state=a.state, actor=a.actor, receipt_type=a.receipt_type, receipt=_load(a.receipt))
    if c == "chain":
        if s == "node":
            return lite.add_chain_node(a.cid, actor=a.actor, kind=a.kind, label=a.label, scope=a.scope, family_id=a.family,
                                       code_unit_id=a.unit, finding_id=a.finding, product_family=a.product, image_id=a.image)
        if s == "edge":
            return lite.add_chain_edge(a.cid, a.src, a.dst, actor=a.actor, relation=a.relation, preconditions=_load(a.preconditions))
        if s == "check":
            return lite.check_precondition(a.cid, a.precondition_id, state=a.state, actor=a.actor, receipt=_load(a.receipt))
        if s == "reuse":
            return lite.reuse_chain_node(a.cid, a.node_id, product_family=a.product, actor=a.actor, entry_label=a.entry_label,
                                         template_edge_id=a.template)
        return lite.attack_chain(a.cid, product_family=a.product)
    if c == "wishlist":
        if s == "request":
            return lite.request_wish(a.cid, actor=a.actor, kind=a.kind, item=a.item, reason=a.reason, required_for=a.required_for,
                                     scope=a.scope, job_id=a.job, image_id=a.image, member_sha256=a.member,
                                     code_unit_id=a.code_unit, finding_id=a.finding, blocking=a.blocking)
        if s == "list":
            return lite.list_wishes(a.cid, status=a.status, kind=a.kind)
        if s == "show":
            return lite.get_wish(a.wish_id)
        if s == "revisit":
            return lite.revisit_wishes(a.cid, actor=a.actor)
        return lite.resolve_wish(a.cid, a.wish_id, actor=a.actor, status=a.status, receipt=_load(a.receipt),
                                 capability=_load(a.capability) or None, superseded_by=a.superseded_by,
                                 decision=_load(a.decision) or None)
    if c == "artifact":
        return _artifact(lite, a, s)
    if c == "storage":
        return _storage(lite, a, s)
    if c == "ledger":
        return lite.verify_ledger(a.cid) if s == "verify" else lite.ledger(a.cid, a.kind)
    raise ValueError(f"unknown command {c}")


def _artifact(lite: RefallLite, a: argparse.Namespace, s: str) -> Any:
    if s == "register":
        return lite.register_artifact(a.cid, actor=a.actor, root=a.root, path=a.path, kind=a.kind,
                                      retention_class=a.retention_class, media_type=a.media_type, sha256=a.sha256,
                                      producer=_load(a.producer) or None, labels=_load(a.labels) or None, expires_at=a.expires_at,
                                      job_id=a.job, image_id=a.image, member_sha256=a.member, code_unit_id=a.code_unit,
                                      finding_id=a.finding, run_id=a.run)
    if s == "show":
        return lite.get_artifact(a.artifact_id)
    if s == "list":
        return lite.list_artifacts(a.cid, state=a.state, retention_class=a.retention_class)
    if s == "reference":
        return lite.reference_artifact(a.cid, a.artifact_id, actor=a.actor, ref_type=a.ref_type, ref_id=a.ref_id, reason=a.reason)
    if s == "hold":
        return lite.hold_artifact(a.cid, a.artifact_id, actor=a.actor, kind=a.kind, reason=a.reason,
                                  expires_at=a.expires_at, job_id=a.job)
    if s == "release":
        return lite.release_artifact(a.cid, actor=a.actor, reason=a.reason, hold_id=a.hold, reference_id=a.reference)
    return lite.pin_artifact(a.cid, a.artifact_id, actor=a.actor, reason=a.reason, pinned=not a.unpin)


def _storage(lite: RefallLite, a: argparse.Namespace, s: str) -> Any:
    if s == "root-add":
        return lite.configure_storage_root(a.name, a.path, role=a.role, actor=a.actor)
    if s == "roots":
        return lite.list_storage_roots()
    if s == "thresholds":
        if not a.thresholds:
            return lite.storage_thresholds()
        if not a.actor:
            raise ValueError("--actor is required to configure thresholds")
        return lite.configure_storage_thresholds(actor=a.actor, thresholds=_load(a.thresholds))
    if s == "inventory":
        return lite.storage_inventory(a.cid)
    if s == "status":
        return lite.storage_status()
    if s == "sample":
        return lite.sample_storage(actor=a.actor)
    if s == "intent":
        return lite.set_job_storage_intent(a.cid, a.job_id, actor=a.actor, intent=a.intent, reason=a.reason,
                                           estimated_bytes=a.estimated_bytes)
    if s == "plan":
        policy = _load(a.policy) or None
        if not a.record:
            return lite.preview_cleanup(a.cid, policy=policy)
        if not (a.actor and a.rationale):
            raise ValueError("--record requires --actor and --rationale")
        return lite.plan_cleanup(a.cid, actor=a.actor, rationale=a.rationale, policy=policy)
    if s == "plans":
        return lite.list_cleanup_plans(a.cid)
    if s == "plan-show":
        return lite.get_cleanup_plan(a.plan_id)
    if s == "validate":
        return lite.validate_cleanup_plan(a.cid, a.plan_id)
    if s == "apply":
        return lite.apply_cleanup_plan(a.cid, a.plan_id, actor=a.actor, execute=a.execute)
    if s == "restore":
        return lite.restore_artifact(a.cid, a.artifact_id, actor=a.actor, execute=a.execute)
    return lite.purge_cleanup_plan(a.cid, a.plan_id, actor=a.actor, execute=a.execute)


def _lineage(lite: RefallLite, a: argparse.Namespace, s: str) -> Any:
    if s == "ingest":
        data = _load(a.file)
        batches = data if isinstance(data, list) else [data]
        return [lite.ingest_fingerprints(a.cid, actor=a.actor, content_sha256=b.get("content_sha256"), unit_id=b.get("unit_id"),
                                         observations=b["observations"], granularity=b.get("granularity", "file"), name=b.get("name", ""))
                for b in batches]
    if s == "unit":
        return lite.register_code_unit(a.cid, a.sha256, actor=a.actor, granularity=a.granularity, name=a.name, parent_unit_id=a.parent)
    if s == "units":
        return lite.list_code_units(a.cid, content_sha256=a.content)
    if s == "observations":
        return lite.unit_observations(a.unit_id, current_only=not a.all_versions)
    if s == "pass":
        return lite.run_lineage_pass(a.cid, actor=a.actor)
    if s == "compare":
        return lite.compare_units(a.cid, a.unit_a, a.unit_b, actor=a.actor)
    if s == "edges":
        return lite.list_similarity_edges(a.cid, unit_id=a.unit, status=a.status)
    if s == "edge-approve":
        return lite.approve_edge(a.cid, a.edge_id, actor=a.actor, receipt_type=a.receipt_type, receipt=_load(a.receipt) or None)
    if s == "edge-reject":
        return lite.reject_edge(a.cid, a.edge_id, actor=a.actor, receipt_type=a.receipt_type, receipt=_load(a.receipt) or None)
    if s == "propose":
        return lite.propose_cluster(a.cid, a.units, actor=a.actor, name=a.name)
    if s == "approve":
        return lite.approve_cluster(a.cid, a.family_id, actor=a.actor, receipt_type=a.receipt_type, receipt=_load(a.receipt) or None)
    if s == "reject":
        return lite.reject_cluster(a.cid, a.family_id, actor=a.actor, receipt_type=a.receipt_type, receipt=_load(a.receipt))
    if s == "families":
        return lite.list_families(a.cid, status=a.status)
    if s == "family":
        return lite.get_family(a.family_id)
    if s == "representative":
        return lite.select_representative(a.cid, a.family_id, actor=a.actor, unit_id=a.unit)
    if s == "plan":
        return lite.plan_lineage_work(a.cid, actor=a.actor, kind=a.kind)
    if s == "deltas":
        return lite.list_delta_jobs(a.cid)
    if s == "receipts":
        return lite.list_delta_receipts(a.cid) if a.delta else lite.list_analysis_receipts(a.cid, unit_id=a.unit)
    if s == "reuse":
        return lite.list_reuse(a.cid)
    if s == "reuse-negative":
        return lite.reuse_negative_result(a.cid, a.receipt_id, a.unit_id, actor=a.actor)
    if s == "set-algorithm":
        return lite.set_fingerprint_algorithm(a.cid, a.version, actor=a.actor, reason=a.reason)
    if s == "show":
        return lite.lineage(a.cid, a.sha256)
    if s == "knowledge":
        return lite.reusable_knowledge(a.cid, a.sha256)
    return lite.lineage_config(a.cid)


def _record_inputs(tel: Any, a: argparse.Namespace) -> list[dict]:
    """Every file argument: digest + bounded redacted artifact; --config also as config.load."""
    out = []
    for name in FILE_ARGS:
        path = getattr(a, name, None)
        if not path:
            continue
        p = Path(path)
        item: dict[str, Any] = {"arg": name, "path": str(p), "exists": p.is_file()}
        if p.is_file():
            data = p.read_bytes()
            item.update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
            item["artifact"] = tel.artifact(f"cli-input-{name}", data)
            tel.record_io("input", f"cli:{name}", path=str(p), sha256=item["sha256"], size=item["size"])
            if name == "config":
                try:
                    tel.record_config("campaign-config", str(p), json.loads(data))
                except ValueError as exc:
                    tel.exception(exc, message="campaign config is not JSON")
        out.append(item)
    return out


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    tel = resolve_telemetry(None)
    try:
        tel.start_process(["refall-lite", *raw], kind="cli")
    except ObservabilityError as exc:
        print(json.dumps({"error": f"ObservabilityError: {exc}"}))
        return 4
    try:
        args = build_parser().parse_args(raw)
    except SystemExit as exc:  # argparse usage error (message already on stderr)
        tel.emit("cli.error", {"exit_code": exc.code, "error_type": "ArgumentError", "argv": tel.redactor.sanitize_argv(raw)})
        tel.end_process(exc.code if isinstance(exc.code, int) else 2)
        raise
    command = " ".join(x for x in (args.cmd, getattr(args, "sub", None)) if x)
    try:
        inv = tel.emit("cli.invoke", {"command": command, "argv": tel.redactor.sanitize_argv(["refall-lite", *raw]),
                                      "db": str(args.db), "inputs": _record_inputs(tel, args)},
                       critical=True, component="refall-lite.cli")
    except ObservabilityError as exc:
        print(json.dumps({"error": f"ObservabilityError: {exc}"}))
        tel.end_process(4, status="refused")
        return 4
    code, err = 0, None
    with tel.bind(parent_event_id=(inv or {}).get("event_id")):
        try:
            with RefallLite(args.db, telemetry=tel) as lite:
                out = dispatch(lite, args)
        except ObservabilityError as exc:
            code, err = 4, exc
            text = json.dumps({"error": f"ObservabilityError: {exc}"})
        except IncompatibleStoreError as exc:
            code, err = 3, exc
            text = json.dumps({"error": f"IncompatibleStoreError: {exc}"})
        except (ValueError, KeyError, PermissionError, FileNotFoundError) as exc:
            code, err = 2, exc
            text = json.dumps({"error": f"{type(exc).__name__}: {exc}"})
        except BaseException as exc:
            tel.exception(exc, event_type="cli.error", data={"command": command, "exit_code": 1, "error_type": type(exc).__name__},
                          component="refall-lite.cli")
            tel.crash(exc)
            raise
        else:
            text = json.dumps(out, sort_keys=True, default=str, indent=1)
        print(text)
        meta = {"command": command, "exit_code": code, "stdout_sha256": digest(text + "\n"),
                "stdout_length": len((text + "\n").encode("utf-8"))}
        if err is not None:
            tel.exception(err, event_type="cli.error", data={**meta, "error_type": type(err).__name__},
                          component="refall-lite.cli")
        else:
            tel.emit("cli.result", meta, component="refall-lite.cli")
    tel.end_process(code)
    return code


if __name__ == "__main__":
    sys.exit(main())
