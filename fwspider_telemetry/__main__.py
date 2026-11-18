"""fwspider-telemetry CLI: inspect one run / campaign / job / model / tool chain from the central logs.

    python -m fwspider_telemetry [--log-dir D] query  [--run R] [--campaign C] [--job J] [--model-call M]
                                                       [--tool-call T] [--finding F] [--type PREFIX] [--level L] [--json]
    python -m fwspider_telemetry [--log-dir D] chain  (--run R | --campaign C | --job J | --model-call M | --tool-call T) [--json]
    python -m fwspider_telemetry [--log-dir D] run    RUN_ID          # manifest + state + resolved segments
    python -m fwspider_telemetry [--log-dir D] artifact RUN_ID ART_REF
    python -m fwspider_telemetry [--log-dir D] verify                 # schema/seq/artifacts/segments/manifests/permissions
    python -m fwspider_telemetry [--log-dir D] render                 # regenerate the human log from JSONL
    python -m fwspider_telemetry [--log-dir D] segments
    python -m fwspider_telemetry [--log-dir D] recover --deadletter-dir DIR
    python -m fwspider_telemetry vendor --dest DIR [--node-dest DIR]
    python -m fwspider_telemetry verify-vendored DIR

Output is JSON unless the command says otherwise. This CLI only reads logs (except recover/vendor).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import query
from .config import resolve_log_dir
from .core import Telemetry


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fwspider-telemetry")
    ap.add_argument("--log-dir")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def filters(p: argparse.ArgumentParser) -> None:
        p.add_argument("--run"); p.add_argument("--campaign"); p.add_argument("--job"); p.add_argument("--model-call")
        p.add_argument("--tool-call"); p.add_argument("--finding"); p.add_argument("--type"); p.add_argument("--level")
        p.add_argument("--json", action="store_true")
    filters(sub.add_parser("query"))
    filters(sub.add_parser("chain"))
    x = sub.add_parser("run"); x.add_argument("run_id")
    x = sub.add_parser("artifact"); x.add_argument("run_id"); x.add_argument("ref")
    sub.add_parser("verify"); sub.add_parser("render"); sub.add_parser("segments")
    x = sub.add_parser("recover"); x.add_argument("--deadletter-dir", required=True)
    x = sub.add_parser("vendor"); x.add_argument("--dest", required=True); x.add_argument("--node-dest")
    x = sub.add_parser("verify-vendored"); x.add_argument("path")
    a = ap.parse_args(argv)
    log_dir = Path(a.log_dir) if a.log_dir else resolve_log_dir()[0]

    if a.cmd in {"query", "chain"}:
        flt = {"run_id": a.run, "campaign_id": a.campaign, "job_id": a.job, "model_call_id": a.model_call,
               "tool_call_id": a.tool_call, "finding_id": a.finding, "type_prefix": a.type, "min_level": a.level}
        if a.cmd == "chain":
            if not any(v for k, v in flt.items() if k not in {"type_prefix", "min_level"}):
                ap.error("chain needs a correlation filter")
            evs = query.chain(log_dir, **{k: v for k, v in flt.items() if k not in {"type_prefix", "min_level"}})
        else:
            evs = query.run_order(e for e in query.events(log_dir) if query.match(e, **flt))
        if a.json:
            print(json.dumps(evs, indent=1))
        elif a.cmd == "chain":
            print("\n".join(query.tree(evs)))
        else:
            sys.stdout.writelines(query.format_human(e) for e in evs)
        return 0
    if a.cmd == "run":
        rd = log_dir / "runs" / a.run_id
        man = json.loads((rd / "manifest.json").read_text())
        state = json.loads((rd / "state.json").read_text())
        segs = {name: (str(p) if p else None, (e or {}).get("status", "active")) for name, p, e in query.segment_files(log_dir)}
        print(json.dumps({"manifest": man, "state": state,
                          "segments": {s: segs.get(s, (None, "unknown")) for s in man.get("segments", [])}}, indent=1))
        return 0
    if a.cmd == "artifact":
        print(json.dumps(query.load_artifact(log_dir, a.run_id, a.ref), indent=1))
        return 0
    if a.cmd == "verify":
        res = query.verify(log_dir)
        print(json.dumps(res, indent=1))
        return 0 if res["ok"] else 1
    if a.cmd == "render":
        sys.stdout.writelines(query.render(log_dir))
        return 0
    if a.cmd == "segments":
        print(json.dumps(query.segments(log_dir), indent=1))
        return 0
    if a.cmd == "recover":
        tel = Telemetry("fwspider-telemetry.recover")
        with tel.guard(kind="cli", install_hooks=False):
            print(json.dumps(query.recover_deadletter(tel, a.deadletter_dir)))
        return 0
    if a.cmd == "vendor":
        print(json.dumps(query.vendor(a.dest, node_dest=a.node_dest), indent=1))
        return 0
    if a.cmd == "verify-vendored":
        res = query.verify_vendored(a.path)
        print(json.dumps(res, indent=1))
        return 0 if res["ok"] else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
