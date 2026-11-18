"""Read side: validation, filtering, chain reconstruction, integrity verification, dead-letter recovery, vendoring."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator

from .core import SCHEMA, TAXONOMY, LEVELS
from .sink import FILE_MODE, format_human, iter_events, read_index, segment_files, sha256_bytes, verify_segments

PKG_DIR = Path(__file__).resolve().parent
_PATTERNS = {k: re.compile(v["pattern"]) for k, v in SCHEMA["properties"].items() if "pattern" in v}
_ALLOWED = set(SCHEMA["properties"])


def validate_event(ev: dict) -> list[str]:
    errs = []
    for k in SCHEMA["required"]:
        if k not in ev:
            errs.append(f"missing {k}")
    for k in ev:
        if k not in _ALLOWED:
            errs.append(f"unexpected field {k}")
    if ev.get("schema_version") != SCHEMA["schema_version"]:
        errs.append(f"schema_version {ev.get('schema_version')!r}")
    for k, rx in _PATTERNS.items():
        if k in ev and ev[k] is not None and not rx.match(str(ev[k])):
            errs.append(f"{k} does not match {rx.pattern}")
    for k in ("seq", "pid", "monotonic_ns"):
        if k in ev and (not isinstance(ev[k], int) or isinstance(ev[k], bool)):
            errs.append(f"{k} must be integer")
    if isinstance(ev.get("seq"), int) and ev["seq"] < 1:
        errs.append("seq must be >= 1")
    if ev.get("level") not in LEVELS:
        errs.append(f"level {ev.get('level')!r}")
    spec = TAXONOMY.get(ev.get("event_type", ""))
    if spec is None:
        errs.append(f"unknown event_type {ev.get('event_type')!r}")
    elif not isinstance(ev.get("data"), dict):
        errs.append("data must be object")
    elif not ev["data"].get("_bounded"):
        for key in spec["required_data"]:
            if key not in ev["data"]:
                errs.append(f"{ev['event_type']} missing data.{key}")
    return errs


def events(log_dir: str | os.PathLike) -> list[dict]:
    return list(iter_events(Path(log_dir)))


def match(ev: dict, **flt: Any) -> bool:
    for k, v in flt.items():
        if v is None:
            continue
        if k == "type_prefix":
            if not ev.get("event_type", "").startswith(v):
                return False
        elif k == "min_level":
            if LEVELS.index(ev.get("level", "debug")) < LEVELS.index(v):
                return False
        elif ev.get(k) != v:
            return False
    return True


def run_order(evs: Iterable[dict]) -> list[dict]:
    """Exact per-run order: (run_id, seq). Within a run seq is the authoritative order."""
    return sorted(evs, key=lambda e: (e["run_id"], e["seq"]))


def chain(log_dir: str | os.PathLike, **flt: Any) -> list[dict]:
    """All events matching any correlation filter, plus their ancestors via parent_event_id, in run order."""
    evs = events(log_dir)
    by_id = {e["event_id"]: e for e in evs}
    picked = {e["event_id"] for e in evs if match(e, **flt)}
    frontier = list(picked)
    while frontier:
        e = by_id.get(frontier.pop())
        p = e and e.get("parent_event_id")
        if p and p in by_id and p not in picked:
            picked.add(p)
            frontier.append(p)
    return run_order(by_id[i] for i in picked)


def tree(evs: list[dict]) -> list[str]:
    kids: dict[str | None, list[dict]] = defaultdict(list)
    ids = {e["event_id"] for e in evs}
    for e in evs:
        kids[e.get("parent_event_id") if e.get("parent_event_id") in ids else None].append(e)
    out: list[str] = []

    def walk(pid: str | None, depth: int) -> None:
        for e in kids.get(pid, []):
            corr = " ".join(f"{k}={e[k]}" for k in ("campaign_id", "job_id", "model_call_id", "tool_call_id") if e.get(k))
            out.append(f"{'  ' * depth}#{e['seq']} {e['event_type']} [{e['level']}] {corr}".rstrip())
            walk(e["event_id"], depth + 1)
    walk(None, 0)
    return out


def load_artifact(log_dir: str | os.PathLike, run_id: str, ref: str) -> dict:
    return json.loads((Path(log_dir) / "runs" / run_id / "artifacts" / f"{ref}.json").read_text())


def verify(log_dir: str | os.PathLike) -> dict:
    """Schema, per-run seq uniqueness/order, artifact references + hashes, segment checksums, manifests."""
    root = Path(log_dir)
    problems: list[dict] = []
    seen_ids: set[str] = set()
    per_run: dict[str, list[int]] = defaultdict(list)
    n = 0
    art_refs: list[tuple[str, str, str]] = []
    try:
        evs = list(iter_events(root))
    except ValueError as exc:
        return {"ok": False, "events": 0, "problems": [{"problem": str(exc)}]}
    for ev in evs:
        n += 1
        for err in validate_event(ev):
            problems.append({"event_id": ev.get("event_id"), "problem": err})
        if ev.get("event_id") in seen_ids:
            problems.append({"event_id": ev.get("event_id"), "problem": "duplicate event_id"})
        seen_ids.add(ev.get("event_id"))
        per_run[ev.get("run_id")].append(ev.get("seq"))
        for ref in ev.get("log_artifacts") or []:
            art_refs.append((ev["run_id"], ref, ev["event_id"]))
    gaps = {}
    for run, seqs in per_run.items():
        if len(seqs) != len(set(seqs)):
            problems.append({"run_id": run, "problem": "duplicate seq"})
        if seqs != sorted(seqs):
            problems.append({"run_id": run, "problem": "seq not increasing in file order"})
        missing = sorted(set(range(1, max(seqs) + 1)) - set(seqs))
        if missing:
            gaps[run] = missing[:20]
    for run, ref, evid in art_refs:
        p = root / "runs" / run / "artifacts" / f"{ref}.json"
        if not p.exists():
            problems.append({"event_id": evid, "problem": f"artifact {ref} missing"})
            continue
        env = json.loads(p.read_text())
        body = env.get("body")
        if body is not None:
            if sha256_bytes(body.encode("utf-8")) != env["stored_sha256"]:
                problems.append({"artifact": ref, "problem": "stored_sha256 mismatch"})
            if not env["truncated"] and env["stored_sha256"] != env["sha256"]:
                problems.append({"artifact": ref, "problem": "untruncated artifact sha256 mismatch"})
            if env["truncated"] != (env["stored_length"] < env["original_length"]):
                problems.append({"artifact": ref, "problem": "truncation flag inconsistent"})
    seg = verify_segments(root)
    problems += seg["problems"]
    known = {name for name, _p, _e in segment_files(root)}
    manifests = 0
    for mp in sorted((root / "runs").glob("*/manifest.json")):
        manifests += 1
        man = json.loads(mp.read_text())
        for s in man.get("segments", []):
            if s not in known:
                problems.append({"run_id": man["run_id"], "problem": f"manifest references unknown segment {s}"})
    perms = []
    for p in root.rglob("*"):
        if p.is_file() and (p.stat().st_mode & 0o077):
            perms.append(str(p.relative_to(root)))
    if perms:
        problems.append({"problem": "files readable by group/other", "files": perms[:20]})
    return {"ok": not problems, "events": n, "runs": len(per_run), "artifact_refs": len(art_refs), "segments": seg["segments"],
            "manifests": manifests, "seq_gaps": gaps, "problems": problems[:200]}


def scan_for(paths: Iterable[str | os.PathLike], needles: Iterable[str]) -> list[dict]:
    """Search every file (gz-aware) for any needle. Used by secret-canary tests."""
    import gzip
    needles = [n for n in needles if n]
    hits = []
    for base in paths:
        base = Path(base)
        files = [base] if base.is_file() else [p for p in base.rglob("*") if p.is_file()]
        for p in files:
            data = p.read_bytes()
            if p.name.endswith(".gz"):
                try:
                    data = gzip.decompress(data)
                except OSError:
                    pass
            text = data.decode("utf-8", errors="ignore")
            for nd in needles:
                if nd in text:
                    hits.append({"file": str(p), "needle_sha256": hashlib.sha256(nd.encode()).hexdigest()[:16]})
    return hits


def recover_deadletter(tel, deadletter_dir: str | os.PathLike) -> dict:
    """Re-import dead-lettered events (new seq, original ids/ts kept, provenance in data._deadletter)."""
    d = Path(deadletter_dir)
    recovered = 0
    files = sorted(d.glob("deadletter-*.jsonl"))
    for f in files:
        for ln in f.read_text().splitlines():
            if not ln.strip():
                continue
            rec = json.loads(ln)
            ev = rec.get("event")
            if not ev or "event_type" not in ev:
                continue
            ev = dict(ev)
            ev["data"] = {**(ev.get("data") or {}), "_deadletter": {"reason": rec.get("reason"), "dead_ts": rec.get("ts"),
                                                                     "reserved_seq": rec.get("reserved_seq")}}
            tel.sink.write_event(ev)
            recovered += 1
        f.rename(f.with_name(f.name + ".recovered"))
        os.chmod(f.with_name(f.name + ".recovered"), FILE_MODE)
    tel.emit("telemetry.deadletter_recovered", {"files": [f.name for f in files], "events": recovered})
    return {"files": len(files), "events": recovered}


def vendor(dest: str | os.PathLike, *, node_dest: str | os.PathLike | None = None) -> dict:
    """Copy this package (and the Node emitter) to a deployment directory with a hash manifest.

    External scripts import the vendored copy through ``fwspider_telemetry_loader`` semantics:
    installed package first, else ``FIRMWARE_SPIDER_TELEMETRY_PATH``, else ``<project home>/lib``;
    the VENDORED.json hashes are verified before import.
    """
    from . import __version__
    from .core import git_commit
    dest = Path(dest)
    target = dest / "fwspider_telemetry"
    if target.exists():
        shutil.rmtree(target)
    files = {}
    for p in sorted(PKG_DIR.rglob("*")):
        if p.is_dir() or "__pycache__" in p.parts or p.suffix == ".pyc":
            continue
        rel = p.relative_to(PKG_DIR)
        out = target / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, out)
        files[rel.as_posix()] = sha256_bytes(out.read_bytes())
    manifest = {"schema_version": "fwspider.vendored.v1", "package": "fwspider_telemetry", "version": __version__,
                "source": str(PKG_DIR), "source_git_commit": git_commit(PKG_DIR), "files": files}
    (target / "VENDORED.json").write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    out = {"python": str(target), "files": len(files)}
    if node_dest:
        nd = Path(node_dest)
        nd.mkdir(parents=True, exist_ok=True)
        nfiles = {}
        for name, src in (("fwspider-telemetry.mjs", PKG_DIR / "node" / "fwspider-telemetry.mjs"),
                          ("event-schema.json", PKG_DIR / "event-schema.json"),
                          ("redaction-rules.json", PKG_DIR / "redaction-rules.json")):
            shutil.copyfile(src, nd / name)
            nfiles[name] = sha256_bytes((nd / name).read_bytes())
        (nd / "VENDORED.json").write_text(json.dumps({**manifest, "files": nfiles, "language": "node"}, indent=1, sort_keys=True) + "\n")
        out["node"] = str(nd)
    return out


def verify_vendored(target: str | os.PathLike) -> dict:
    target = Path(target)
    man = json.loads((target / "VENDORED.json").read_text())
    bad = [f for f, h in man["files"].items() if not (target / f).is_file() or sha256_bytes((target / f).read_bytes()) != h]
    return {"ok": not bad, "mismatched": bad, "version": man.get("version"), "source_git_commit": man.get("source_git_commit")}


def render(log_dir: str | os.PathLike) -> Iterator[str]:
    for ev in iter_events(Path(log_dir)):
        yield format_human(ev)


def segments(log_dir: str | os.PathLike) -> list[dict]:
    return read_index(Path(log_dir))
