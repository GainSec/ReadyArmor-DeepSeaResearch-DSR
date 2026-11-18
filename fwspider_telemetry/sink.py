"""Append-only, concurrency-safe JSONL sink shared by Python and Node writers.

Layout under the log directory (dirs 0700, files 0600)::

    .lock/                      mkdir-based inter-process lock (owner.json inside)
    events/ACTIVE               number of the active segment
    events/current.jsonl        active segment (becomes seg-NNNNNN.jsonl[.gz] on rotation)
    events/INDEX.jsonl          one hash-chained line per closed / deleted segment
    human/current.log           human-readable view derived from the same events
    human/seg-NNNNNN.log[.gz]
    runs/<run_id>/state.json    per-run sequence counter + segment membership
    runs/<run_id>/manifest.json per-run manifest
    runs/<run_id>/artifacts/    bounded artifact envelopes (art_*.json)

The lock protocol (mkdir of ``.lock`` + ``owner.json``) is identical in the Node
implementation, so both languages can write the same directory concurrently.
Sequence numbers are reserved (state.json written) *before* the event line is
appended, so a failed append can leave a gap but never a duplicate.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import socket
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

DIR_MODE = 0o700
FILE_MODE = 0o600
SEGMENT_INDEX_SCHEMA = "fwspider.segment-index.v1"
MANIFEST_SCHEMA = "fwspider.run-manifest.v1"
EVENT_KEY_ORDER = ("schema_version", "event_id", "ts", "monotonic_ns", "seq", "level", "event_type", "component", "host",
                   "pid", "run_id", "process_id", "parent_event_id", "campaign_id", "job_id", "model_call_id",
                   "tool_call_id", "artifact_id", "finding_id", "message", "data", "log_artifacts", "redaction", "debug")


class LockTimeout(TimeoutError):
    pass


def ordered(ev: dict) -> dict:
    out = {k: ev[k] for k in EVENT_KEY_ORDER if k in ev and ev[k] is not None}
    for k, v in ev.items():
        if k not in out and v is not None:
            out[k] = v
    return out


def dumps_line(ev: dict) -> str:
    return json.dumps(ordered(ev), ensure_ascii=False, separators=(",", ":"), default=str) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def format_human(ev: dict, width: int = 400) -> str:
    ids = " ".join(f"{k.split('_')[0] if k != 'model_call_id' else 'model'}={ev[k]}" for k in
                   ("campaign_id", "job_id", "model_call_id", "tool_call_id", "finding_id", "artifact_id") if ev.get(k))
    data = json.dumps(ev.get("data") or {}, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)
    if len(data) > width:
        data = f"{data[:width]}…(+{len(data) - width} chars; full data in event {ev.get('event_id')})"
    red = f" redactions={ev['redaction']['count']}" if ev.get("redaction") else ""
    msg = f" {ev['message']}" if ev.get("message") else ""
    return (f"{ev.get('ts')} {ev.get('level', '?').upper():<8} {ev.get('component')} run={ev.get('run_id')} "
            f"seq={ev.get('seq')} {ev.get('event_type')}{(' ' + ids) if ids else ''}{msg}{red} {data}\n")


class LogDir:
    def __init__(self, root: Path, *, rotate_bytes: int, compress: bool = True, fsync: bool = False,
                 retention_segments: int | None = None, retention_days: float | None = None,
                 lock_timeout_s: float = 30.0, stale_lock_s: float = 120.0) -> None:
        self.root = Path(root)
        self.rotate_bytes = rotate_bytes
        self.compress = compress
        self.fsync = fsync
        self.retention_segments = retention_segments
        self.retention_days = retention_days
        self.lock_timeout_s = lock_timeout_s
        self.stale_lock_s = stale_lock_s
        self._tlock = threading.RLock()
        self._held = 0
        self.host = socket.gethostname()

    # -- paths -------------------------------------------------------------------------
    @property
    def events_dir(self) -> Path:
        return self.root / "events"

    @property
    def current(self) -> Path:
        return self.events_dir / "current.jsonl"

    @property
    def human_current(self) -> Path:
        return self.root / "human" / "current.log"

    @property
    def index_path(self) -> Path:
        return self.events_dir / "INDEX.jsonl"

    def run_dir(self, run_id: str) -> Path:
        return self.root / "runs" / run_id

    # -- setup ---------------------------------------------------------------------------
    def ensure(self) -> None:
        for d in (self.root, self.events_dir, self.root / "human", self.root / "runs"):
            self._mkdir(d)

    def _mkdir(self, d: Path) -> None:
        """Create d and any missing ancestors with 0700 (Path.mkdir(parents=True) would use the umask)."""
        if d.is_dir():
            return
        missing = []
        cur = d
        while not cur.is_dir():
            missing.append(cur)
            cur = cur.parent
        for m in reversed(missing):
            try:
                os.mkdir(m, DIR_MODE)
            except FileExistsError:
                pass
            os.chmod(m, DIR_MODE)

    def _write_new(self, path: Path, data: bytes) -> None:
        """Atomic replace with 0600 permissions."""
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, FILE_MODE)
        try:
            os.write(fd, data)
            if self.fsync:
                os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)

    def _append(self, path: Path, data: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, FILE_MODE)
        try:
            n = os.write(fd, data)
            if n != len(data):  # never silently drop part of a record
                raise OSError(f"short write to {path}: {n} of {len(data)} bytes")
            if self.fsync:
                os.fsync(fd)
        finally:
            os.close(fd)

    # -- lock (shared protocol with Node) ----------------------------------------------
    @contextmanager
    def lock(self) -> Iterator[None]:
        with self._tlock:
            if self._held:
                self._held += 1
                try:
                    yield
                finally:
                    self._held -= 1
                return
            self._acquire()
            self._held = 1
            try:
                yield
            finally:
                self._held = 0
                self._release()

    def _acquire(self) -> None:
        lock = self.root / ".lock"
        deadline = time.monotonic() + self.lock_timeout_s
        delay = 0.0005
        while True:
            try:
                os.mkdir(lock, DIR_MODE)
                owner = json.dumps({"host": self.host, "pid": os.getpid(), "ts": time.time(), "lang": "python"}).encode()
                fd = os.open(lock / "owner.json", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE)
                try:
                    os.write(fd, owner)
                finally:
                    os.close(fd)
                return
            except FileExistsError:
                self._maybe_break_stale(lock)
            except FileNotFoundError:
                self._mkdir(self.root)  # first writer: create the log root, then retry
                continue
            if time.monotonic() > deadline:
                raise LockTimeout(f"could not acquire telemetry lock {lock} within {self.lock_timeout_s}s")
            time.sleep(delay)
            delay = min(delay * 2, 0.02)

    def _maybe_break_stale(self, lock: Path) -> None:
        try:
            st = lock.stat()
        except FileNotFoundError:
            return
        try:
            owner = json.loads((lock / "owner.json").read_text())
        except (OSError, ValueError):
            owner = None
        age = time.time() - st.st_mtime
        stale = False
        if owner and owner.get("host") == self.host and isinstance(owner.get("pid"), int) and not _pid_alive(owner["pid"]):
            stale = True
        elif age > self.stale_lock_s:
            stale = True
        elif owner is None and age > 5.0:
            stale = True  # creator died between mkdir and owner write
        if stale:
            grave = lock.with_name(f".lock.stale-{uuid.uuid4().hex[:8]}")
            try:
                os.rename(lock, grave)
            except OSError:
                return
            shutil.rmtree(grave, ignore_errors=True)

    def _release(self) -> None:
        lock = self.root / ".lock"
        try:
            (lock / "owner.json").unlink()
        except FileNotFoundError:
            pass
        os.rmdir(lock)

    # -- run state -----------------------------------------------------------------------
    def read_state(self, run_id: str) -> dict:
        p = self.run_dir(run_id) / "state.json"
        try:
            return json.loads(p.read_text())
        except FileNotFoundError:
            return {}

    def active_segment(self) -> int:
        p = self.events_dir / "ACTIVE"
        try:
            return int(p.read_text().strip())
        except FileNotFoundError:
            self._write_new(p, b"1\n")
            return 1

    # -- write path ----------------------------------------------------------------------
    def write_event(self, ev: dict, *, on_rotate: Callable[[dict], dict] | None = None) -> dict:
        """Reserve the next per-run seq, append JSONL + human line, rotate if needed. Returns the event."""
        with self.lock():
            self.ensure()
            rd = self.run_dir(ev["run_id"])
            self._mkdir(rd)
            state = self.read_state(ev["run_id"])
            seg = self.active_segment()
            seq = int(state.get("seq", 0)) + 1
            state["seq"] = seq
            state["events"] = int(state.get("events", 0)) + 1
            segs = state.setdefault("segments", [])
            if seg not in segs:
                segs.append(seg)
            state.setdefault("first_ts", ev["ts"])
            state["last_ts"] = ev["ts"]
            state["run_id"] = ev["run_id"]
            # reserve first: a failed append leaves a gap, never a reused seq
            self._write_new(rd / "state.json", json.dumps(state, sort_keys=True).encode())
            ev["seq"] = seq
            line = dumps_line(ev).encode("utf-8")
            self._append(self.current, line)
            self._append(self.human_current, format_human(ev).encode("utf-8"))
            if self.current.stat().st_size >= self.rotate_bytes:
                rot = self.rotate()
                if on_rotate:
                    on_rotate(rot)
            return ev

    # -- rotation / retention ----------------------------------------------------------
    def _seal(self, src: Path, dst_base: Path) -> dict:
        data = src.read_bytes()
        info = {"uncompressed_sha256": sha256_bytes(data), "uncompressed_bytes": len(data)}
        if self.compress:
            gz = gzip.compress(data, mtime=0)
            if gzip.decompress(gz) != data:  # pragma: no cover - defensive
                raise OSError(f"compression round-trip failed for {src}")
            dst = dst_base.with_name(dst_base.name + ".gz")
            self._write_new(dst, gz)
            src.unlink()
            info.update(file=dst.name, sha256=sha256_bytes(gz), bytes=len(gz), compressed=True)
        else:
            os.replace(src, dst_base)
            os.chmod(dst_base, FILE_MODE)
            info.update(file=dst_base.name, sha256=info["uncompressed_sha256"], bytes=len(data), compressed=False)
        return info

    def _index_entries(self) -> list[dict]:
        try:
            return [json.loads(ln) for ln in self.index_path.read_text().splitlines() if ln.strip()]
        except FileNotFoundError:
            return []

    def _append_index(self, entry: dict) -> dict:
        prev = self._index_entries()
        entry["prev_entry_sha256"] = prev[-1]["entry_sha256"] if prev else "0" * 64
        body = json.dumps({k: v for k, v in entry.items() if k != "entry_sha256"}, sort_keys=True)
        entry["entry_sha256"] = sha256_bytes(body.encode())
        self._append(self.index_path, (json.dumps(entry, sort_keys=True) + "\n").encode())
        return entry

    def rotate(self) -> dict:
        """Close the active segment (checksummed, optionally gzip) and open the next one. Caller holds the lock."""
        with self.lock():
            seg = self.active_segment()
            if not self.current.exists() or self.current.stat().st_size == 0:
                return {}
            runs: dict[str, list[int]] = {}
            events = 0
            first_ts = last_ts = None
            for ln in self.current.read_text(encoding="utf-8").splitlines():
                if not ln.strip():
                    continue
                ev = json.loads(ln)
                events += 1
                r = runs.setdefault(ev["run_id"], [ev["seq"], ev["seq"]])
                r[0], r[1] = min(r[0], ev["seq"]), max(r[1], ev["seq"])
                first_ts = first_ts or ev["ts"]
                last_ts = ev["ts"]
            name = f"seg-{seg:06d}"
            info = self._seal(self.current, self.events_dir / f"{name}.jsonl")
            human = {}
            if self.human_current.exists():
                human = self._seal(self.human_current, self.root / "human" / f"{name}.log")
            entry = self._append_index({
                "schema_version": SEGMENT_INDEX_SCHEMA, "segment": seg, "name": name, **info, "events": events,
                "runs": runs, "first_ts": first_ts, "last_ts": last_ts, "status": "present",
                "human": {k: human[k] for k in ("file", "sha256", "bytes", "uncompressed_sha256")} if human else None,
                "closed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
            self._write_new(self.events_dir / "ACTIVE", f"{seg + 1}\n".encode())
            deleted = self.apply_retention()
            return {"closed": entry, "deleted": deleted}

    def apply_retention(self) -> list[dict]:
        entries = self._index_entries()
        status: dict[int, dict] = {}
        for e in entries:
            status[e["segment"]] = e
        present = sorted((e for e in status.values() if e["status"] == "present"), key=lambda e: e["segment"])
        doomed: list[dict] = []
        if self.retention_segments is not None and len(present) > self.retention_segments:
            doomed = present[: len(present) - self.retention_segments]
        if self.retention_days is not None:
            cutoff = time.time() - self.retention_days * 86400
            for e in present:
                p = self.events_dir / e["file"]
                if p.exists() and p.stat().st_mtime < cutoff and e not in doomed:
                    doomed.append(e)
        out = []
        for e in doomed:
            for p in (self.events_dir / e["file"], self.root / "human" / (e.get("human") or {}).get("file", "\0")):
                try:
                    p.unlink()
                except (FileNotFoundError, OSError):
                    pass
            tomb = {k: v for k, v in e.items() if k not in {"entry_sha256", "prev_entry_sha256"}}
            tomb.update(status="deleted", deleted_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        reason="retention")
            out.append(self._append_index(tomb))
        return out

    # -- artifacts / manifests ----------------------------------------------------------
    def write_artifact(self, run_id: str, ref: str, envelope: dict) -> Path:
        d = self.run_dir(run_id) / "artifacts"
        self._mkdir(d)
        p = d / f"{ref}.json"
        self._write_new(p, (json.dumps(envelope, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8"))
        return p

    def update_manifest(self, run_id: str, mutate: Callable[[dict], None]) -> dict:
        with self.lock():
            self.ensure()
            rd = self.run_dir(run_id)
            self._mkdir(rd)
            p = rd / "manifest.json"
            try:
                man = json.loads(p.read_text())
            except FileNotFoundError:
                now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                man = {"schema_version": MANIFEST_SCHEMA, "run_id": run_id, "created_at": now, "updated_at": now,
                       "status": "running", "processes": [], "segments": [], "events": {}, "inputs": [], "outputs": [],
                       "components": {}, "config_digests": {}, "models": [], "telemetry_failures": 0}
            mutate(man)
            st = self.read_state(run_id)
            man["segments"] = [f"seg-{s:06d}" for s in st.get("segments", [])]
            man["events"] = {"count": st.get("events", 0), "last_seq": st.get("seq", 0),
                             "first_ts": st.get("first_ts"), "last_ts": st.get("last_ts")}
            man["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            procs = man.get("processes", [])
            if any(pr.get("ended_at") is None for pr in procs):
                man["status"] = "running"
            elif any(pr.get("status") == "crashed" for pr in procs):
                man["status"] = "crashed"
            elif any(pr.get("exit_code") not in (0, None) for pr in procs):
                man["status"] = "completed_with_errors"
            elif procs:
                man["status"] = "completed"
            if man.get("closed_status"):
                man["status"] = man["closed_status"]
            self._write_new(p, (json.dumps(man, sort_keys=True, indent=1) + "\n").encode())
            return man


# -- reading ----------------------------------------------------------------------------
def read_index(root: Path) -> list[dict]:
    p = Path(root) / "events" / "INDEX.jsonl"
    try:
        return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]
    except FileNotFoundError:
        return []


def segment_files(root: Path) -> list[tuple[str, Path | None, dict | None]]:
    """Ordered (name, path-or-None-if-deleted, index-entry) for every segment incl. the active one."""
    root = Path(root)
    latest: dict[int, dict] = {}
    for e in read_index(root):
        latest[e["segment"]] = e
    out: list[tuple[str, Path | None, dict | None]] = []
    for seg in sorted(latest):
        e = latest[seg]
        p = root / "events" / e["file"]
        out.append((e["name"], p if e["status"] == "present" and p.exists() else None, e))
    cur = root / "events" / "current.jsonl"
    if cur.exists():
        try:
            active = int((root / "events" / "ACTIVE").read_text().strip())
        except (FileNotFoundError, ValueError):
            active = (max(latest) + 1) if latest else 1
        out.append((f"seg-{active:06d}", cur, None))
    return out


def iter_lines(path: Path) -> Iterator[str]:
    if path.name.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            yield from f
    else:
        with open(path, encoding="utf-8") as f:
            yield from f


def iter_events(root: Path, *, strict: bool = True) -> Iterator[dict]:
    for _name, path, _entry in segment_files(root):
        if path is None:
            continue
        for n, ln in enumerate(iter_lines(path), 1):
            if not ln.strip():
                continue
            try:
                yield json.loads(ln)
            except json.JSONDecodeError as exc:
                if strict:
                    raise ValueError(f"corrupt JSONL at {path}:{n}: {exc}") from exc


def verify_segments(root: Path) -> dict:
    """Check every present closed segment against its index checksum and the index hash chain."""
    root = Path(root)
    problems = []
    prev = "0" * 64
    entries = read_index(root)
    for e in entries:
        body = json.dumps({k: v for k, v in e.items() if k != "entry_sha256"}, sort_keys=True)
        if e.get("prev_entry_sha256") != prev or sha256_bytes(body.encode()) != e.get("entry_sha256"):
            problems.append({"segment": e.get("segment"), "problem": "index chain broken"})
        prev = e.get("entry_sha256", prev)
    latest: dict[int, dict] = {}
    for e in entries:
        latest[e["segment"]] = e
    for seg, e in sorted(latest.items()):
        p = root / "events" / e["file"]
        if e["status"] != "present":
            continue
        if not p.exists():
            problems.append({"segment": seg, "problem": "missing file"})
            continue
        if sha256_file(p) != e["sha256"]:
            problems.append({"segment": seg, "problem": "sha256 mismatch"})
            continue
        raw = gzip.decompress(p.read_bytes()) if e.get("compressed") else p.read_bytes()
        if sha256_bytes(raw) != e["uncompressed_sha256"]:
            problems.append({"segment": seg, "problem": "uncompressed sha256 mismatch"})
    return {"ok": not problems, "segments": len(latest), "problems": problems}
