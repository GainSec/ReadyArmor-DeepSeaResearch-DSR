"""Host-side glue for the D1 promotion gate (``verify.promote_or_hold``).

The live hunt records a finding's ``claim`` in whatever shape the model emitted:
source findings carry reproducible byte anchors (``{offset:int, hex}``) alongside
free-text ``node@file:line`` call paths and ``{from,to}`` line pairs; binary
findings carry a decompiler *narrative* in ``bytes.hex`` with a ``vaddr:`` offset.
``check_consistency`` only parses canonical mechanical facts, so this module:

* ``normalize_claim`` reduces a recorded claim to the mechanically-checkable facts
  in canonical shape, dropping anything that is narrative rather than reproducible.
* ``file_rea_query`` is a deterministic ``rea_query`` that reproduces byte anchors
  by reading the member file itself -- the host half of the two-source check for
  source targets (no REA call graph exists for a ``.py``).
* ``make_file_rea_facts_fn`` adapts those into the ``rea_facts_fn(lite, cid,
  finding)`` hook that ``run_slice``/``promote_or_hold`` consume.
"""
from __future__ import annotations

from typing import Callable, Iterable

_HEXDIGITS = set("0123456789abcdefABCDEF")


def _is_hex(s) -> bool:
    return isinstance(s, str) and len(s) > 0 and len(s) % 2 == 0 and all(c in _HEXDIGITS for c in s)


def _int_offset(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None  # e.g. "vaddr:0x41d2b8" -> not a file offset we can reproduce


def _canon_bytes(raw) -> list[dict]:
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for b in raw:
        if not isinstance(b, dict):
            continue
        off = _int_offset(b.get("offset"))
        hx = b.get("hex")
        if off is None or not _is_hex(hx):
            continue  # narrative / vaddr entries are not reproducible bytes
        out.append({"offset": off, "hex": hx})
    return out


def _canon_xrefs(raw) -> list[dict]:
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for x in raw:
        if not isinstance(x, dict) or "from" not in x:
            continue  # bare "0x.." strings are not from/target pairs
        if "target" in x:
            out.append({"from": x["from"], "target": x["target"]})
        elif "to" in x:
            out.append({"from": x["from"], "target": x["to"]})
    return out


def _canon_call_path(raw) -> list[list]:
    if isinstance(raw, dict):
        raw = raw.get("edges")
    if not isinstance(raw, list):
        return []
    out: list[list] = []
    for e in raw:
        if isinstance(e, (list, tuple)) and len(e) == 2:
            out.append([e[0], e[1]])
        elif isinstance(e, dict) and "from" in e and "to" in e:
            out.append([e["from"], e["to"]])
        # free-text "node@file:line" strings are not mechanical edges -> dropped
    return out


def normalize_claim(claim: dict, *, keep: Iterable[str] = ("bytes", "call_path", "xrefs")) -> dict:
    """Return a claim holding only canonical, mechanically-checkable facts.

    ``keep`` restricts which fact kinds survive (source targets pass ``("bytes",)``
    since only byte anchors are reproducible for them). Empty fact lists are
    omitted so a claim with nothing reproducible never falsely verifies."""
    claim = claim or {}
    keep = set(keep)
    out: dict = {}
    if "bytes" in keep:
        b = _canon_bytes(claim.get("bytes"))
        if b:
            out["bytes"] = b
    if "call_path" in keep:
        cp = _canon_call_path(claim.get("call_path"))
        if cp:
            out["call_path"] = cp
    if "xrefs" in keep:
        xr = _canon_xrefs(claim.get("xrefs"))
        if xr:
            out["xrefs"] = xr
    return out


def line_offset_rederive(path: str, claim: dict) -> dict:
    """Deterministic independent re-derivation of byte anchors for a SOURCE target.

    A fresh model cannot reliably transcribe exact byte hex (it approximates), so for a
    source byte-anchor the sound independent source is deterministic: locate each anchor by
    its claimed ``line`` and confirm the claimed ``offset`` falls within that line AND the
    bytes there equal the claimed ``hex``. This catches a confabulated offset/line/hex
    (any inconsistency with the file drops the anchor) and is independent of the offset-seek
    host read in that it indexes by line. Anchors with no usable ``line`` fall back to an
    offset-only byte confirmation. Returns ``{"bytes": [{offset, hex}]}`` for the survivors."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return {}
    lines = raw.splitlines(keepends=True)
    starts: list[int] = []
    pos = 0
    for ln in lines:
        starts.append(pos)
        pos += len(ln)
    raw_bytes = (claim or {}).get("bytes")
    if isinstance(raw_bytes, dict):  # live claims sometimes store a single dict, not a list
        raw_bytes = [raw_bytes]
    out: list[dict] = []
    for b in raw_bytes if isinstance(raw_bytes, list) else []:
        if not isinstance(b, dict) or not _is_hex(b.get("hex")):
            continue
        off = _int_offset(b.get("offset"))
        if off is None or off < 0:
            continue
        hx = b["hex"].lower()
        want = bytes.fromhex(hx)
        if raw[off:off + len(want)] != want:
            continue  # claimed bytes are not actually at the claimed offset
        line_no = b.get("line")
        if isinstance(line_no, int) and 1 <= line_no <= len(lines):
            lo = starts[line_no - 1]
            hi = lo + len(lines[line_no - 1])
            if not (lo <= off < hi):
                continue  # offset/line disagree -> inconsistent, hold
        out.append({"offset": off, "hex": hx})
    return {"bytes": out} if out else {}


def file_rea_query(path: str) -> Callable[[str, dict], object]:
    """A deterministic ``rea_query`` that reproduces byte anchors from ``path``.

    Implements only ``read_bytes {offset, length} -> hex``; every other op returns
    ``None`` (so call_path/xref facts stay unsupported -> held) and any read error
    or short read returns ``None`` rather than a partial match."""
    def query(op: str, args: dict):
        if op != "read_bytes":
            return None
        off, length = args.get("offset"), args.get("length")
        if not isinstance(off, int) or not isinstance(length, int) or off < 0 or length <= 0:
            return None
        try:
            with open(path, "rb") as f:
                f.seek(off)
                data = f.read(length)
        except OSError:
            return None
        if len(data) != length:
            return None
        return data.hex()
    return query


def make_file_rea_facts_fn(resolve_path: Callable[[object, str, dict], str | None],
                           *, keep: Iterable[str] = ("bytes",)):
    """Build a ``rea_facts_fn(lite, cid, finding)`` that reproduces byte anchors
    from the finding's member file. ``resolve_path(lite, cid, finding)`` returns the
    on-disk path of the member (or ``None`` -> empty facts -> held)."""
    from .verify import host_rea_facts

    def rea_facts_fn(lite, cid, finding: dict) -> dict:
        path = resolve_path(lite, cid, finding)
        if not path:
            return {}
        norm = normalize_claim(finding.get("claim") or {}, keep=keep)
        return host_rea_facts({"claim": norm}, rea_query=file_rea_query(path))

    return rea_facts_fn
