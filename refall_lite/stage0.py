"""Stage-0: single-image mechanical unpack + member enumeration (file ops only)."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Literal, Mapping

# kind -> argv-builder(image_path, out_dir) -> argv list (injectable for tests)
UnpackTools = Mapping[str, Callable[[str, str], list]]

DEFAULT_UNPACK: UnpackTools = {
    "squashfs": lambda img, out: ["unsquashfs", "-f", "-d", out, img],
    "gzip": lambda img, out: ["binwalk", "-e", "-C", out, img],
    "xz": lambda img, out: ["binwalk", "-e", "-C", out, img],
    "cpio": lambda img, out: ["binwalk", "-e", "-C", out, img],
    "7z": lambda img, out: ["7z", "x", "-y", "-o" + out, img],
}


@dataclass
class UnpackOutcome:
    status: Literal["extracted", "failed"]
    members: list = field(default_factory=list)
    reason: str = ""


def _sniff(head: bytes) -> str | None:
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"hsqs", b"sqsh"):
        return "squashfs"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:6] == b"\xfd7zXZ\x00" or head[:3] == b"\x5d\x00\x00":
        return "xz"
    if head[:6] in (b"070701", b"070702", b"070707"):
        return "cpio"
    if head[:4] == b"7z\xbc\xaf":
        return "7z"
    return None


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _member(full: str, rel: str) -> dict:
    return {"path": rel, "sha256": _sha256(full), "size_bytes": os.path.getsize(full)}


def expand_image(image_path: str, out_dir: str, *, tools: UnpackTools = DEFAULT_UNPACK) -> UnpackOutcome:
    try:
        with open(image_path, "rb") as f:
            head = f.read(16)
    except OSError as e:
        return UnpackOutcome("failed", [], f"cannot read image: {e}")
    kind = _sniff(head)
    if kind is None:
        return UnpackOutcome("failed", [], f"unrecognized magic {head.hex()}")
    if kind == "elf":
        name = os.path.basename(image_path)
        os.makedirs(out_dir, exist_ok=True)
        dest = os.path.join(out_dir, name)
        shutil.copy2(image_path, dest)  # contract: out_dir/path resolves to member bytes
        return UnpackOutcome("extracted", [_member(dest, name)], "")
    builder = tools.get(kind)
    if builder is None:
        return UnpackOutcome("failed", [], f"no unpack tool configured for {kind}")
    os.makedirs(out_dir, exist_ok=True)
    try:
        proc = subprocess.run(builder(image_path, out_dir), capture_output=True, timeout=600)
    except (OSError, subprocess.SubprocessError) as e:
        return UnpackOutcome("failed", [], f"{kind} tool error: {e}")
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()[:200]
        return UnpackOutcome("failed", [], f"{kind} tool exit {proc.returncode}: {err}")
    members = []
    for dp, _dn, fns in os.walk(out_dir):
        for fn in fns:
            full = os.path.join(dp, fn)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            members.append(_member(full, os.path.relpath(full, out_dir)))
    members.sort(key=lambda m: m["path"])
    if not members:
        return UnpackOutcome("failed", [], f"{kind} tool produced no files")
    return UnpackOutcome("extracted", members, "")
