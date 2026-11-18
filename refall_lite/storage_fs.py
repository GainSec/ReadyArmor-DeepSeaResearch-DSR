"""Filesystem safety for the artifact registry (stdlib only).

Every mutation the registry performs goes through this module, and only ever below a configured root:
  * roots are canonicalised once (realpath, must be a real directory, not a symlink) and re-checked by (dev, inode)
    before every use, so a root swapped for a symlink or another directory is refused;
  * relative artifact paths are walked component by component with lstat: traversal (``..``), absolute paths,
    symlinks anywhere on the path, and device files, sockets and FIFOs are refused, never followed;
  * snapshots record type/dev/inode/size/mtime_ns/nlink plus a content hash (files) or a tree digest (directories)
    so drift between plan and apply is detected and the changed target is refused rather than deleted;
  * moves are a single same-filesystem ``rename`` into a freshly created (exclusive) directory, so nothing is ever
    overwritten and no large body is copied; cross-device moves are refused;
  * removal never follows symlinks (``shutil.rmtree`` with symlink-attack protection, else refused).
No file body is ever returned to the caller; only hashes, sizes and metadata.
"""
from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import shutil
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

HASH_CHUNK = 1 << 20
TREE_MAX_ENTRIES = 200_000


class UnsafePathError(ValueError):
    """A path is outside its root, traverses a symlink, or names something that is not a regular file/directory."""


def _kind(mode: int) -> str:
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "device"
    return "other"


def canonical_root(path: str) -> tuple[str, os.stat_result]:
    """Canonical real path of a configured root. The path given must itself be a real directory (not a symlink)."""
    if not isinstance(path, str) or not path.strip() or "\x00" in path:
        raise ValueError("storage root path required")
    p = Path(path).expanduser()
    if not p.is_absolute():
        raise ValueError("storage root path must be absolute")
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        raise ValueError(f"storage root does not exist: {path}") from None
    if stat.S_ISLNK(st.st_mode):
        raise UnsafePathError("storage root must not be a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise ValueError("storage root must be a directory")
    real = os.path.realpath(p)
    return real, os.lstat(real)


def check_root(real: str, dev: int, ino: int) -> None:
    """The configured root is still the same real directory (no swap for a symlink or another tree)."""
    try:
        st = os.lstat(real)
    except FileNotFoundError:
        raise UnsafePathError("storage root is missing") from None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or (st.st_dev, st.st_ino) != (dev, ino):
        raise UnsafePathError("storage root changed identity since it was configured")


def normalize_rel(rel: str) -> str:
    """Validate a root-relative path lexically: no absolute path, NUL, empty, '.' or '..' component."""
    if not isinstance(rel, str) or not rel.strip() or "\x00" in rel:
        raise UnsafePathError("artifact path required")
    if rel.startswith(("/", "\\")) or os.path.isabs(rel):
        raise UnsafePathError("artifact path must be relative to its storage root")
    parts = rel.replace("\\", "/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise UnsafePathError("artifact path must not contain empty, '.' or '..' components (no traversal)")
    return "/".join(parts)


def resolve(root_real: str, rel: str, *, must_exist: bool = True) -> Path:
    """Walk ``rel`` under the root with lstat; every parent must be a real directory, the leaf a file or directory."""
    rel = normalize_rel(rel)
    current = Path(root_real)
    parts = rel.split("/")
    for i, part in enumerate(parts):
        current = current / part
        try:
            st = os.lstat(current)
        except FileNotFoundError:
            if must_exist:
                raise UnsafePathError(f"artifact path does not exist: {rel}") from None
            return Path(root_real, *parts)
        kind = _kind(st.st_mode)
        leaf = i == len(parts) - 1
        if kind == "symlink":
            raise UnsafePathError(f"artifact path traverses a symlink at component {i + 1} (symlinks are never followed)")
        if not leaf and kind != "dir":
            raise UnsafePathError(f"artifact path component {i + 1} is a {kind}, not a directory")
        if leaf and kind not in ("file", "dir"):
            raise UnsafePathError(f"artifact is a {kind}; only regular files and directories are managed")
    real = os.path.realpath(current)
    if os.path.commonpath([real, root_real]) != root_real:
        raise UnsafePathError("artifact path escapes its storage root")
    return current


def ensure_dirs(root_real: str, rel_dir: str) -> Path:
    """Create (if needed) a directory chain below the root, refusing any symlink or non-directory on the way."""
    current = Path(root_real)
    for part in normalize_rel(rel_dir).split("/"):
        current = current / part
        try:
            os.mkdir(current, 0o700)
        except FileExistsError:
            pass
        st = os.lstat(current)
        if _kind(st.st_mode) != "dir":
            raise UnsafePathError("quarantine/restore directory chain contains a non-directory or symlink")
    return current


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as fh:
        for chunk in iter(lambda: fh.read(HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def snapshot(path: Path, *, hash_limit: int | None) -> dict:
    """Identity + drift snapshot. ``hash_limit``: hash regular files up to this size (None = always).

    Directory snapshots walk the tree without following symlinks; device files, sockets and FIFOs inside a tree are
    refused. ``tree_digest`` covers (relpath, type, size, mtime_ns, inode) of every entry below the top directory;
    ``content_sha256`` (when hashing) covers file contents and symlink targets."""
    st = os.lstat(path)
    kind = _kind(st.st_mode)
    snap = {"type": kind, "dev": st.st_dev, "ino": st.st_ino, "nlink": st.st_nlink}
    if kind == "file":
        snap.update(size=st.st_size, mtime_ns=st.st_mtime_ns, reclaim_bytes=st.st_size if st.st_nlink == 1 else 0)
        if hash_limit is None or st.st_size <= hash_limit:
            snap["sha256"] = file_sha256(path)
        return snap
    if kind != "dir":
        raise UnsafePathError(f"artifact is a {kind}; only regular files and directories are managed")
    tree, content = hashlib.sha256(), hashlib.sha256()
    hashed, size, reclaim, entries = True, 0, 0, 0
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        dirnames.sort()
        for name in sorted(dirnames + filenames):
            full = Path(dirpath, name)
            rel = full.relative_to(path).as_posix()
            est = os.lstat(full)
            ek = _kind(est.st_mode)
            entries += 1
            if entries > TREE_MAX_ENTRIES:
                raise UnsafePathError(f"directory artifact exceeds {TREE_MAX_ENTRIES} entries")
            if ek in ("device", "socket", "fifo", "other"):
                raise UnsafePathError(f"directory artifact contains a {ek} entry; refused")
            esize = est.st_size if ek == "file" else 0
            tree.update(f"{rel}\0{ek}\0{esize}\0{est.st_mtime_ns}\0{est.st_ino}\n".encode())
            if ek == "file":
                size += esize
                reclaim += esize if est.st_nlink == 1 else 0
                if hash_limit is None or esize <= hash_limit:
                    content.update(f"{rel}\0file\0{file_sha256(full)}\n".encode())
                else:
                    hashed = False
            elif ek == "symlink":
                content.update(f"{rel}\0symlink\0{os.readlink(full)}\n".encode())
            else:
                content.update(f"{rel}\0dir\n".encode())
    snap.update(size=size, reclaim_bytes=reclaim, entries=entries, tree_digest=tree.hexdigest())
    if hashed:
        snap["sha256"] = content.hexdigest()
    return snap


# Fields compared between plan and apply (before a move) and before/after a move. A directory's own mtime is
# excluded on purpose: renaming a directory may update it, while every child change shows in tree_digest.
DRIFT_FIELDS = ("type", "dev", "ino", "size", "mtime_ns", "nlink", "tree_digest", "sha256")


def drift(expected: dict, actual: dict) -> list[str]:
    """Names of snapshot fields that differ (a hash is compared only when both sides carry one)."""
    out = []
    for key in DRIFT_FIELDS:
        if key == "sha256" and not (expected.get(key) and actual.get(key)):
            continue
        if expected.get(key) != actual.get(key):
            out.append(key)
    return out


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def move_into_fresh_dir(src: Path, dest_dir: Path, name: str) -> Path:
    """Atomically rename ``src`` to ``dest_dir/name``. ``dest_dir`` is created exclusively (or must be an empty real
    directory left by an interrupted attempt), so nothing is overwritten. Same filesystem only."""
    try:
        os.mkdir(dest_dir, 0o700)
    except FileExistsError:
        st = os.lstat(dest_dir)
        if _kind(st.st_mode) != "dir" or any(os.scandir(dest_dir)):
            raise UnsafePathError("quarantine slot already exists and is not an empty directory") from None
    if os.lstat(src).st_dev != os.lstat(dest_dir).st_dev:
        os.rmdir(dest_dir)
        raise UnsafePathError("cross-device move refused (quarantine root is on another filesystem; no copy fallback)")
    dest = dest_dir / name
    try:
        os.rename(src, dest)
    except OSError as exc:
        if exc.errno == errno.EXDEV:
            raise UnsafePathError("cross-device move refused") from None
        raise
    _fsync_dir(dest_dir)
    _fsync_dir(src.parent)
    return dest


def move_back(src: Path, dest: Path) -> None:
    """Rename ``src`` to ``dest`` only if ``dest`` is absent (restore / undo); never overwrites."""
    try:
        os.lstat(dest)
    except FileNotFoundError:
        pass
    else:
        raise UnsafePathError("restore target already exists; refusing to overwrite")
    if os.lstat(src).st_dev != os.lstat(dest.parent).st_dev:
        raise UnsafePathError("cross-device restore refused")
    os.rename(src, dest)
    _fsync_dir(dest.parent)
    _fsync_dir(src.parent)


LOCK_NAME = ".dsr-storage.lock"


@contextmanager
def mutation_lock(quarantine_root: str) -> Iterator[None]:
    """Host-wide exclusive lock for storage mutation (apply/restore/purge). Non-blocking: a second holder is refused.
    flock is released by the OS if the holder dies, so crash recovery never races a live mutator."""
    fd = os.open(Path(quarantine_root, LOCK_NAME), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise UnsafePathError("another storage mutation holds the storage lock; retry after it finishes") from None
        yield
    finally:
        os.close(fd)


def exists(path: Path) -> bool:
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False


def remove(path: Path) -> None:
    """Delete a quarantined body without following symlinks. Missing is fine (idempotent)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return
    kind = _kind(st.st_mode)
    if kind == "dir":
        if not shutil.rmtree.avoids_symlink_attacks:
            raise UnsafePathError("this platform's rmtree cannot avoid symlink attacks; directory purge refused")
        shutil.rmtree(path)
    elif kind == "file":
        os.unlink(path)
    else:
        raise UnsafePathError(f"refusing to purge a {kind}")
    _fsync_dir(path.parent)
    # remove now-empty quarantine slot directory (best effort, never recursive)
    try:
        os.rmdir(path.parent)
    except OSError:
        pass
