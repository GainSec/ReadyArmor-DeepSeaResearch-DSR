"""Telemetry configuration: log directory resolution, policy, rotation, retention.

Resolution order for the log directory (first match wins):

1. explicit ``log_dir`` argument
2. ``FIRMWARE_SPIDER_LOG_DIR``
3. ``FIRMWARE_SPIDER_PROFILE`` = ``local`` | ``spark`` -> that profile's default
4. host detection: the profile whose project root exists *and* whose platform matches
   (``local``: macOS + /Users/dsr/firmware-spider;
   ``spark``: Linux + /home/dsr/firmware-spider)
5. ``FIRMWARE_SPIDER_HOME``/var/log
6. fallback ``$XDG_STATE_HOME`` (or ~/.local/state)/firmware-spider/log  (recorded as ``fallback``)

The chosen source is recorded in every process.start event and run manifest.
"""
from __future__ import annotations

import os
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

PROFILES = {
    "local": {"platform": "darwin", "home": "/Users/dsr/firmware-spider",
              "log_dir": "/Users/dsr/firmware-spider/var/log"},
    "spark": {"platform": "linux", "home": "/home/dsr/firmware-spider",
              "log_dir": "/home/dsr/firmware-spider/logs"},
}
POLICIES = ("strict", "degrade")


class ObservabilityError(RuntimeError):
    """Telemetry could not record a pre-operation event (strict policy) or could not start."""


def _truthy(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(value: str | None, default: int | None) -> int | None:
    if value is None or value.strip() == "":
        return default
    return int(value)


def detect_profile(platform: str | None = None, exists=os.path.isdir) -> str | None:
    plat = platform or sys.platform
    for name, spec in PROFILES.items():
        if plat.startswith(spec["platform"]) and exists(spec["home"]):
            return name
    return None


def resolve_log_dir(explicit: str | os.PathLike | None = None, env: Mapping[str, str] | None = None,
                    platform: str | None = None, exists=os.path.isdir) -> tuple[Path, str, str | None]:
    env = os.environ if env is None else env
    if explicit:
        return Path(explicit), "argument", None
    if env.get("FIRMWARE_SPIDER_LOG_DIR"):
        return Path(env["FIRMWARE_SPIDER_LOG_DIR"]), "env:FIRMWARE_SPIDER_LOG_DIR", env.get("FIRMWARE_SPIDER_PROFILE")
    prof = env.get("FIRMWARE_SPIDER_PROFILE")
    if prof:
        if prof not in PROFILES:
            raise ObservabilityError(f"FIRMWARE_SPIDER_PROFILE must be one of {sorted(PROFILES)}, got {prof!r}")
        return Path(PROFILES[prof]["log_dir"]), f"profile:{prof}(env)", prof
    det = detect_profile(platform, exists)
    if det:
        return Path(PROFILES[det]["log_dir"]), f"profile:{det}(detected)", det
    if env.get("FIRMWARE_SPIDER_HOME"):
        return Path(env["FIRMWARE_SPIDER_HOME"]) / "var" / "log", "env:FIRMWARE_SPIDER_HOME", None
    base = env.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return Path(base) / "firmware-spider" / "log", "fallback", None


def project_home(env: Mapping[str, str] | None = None, platform: str | None = None, exists=os.path.isdir) -> Path | None:
    env = os.environ if env is None else env
    if env.get("FIRMWARE_SPIDER_HOME"):
        return Path(env["FIRMWARE_SPIDER_HOME"])
    prof = env.get("FIRMWARE_SPIDER_PROFILE") or detect_profile(platform, exists)
    return Path(PROFILES[prof]["home"]) if prof in PROFILES else None


@dataclass
class TelemetryConfig:
    log_dir: Path
    log_dir_source: str = "argument"
    profile: str | None = None
    policy: str = "strict"
    debug: bool = False
    log_bodies: bool = True
    max_artifact_bytes: int = 256 * 1024
    max_inline_bytes: int = 16 * 1024
    rotate_bytes: int = 64 * 1024 * 1024
    retention_segments: int | None = None
    retention_days: float | None = None
    compress: bool = True
    fsync: bool = False
    lock_timeout_s: float = 30.0
    stale_lock_s: float = 120.0
    deadletter_dir: Path = field(default_factory=lambda: Path(tempfile.gettempdir()) / f"fwspider-deadletter-{os.getuid()}")
    extra_redact_patterns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.log_dir = Path(self.log_dir)
        self.deadletter_dir = Path(self.deadletter_dir)
        if self.policy not in POLICIES:
            raise ObservabilityError(f"telemetry policy must be one of {POLICIES}, got {self.policy!r}")
        if self.rotate_bytes < 1024:
            raise ObservabilityError("rotate_bytes must be >= 1024")
        if self.max_artifact_bytes < 256:
            raise ObservabilityError("max_artifact_bytes must be >= 256")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, **overrides) -> "TelemetryConfig":
        env = os.environ if env is None else env
        log_dir, source, profile = resolve_log_dir(overrides.pop("log_dir", None), env)
        kw = dict(
            log_dir=log_dir, log_dir_source=source, profile=profile,
            policy=env.get("FIRMWARE_SPIDER_TELEMETRY_POLICY", "strict") or "strict",
            debug=_truthy(env.get("FIRMWARE_SPIDER_DEBUG"), False),
            log_bodies=_truthy(env.get("FIRMWARE_SPIDER_LOG_BODIES"), True),
            max_artifact_bytes=_int(env.get("FIRMWARE_SPIDER_MAX_ARTIFACT_BYTES"), 256 * 1024),
            rotate_bytes=_int(env.get("FIRMWARE_SPIDER_LOG_ROTATE_BYTES"), 64 * 1024 * 1024),
            retention_segments=_int(env.get("FIRMWARE_SPIDER_LOG_RETENTION_SEGMENTS"), None),
            retention_days=float(env["FIRMWARE_SPIDER_LOG_RETENTION_DAYS"]) if env.get("FIRMWARE_SPIDER_LOG_RETENTION_DAYS") else None,
            compress=_truthy(env.get("FIRMWARE_SPIDER_LOG_COMPRESS"), True),
            fsync=_truthy(env.get("FIRMWARE_SPIDER_LOG_FSYNC"), False),
        )
        if env.get("FIRMWARE_SPIDER_DEADLETTER_DIR"):
            kw["deadletter_dir"] = Path(env["FIRMWARE_SPIDER_DEADLETTER_DIR"])
        kw.update(overrides)
        return cls(**kw)

    def effective(self) -> dict:
        return {
            "log_dir": str(self.log_dir), "log_dir_source": self.log_dir_source, "profile": self.profile,
            "policy": self.policy, "debug": self.debug, "log_bodies": self.log_bodies,
            "max_artifact_bytes": self.max_artifact_bytes, "max_inline_bytes": self.max_inline_bytes,
            "rotate_bytes": self.rotate_bytes, "retention_segments": self.retention_segments,
            "retention_days": self.retention_days, "compress": self.compress, "fsync": self.fsync,
            "deadletter_dir": str(self.deadletter_dir), "extra_redact_patterns": len(self.extra_redact_patterns),
        }
