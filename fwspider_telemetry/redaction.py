"""Central redaction pipeline. Runs on every value before it reaches disk.

Rules are shared with the Node emitter via ``redaction-rules.json``. Redaction is
pattern/key based and therefore conservative (over-redaction is acceptable);
see REDACTION-POLICY.md for what is and is not guaranteed.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

RULES_PATH = Path(__file__).with_name("redaction-rules.json")
RULES: dict = json.loads(RULES_PATH.read_text(encoding="utf-8"))
REDACTED: str = RULES["replacement"]
MAX_PATHS = 50


def _flags(spec: str) -> int:
    out = 0
    if "i" in spec:
        out |= re.IGNORECASE
    if "m" in spec:
        out |= re.MULTILINE
    if "s" in spec:
        out |= re.DOTALL
    return out


def luhn_ok(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@dataclass
class _Rule:
    name: str
    regex: re.Pattern
    keep: tuple[int, ...]
    luhn: bool = False


def _normalize_key(key: str) -> str:
    k = str(key).strip().lstrip("-").lower()
    return re.sub(r"[-. ]", "_", k)


@dataclass
class RedactionReport:
    count: int = 0
    rules: set[str] = field(default_factory=set)
    paths: list[str] = field(default_factory=list)

    def hit(self, rule: str, path: str) -> None:
        self.count += 1
        self.rules.add(rule)
        if len(self.paths) < MAX_PATHS and path not in self.paths:
            self.paths.append(path)

    def merge(self, other: "RedactionReport") -> None:
        self.count += other.count
        self.rules |= other.rules
        for p in other.paths:
            if len(self.paths) < MAX_PATHS and p not in self.paths:
                self.paths.append(p)

    def as_dict(self) -> dict | None:
        if not self.count:
            return None
        out = {"count": self.count, "rules": sorted(self.rules), "paths": self.paths}
        if len(self.paths) >= MAX_PATHS:
            out["paths_truncated"] = True
        return out


class Redactor:
    """Redacts strings (regex rules) and mappings (sensitive keys), recursively."""

    def __init__(self, extra_patterns: Iterable[str] = ()) -> None:
        self.rules: list[_Rule] = [
            _Rule(r["name"], re.compile(r["pattern"], _flags(r.get("flags", ""))), tuple(r.get("keep", [])), bool(r.get("luhn")))
            for r in RULES["string_rules"]
        ]
        for i, pat in enumerate(extra_patterns):
            self.rules.append(_Rule(f"custom_{i}", re.compile(pat), ()))
        self.key_re = re.compile(RULES["sensitive_key_pattern"])
        self.non_secret = set(RULES["non_secret_keys"])
        self.non_secret_exact = set(RULES.get("case_sensitive_non_secret_keys", []))

    @classmethod
    def from_env(cls, extra: Iterable[str] = ()) -> "Redactor":
        return cls([*extra, *load_extra_patterns(os.environ.get("FIRMWARE_SPIDER_REDACT_PATTERNS", ""))])

    def sensitive_key(self, key: Any) -> bool:
        if str(key) in self.non_secret_exact:
            return False
        k = _normalize_key(str(key))
        if k in self.non_secret:
            return False
        return bool(self.key_re.search(k))

    def redact_text(self, text: str, report: RedactionReport | None = None, path: str = "") -> str:
        for rule in self.rules:
            def repl(m: re.Match, rule: _Rule = rule) -> str:
                if rule.luhn and not luhn_ok(m.group(0)):
                    return m.group(0)
                if report is not None:
                    report.hit(rule.name, path or "$")
                if not rule.keep:
                    return REDACTED
                out = m.group(rule.keep[0]) or ""
                out += REDACTED
                for g in rule.keep[1:]:
                    out += m.group(g) or ""
                return out
            text = rule.regex.sub(repl, text)
        return text

    def redact(self, value: Any, report: RedactionReport | None = None, path: str = "$") -> Any:
        if isinstance(value, str):
            return self.redact_text(value, report, path)
        if isinstance(value, bytes):
            # bytes never go to disk raw; describe them
            return {"_bytes": True, "length": len(value), "sha256": hashlib.sha256(value).hexdigest()}
        if isinstance(value, dict):
            out = {}
            for k, v in value.items():
                key = str(k)
                sub = f"{path}.{key}"
                if self.sensitive_key(key) and v not in (None, "", [], {}):
                    if report is not None:
                        report.hit("sensitive_key", sub)
                    out[key] = REDACTED
                else:
                    out[key] = self.redact(v, report, sub)
            return out
        if isinstance(value, (list, tuple)):
            return [self.redact(v, report, f"{path}[{i}]") for i, v in enumerate(value)]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return self.redact_text(str(value), report, path)

    def sanitize_argv(self, argv: Iterable[Any], report: RedactionReport | None = None) -> list[str]:
        out: list[str] = []
        redact_next = False
        for i, raw in enumerate(argv):
            arg = str(raw)
            path = f"$.argv[{i}]"
            if redact_next:
                redact_next = False
                if report is not None:
                    report.hit("sensitive_flag_value", path)
                out.append(REDACTED)
                continue
            if arg.startswith("-") and "=" in arg:
                flag, _, val = arg.partition("=")
                if self.sensitive_key(flag) and val:
                    if report is not None:
                        report.hit("sensitive_flag_value", path)
                    out.append(f"{flag}={REDACTED}")
                    continue
            elif arg.startswith("-") and self.sensitive_key(arg):
                redact_next = True
            out.append(self.redact_text(arg, report, path))
        return out

    def env_summary(self, env: dict[str, str] | None, *, debug: bool = False,
                    report: RedactionReport | None = None) -> dict:
        """Allowlisted values (redacted) + digest over the whole environment. Never the full env."""
        env = dict(os.environ if env is None else env)
        allow = set(RULES["env_allowlist"])
        h = hashlib.sha256()
        for k in sorted(env):
            h.update(k.encode() + b"\0" + hashlib.sha256(str(env[k]).encode()).digest() + b"\n")
        out = {
            "allowlisted": {k: self.redact_text(str(env[k]), report, f"$.env.{k}") for k in sorted(env) if k in allow},
            "digest": "sha256:" + h.hexdigest(),
            "count": len(env),
        }
        if debug:
            out["names_sha256"] = hashlib.sha256("\n".join(sorted(env)).encode()).hexdigest()
        return out


def load_extra_patterns(spec: str) -> list[str]:
    """FIRMWARE_SPIDER_REDACT_PATTERNS: a JSON list of regexes, or a path to a file holding one."""
    spec = (spec or "").strip()
    if not spec:
        return []
    if not spec.startswith("["):
        spec = Path(spec).read_text(encoding="utf-8")
    pats = json.loads(spec)
    if not isinstance(pats, list) or not all(isinstance(p, str) for p in pats):
        raise ValueError("FIRMWARE_SPIDER_REDACT_PATTERNS must be a JSON list of regex strings")
    for p in pats:
        re.compile(p)
    return pats
