"""Host-side CVE *prior-art* lookup for binary members (Match-gated policy).

The hunt chases NOVEL bugs. Before spending verify/promote budget on a binary
finding, this module asks whether the finding's component is already publicly
known-vulnerable, via two public, key-less services:

* **CIRCL hashlookup** (``hashlookup.circl.lu``) -- sha256 -> known-software
  identity (NSRL-style). Returns nothing for a custom vendor binary.
* **NVD CVE API 2.0** (``services.nvd.nist.gov``) -- component+version -> CVEs.
  Works without a key (lower rate limit); an optional ``NVD_API_KEY`` raises it.

A raw sha256 almost never maps to a CVE directly, so component identification is
the real pivot: CIRCL and/or embedded version strings give (product, version),
which keys the NVD query. ``covers_finding`` then decides, conservatively,
whether a disclosed CVE plausibly covers THIS finding -- if so the caller
disposes it to the ``known_cve`` lead; otherwise it is promoted as potentially
novel with the prior art attached.

All network access goes through an injected ``fetch(url, *, headers, timeout) ->
(status, body)`` so the policy is deterministically testable with no real calls.
The default fetcher is key-less and sends a generic User-Agent (never the user's
identity). Every lookup fails closed to "no prior art" on any network error.
"""
from __future__ import annotations

import json
import re
from typing import Callable, Iterable

Fetch = Callable[..., "tuple[int, str]"]

CIRCL_URL = "https://hashlookup.circl.lu/lookup/sha256/{sha256}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/{cve_id}"

# Embedded version banners for the components most common in firmware. Each
# pattern captures the version; the dict key is the lowercase NVD product name.
_VERSION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("busybox", re.compile(r"busybox\s+v?(\d+\.\d+\.\d+)", re.I)),
    ("openssl", re.compile(r"openssl\s+(\d+\.\d+\.\d+[a-z]?)", re.I)),
    ("dropbear", re.compile(r"dropbear[^\d]*(\d{4}\.\d+)", re.I)),
    ("dnsmasq", re.compile(r"dnsmasq[- ]+(?:version\s+)?(\d+\.\d+)", re.I)),
    ("lighttpd", re.compile(r"lighttpd[/ ](\d+\.\d+\.\d+)", re.I)),
    ("curl", re.compile(r"\bcurl[/ ](\d+\.\d+\.\d+)", re.I)),
    ("zlib", re.compile(r"\bzlib\s+(\d+\.\d+\.\d+)", re.I)),
    ("wpa_supplicant", re.compile(r"wpa_supplicant\s+v?(\d+\.\d+)", re.I)),
    ("hostapd", re.compile(r"hostapd\s+v?(\d+\.\d+)", re.I)),
)

# vuln_class / title -> memory-safety/other primitive keywords that may appear in
# a CVE summary. Kept small and conservative; only used as a secondary signal.
_PRIMITIVE_KEYWORDS = {
    "buffer": ("buffer overflow", "overflow", "out-of-bounds", "oob"),
    "overflow": ("overflow", "out-of-bounds"),
    "memory": ("overflow", "out-of-bounds", "use-after-free", "double free", "memory"),
    "injection": ("command injection", "injection", "shell"),
    "command": ("command injection", "os command"),
    "format": ("format string",),
    "integer": ("integer overflow", "integer"),
    "path": ("path traversal", "directory traversal", "../"),
    "traversal": ("path traversal", "directory traversal"),
}

_SYMBOL_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}(?:\.[ch])?")

# Generic "Name/version" banner (Server: headers, daemon idents like "MiniUPnPd/2.0",
# "nginx/1.21.0"). Caught after the curated patterns; protocol/transport tokens are
# dropped so "HTTP/1.1", "UPnP/1.1", "SIP/2.0" are not mistaken for products.
_GENERIC_BANNER = re.compile(r"(?<![\w./])([A-Za-z][A-Za-z0-9_+.-]{3,})/v?(\d+\.\d+(?:\.\d+)?[a-z]?)\b")
_PROTOCOL_STOPLIST = {
    "http", "https", "upnp", "tcp", "udp", "tls", "ssl", "ftp", "tftp", "sip", "rtsp", "rtp",
    "html", "dlna", "soap", "xml", "mime", "sdp", "icy", "smtp", "imap", "pop3", "snmp", "ntp",
    "mqtt", "websocket", "json", "uuid", "sha256", "md5", "en-us",
}


def _banner_hints(text: str) -> list[tuple[str, str]]:
    out = []
    for m in _GENERIC_BANNER.finditer(text):
        name = m.group(1).lower()
        if name in _PROTOCOL_STOPLIST or name.startswith(("tlsv", "sslv")):
            continue
        out.append((name, m.group(2)))
    return out


# --- default fetcher --------------------------------------------------------

def default_fetch(url: str, *, headers: dict | None = None, timeout: int = 20) -> tuple[int, str]:
    """Key-less HTTP GET via urllib with a generic UA. Returns (status, body).

    Network/HTTP errors surface as the error's status (or 0) with an empty body;
    callers treat a non-200 as 'no data' and degrade to 'no prior art'."""
    import urllib.error
    import urllib.request

    hdrs = {"User-Agent": "dsr-prior-art/1.0", "Accept": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed https hosts)
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except (urllib.error.URLError, OSError, ValueError):
        return 0, ""


def _get_json(fetch: Fetch, url: str, *, headers: dict | None = None) -> dict | None:
    status, body = fetch(url, headers=headers, timeout=20)
    if status != 200 or not body:
        return None
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) else None


# --- CIRCL hashlookup -------------------------------------------------------

def circl_hashlookup(sha256: str, *, fetch: Fetch = default_fetch) -> dict | None:
    """Look a member's sha256 up in CIRCL hashlookup. Returns identity dict or None.

    ``{"known": True, "product": <str|None>, "version": <str|None>, "raw": {...}}``.
    CIRCL keys by UPPERCASE hex; product/version are best-effort (CIRCL is a
    file-identity service, not a CPE source) -- callers lean on version strings."""
    sha = str(sha256 or "").strip().upper()
    if not re.fullmatch(r"[0-9A-F]{64}", sha):
        return None
    data = _get_json(fetch, CIRCL_URL.format(sha256=sha))
    if not data or data.get("message"):  # 'Non existing ...' => unknown file
        return None
    name = str(data.get("ProductName") or data.get("FileName") or "").strip()
    product, version = _split_product_version(name)
    return {"known": True, "product": product, "version": version, "raw_keys": sorted(data)}


def _split_product_version(text: str) -> tuple[str | None, str | None]:
    """'BusyBox 1.31.0' -> ('busybox', '1.31.0'); bare name -> (name.lower(), None)."""
    text = (text or "").strip()
    if not text:
        return None, None
    m = re.search(r"(\d+\.\d+(?:\.\d+)?[a-z]?)", text)
    version = m.group(1) if m else None
    name = text[: m.start()].strip() if m else text
    name = re.split(r"[\s/_-]+", name.strip())[0] if name else ""
    return (name.lower() or None), version


# --- NVD ---------------------------------------------------------------------

def _severity(cve: dict) -> str:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key) or []
        if rows and isinstance(rows[0], dict):
            data = rows[0].get("cvssData") or {}
            sev = data.get("baseSeverity")
            if sev:
                return str(sev)
            score = data.get("baseScore")
            if isinstance(score, (int, float)):  # V2 has no baseSeverity
                return "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
    return "UNKNOWN"


def _summary(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if isinstance(d, dict) and d.get("lang") == "en":
            return str(d.get("value") or "")
    return ""


def _cpe(product: str, version: str) -> str:
    """CPE 2.3 string for an application. Assumes vendor == product (true for
    busybox/openssl/zlib/curl/… ; a mismatched vendor simply yields no cpe hit)."""
    return f"cpe:2.3:a:{product}:{product}:{version}:*:*:*:*:*:*:*"


def _nvd_query(params: dict, *, fetch: Fetch, api_key: str | None, limit: int) -> list[dict]:
    from urllib.parse import urlencode

    params = {**params, "resultsPerPage": str(limit)}
    url = f"{NVD_URL}?{urlencode(params)}"
    headers = {"apiKey": api_key} if api_key else None
    data = _get_json(fetch, url, headers=headers)
    if not data:
        return []
    out: list[dict] = []
    for item in data.get("vulnerabilities") or []:
        cve = (item or {}).get("cve") or {}
        cid = cve.get("id")
        if not cid:
            continue
        out.append({"id": cid, "summary": _summary(cve), "severity": _severity(cve),
                    "url": NVD_DETAIL.format(cve_id=cid)})
    return out


def nvd_cves(product: str, version: str | None = None, *, fetch: Fetch = default_fetch,
             api_key: str | None = None, limit: int = 50) -> list[dict]:
    """Query NVD for CVEs on ``product`` (+ optional ``version``).

    With a version, query by **cpeName** (CPE 2.3) first: NVD then returns CVEs
    that actually affect that version (verified: ``busybox 1.31.0`` keyword -> 0
    hits; cpeName -> 15). But cpeName assumes vendor==product and relies on CPE
    applicability nodes, which miss for many components (verified: miniupnpd's
    vendor is ``miniupnp``, and even that returns 0 for 2.0). So when cpeName yields
    nothing, fall back to a **keyword search** on the product name (version-
    approximate -- the Match-gated symbol check downstream keeps it honest). Without
    a version, keyword search directly.

    Returns ``[{id, summary, severity, url}, ...]`` (possibly empty). An ``api_key``
    is sent as the ``apiKey`` header to raise the rate limit; without one the call
    still works at NVD's lower anonymous limit."""
    if not product:
        return []
    if version:
        hits = _nvd_query({"cpeName": _cpe(product, version)}, fetch=fetch, api_key=api_key, limit=limit)
        if hits:
            return hits
    return _nvd_query({"keywordSearch": product}, fetch=fetch, api_key=api_key, limit=limit)


# --- version hints from embedded strings ------------------------------------

def extract_version_hints(strings: Iterable[str]) -> list[tuple[str, str]]:
    """Scan embedded strings for known component version banners.

    Returns a de-duplicated ``[(product, version), ...]`` (first version wins
    per product)."""
    items = [str(s or "") for s in (strings or [])]  # materialize: callers may pass a generator
    found: dict[str, str] = {}
    for text in items:
        for product, pat in _VERSION_PATTERNS:
            if product in found:
                continue
            m = pat.search(text)
            if m:
                found[product] = m.group(1)
    # Second pass: generic Name/version banners (curated patterns win via setdefault).
    for text in items:
        for name, ver in _banner_hints(text):
            found.setdefault(name, ver)
    return list(found.items())


# --- orchestration -----------------------------------------------------------

def lookup_prior_art(sha256: str, *, version_hints: Iterable[tuple[str, str]] = (),
                     fetch: Fetch = default_fetch, nvd_api_key: str | None = None) -> dict | None:
    """Identify a binary member's component and collect disclosed CVEs.

    Returns a prior-art record or ``None`` when the component cannot be
    identified (custom vendor binary / network down). Fails closed: any fetch
    exception degrades to ``None`` rather than raising into the pipeline.

    ``{component, version, cves: [...], sources: [...], queries: [...],
       identified_via: str}``"""
    try:
        circl = circl_hashlookup(sha256, fetch=fetch)
    except Exception:  # fetch raised -> no prior art
        return None

    # Candidate (product, version) pairs: explicit string hints first (most
    # reliable), then any CIRCL-derived identity.
    candidates: list[tuple[str, str | None]] = [(p.lower(), v) for p, v in (version_hints or []) if p]
    if circl and circl.get("product"):
        candidates.append((circl["product"], circl.get("version")))
    # de-dup preserving order
    seen: set = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    if not candidates:
        return None  # cannot identify a queryable component

    sources = (["circl:known-file"] if circl else []) + ([f"string:{p}" for p, _ in (version_hints or [])])
    queries: list[str] = []
    if circl:
        queries.append("GET " + CIRCL_URL.format(sha256=str(sha256).upper()))
    all_cves: list[dict] = []
    component, version = candidates[0]
    for product, ver in candidates:
        queries.append(f"GET {NVD_URL}?keywordSearch={product}{(' ' + ver) if ver else ''}")
        try:
            cves = nvd_cves(product, ver, fetch=fetch, api_key=nvd_api_key)
        except Exception:
            cves = []
        all_cves.extend(cves)

    # de-dup CVEs by id, preserving order
    cves, ids = [], set()
    for c in all_cves:
        if c["id"] not in ids:
            ids.add(c["id"])
            cves.append(c)

    return {"component": component, "version": version, "cves": cves, "sources": sources,
            "queries": queries, "identified_via": "circl+strings" if circl else "strings"}


# --- match gate --------------------------------------------------------------

def _finding_tokens(finding: dict) -> set[str]:
    """Symbol / filename tokens from a finding's anchors, title and claim."""
    tokens: set[str] = set()
    for anchor in finding.get("source_anchors") or []:
        for m in _SYMBOL_RE.findall(str(anchor)):
            tokens.add(m.lower())
    for m in _SYMBOL_RE.findall(str(finding.get("title") or "")):
        tokens.add(m.lower())
    claim = finding.get("claim")
    if isinstance(claim, dict):
        for v in claim.values():
            for m in _SYMBOL_RE.findall(str(v)):
                tokens.add(m.lower())
    # drop generic words that would over-match
    return {t for t in tokens if len(t) >= 4 and t not in _GENERIC}


_GENERIC = {"read", "write", "null", "size", "data", "func", "call", "code", "line",
            "byte", "bytes", "file", "char", "void", "main", "init", "free", "true",
            "false", "none", "memory", "stack", "heap", "error", "value", "buffer"}


def _primitive_keywords(finding: dict) -> set[str]:
    text = f"{finding.get('vuln_class') or ''} {finding.get('title') or ''}".lower()
    kws: set[str] = set()
    for trigger, words in _PRIMITIVE_KEYWORDS.items():
        if trigger in text:
            kws.update(words)
    return kws


def covers_finding(prior_art: dict, finding: dict) -> tuple[bool, str]:
    """Conservatively decide whether a disclosed CVE plausibly covers THIS finding.

    Match-gated policy: a CVE covers the finding only when a concrete signal
    fires -- a finding symbol/filename token appears verbatim in the CVE summary.
    (Primitive-keyword overlap alone is reported as a weak signal but does NOT
    auto-divert, so novel bugs in well-studied binaries still promote.) Returns
    ``(covered, rationale)``."""
    cves = prior_art.get("cves") or []
    comp = f"{prior_art.get('component')} {prior_art.get('version') or ''}".strip()
    if not cves:
        return False, f"no disclosed CVEs matched {comp or 'this component'} -- treat as potentially novel"

    tokens = _finding_tokens(finding)
    for cve in cves:
        summary = str(cve.get("summary") or "").lower()
        hit = next((t for t in tokens if t in summary), None)
        if hit:
            return True, (f"{cve['id']} ({cve.get('severity')}) summary names '{hit}' from this finding "
                          f"-- rediscovery of a known {comp} issue: {cve.get('url')}")

    primitives = _primitive_keywords(finding)
    weak = [c["id"] for c in cves if any(k in str(c.get("summary") or "").lower() for k in primitives)]
    note = f" ({len(weak)} CVE(s) share the primitive but name no shared symbol: {', '.join(weak)})" if weak else ""
    return False, (f"{comp} has {len(cves)} disclosed CVE(s) but none names this finding's symbols "
                   f"-- treat as potentially novel{note}")


# --- file strings -> version hints ------------------------------------------

def iter_file_strings(path: str, *, min_len: int = 4):
    """Yield printable-ASCII runs (>= ``min_len``) from a binary file.

    A deterministic, offline stand-in for ``strings(1)`` so version-banner
    extraction needs no external tool. Unreadable files yield nothing."""
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return
    run = bytearray()
    for byte in raw:
        if 32 <= byte < 127:
            run.append(byte)
        else:
            if len(run) >= min_len:
                yield run.decode("ascii")
            run = bytearray()
    if len(run) >= min_len:
        yield run.decode("ascii")


def file_version_hints(path: str) -> list[tuple[str, str]]:
    """Extract known-component version banners straight from a binary file."""
    return extract_version_hints(iter_file_strings(path))


# --- 3-way classification (the policy the pipeline consumes) -----------------

def classify_for_prior_art(sha256: str, finding: dict, *, version_hints: Iterable[tuple[str, str]] = (),
                           fetch: Fetch = default_fetch, nvd_api_key: str | None = None) -> tuple[str, dict | None, str]:
    """Classify a binary finding against public prior art. Returns (verdict, prior_art, rationale):

    * ``"lead"``   -- a disclosed CVE plausibly covers it; caller disposes to
      ``known_cve`` (do NOT promote). ``prior_art`` carries the CVE refs.
    * ``"novel"``  -- component identified, but no CVE covers this finding;
      caller promotes as usual with ``prior_art`` attached as context.
    * ``"unknown"`` -- component could not be identified (custom binary / network
      down); caller proceeds exactly as before, ``prior_art`` is ``None``."""
    pa = lookup_prior_art(sha256, version_hints=version_hints, fetch=fetch, nvd_api_key=nvd_api_key)
    if not pa:
        return "unknown", None, "component not identified (custom binary, no version banner, or lookup unavailable)"
    covered, why = covers_finding(pa, finding)
    return ("lead" if covered else "novel"), pa, why


# --- receipt -----------------------------------------------------------------

def prior_art_receipt(prior_art: dict, rationale: str) -> dict:
    """Build the typed ``prior_art_cve`` receipt for a ``known_cve`` disposition.

    CVE ids+urls go in ``evidence_refs`` (satisfies the gate's material rule); the
    upstream queries go in ``commands`` so the lead is replayable."""
    cves = prior_art.get("cves") or []
    return {
        "checker_kind": "deterministic_tool",
        "component": prior_art.get("component"),
        "version": prior_art.get("version"),
        "evidence_refs": [f"{c['id']} [{c.get('severity')}] {c.get('url')}" for c in cves],
        "commands": list(prior_art.get("queries") or []),
        "source_anchors": list(prior_art.get("sources") or []),
        "summary": rationale,
    }
