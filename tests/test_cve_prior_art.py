"""Host-side CVE prior-art lookup for binary members.

The goal: before spending verify/promote budget on a binary finding, ask whether
its component is already publicly known-vulnerable. If a disclosed CVE plausibly
covers THIS finding, it is saved as a lead (``known_cve`` disposition) rather than
promoted as novel. All network access is injected via ``fetch`` so these tests
make no real calls.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from refall_lite.arcticbase.contracts import evaluate_transition
from refall_lite.cve_prior_art import (
    circl_hashlookup,
    classify_for_prior_art,
    covers_finding,
    extract_version_hints,
    file_version_hints,
    lookup_prior_art,
    nvd_cves,
    prior_art_receipt,
)

# -- canned upstream payloads -------------------------------------------------

CIRCL_KNOWN = json.dumps({
    "FileName": "busybox",
    "ProductName": "BusyBox 1.31.0",
    "SHA-256": "A" * 64,
    "source": "NSRL",
})
CIRCL_MISS = json.dumps({"message": "Non existing SHA-256"})

NVD_HIT = json.dumps({
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2021-28831",
            "descriptions": [{"lang": "en", "value": "decompress_gunzip.c in BusyBox through 1.32.1 mishandles the error bit."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 7.5}}]},
        }
    }]
})
NVD_EMPTY = json.dumps({"vulnerabilities": []})


def fake_fetch(responses):
    """Build a fetch(url, headers, timeout) that matches a url substring -> (status, body).

    Also records the headers it was called with, so key-injection can be asserted.
    """
    calls = []

    def fetch(url, *, headers=None, timeout=20):
        calls.append({"url": url, "headers": dict(headers or {})})
        for needle, (status, body) in responses.items():
            if needle in url:
                return status, body
        return 404, ""

    fetch.calls = calls
    return fetch


class CirclHashlookupTests(unittest.TestCase):
    def test_known_file_returns_product_and_version(self):
        fetch = fake_fetch({"hashlookup.circl.lu": (200, CIRCL_KNOWN)})
        out = circl_hashlookup("a" * 64, fetch=fetch)
        self.assertIsNotNone(out)
        self.assertTrue(out["known"])
        self.assertEqual(out["product"], "busybox")
        self.assertEqual(out["version"], "1.31.0")
        # CIRCL keys sha256 uppercase
        self.assertIn(("A" * 64), fetch.calls[0]["url"])

    def test_unknown_file_returns_none(self):
        fetch = fake_fetch({"hashlookup.circl.lu": (404, CIRCL_MISS)})
        self.assertIsNone(circl_hashlookup("b" * 64, fetch=fetch))


class NvdCvesTests(unittest.TestCase):
    def test_parses_id_summary_severity_url(self):
        fetch = fake_fetch({"services.nvd.nist.gov": (200, NVD_HIT)})
        cves = nvd_cves("busybox", "1.31.0", fetch=fetch)
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0]["id"], "CVE-2021-28831")
        self.assertEqual(cves[0]["severity"], "HIGH")
        self.assertIn("decompress_gunzip.c", cves[0]["summary"])
        self.assertIn("CVE-2021-28831", cves[0]["url"])

    def test_no_vulnerabilities_returns_empty(self):
        fetch = fake_fetch({"services.nvd.nist.gov": (200, NVD_EMPTY)})
        self.assertEqual(nvd_cves("busybox", "9.9.9", fetch=fetch), [])

    def test_api_key_sent_as_header_when_provided(self):
        fetch = fake_fetch({"services.nvd.nist.gov": (200, NVD_EMPTY)})
        nvd_cves("busybox", "1.31.0", fetch=fetch, api_key="SECRET")
        self.assertEqual(fetch.calls[0]["headers"].get("apiKey"), "SECRET")

    def test_no_api_key_sends_no_apikey_header(self):
        fetch = fake_fetch({"services.nvd.nist.gov": (200, NVD_EMPTY)})
        nvd_cves("busybox", "1.31.0", fetch=fetch)
        self.assertNotIn("apiKey", fetch.calls[0]["headers"])

    def test_version_query_uses_cpename_for_version_accuracy(self):
        # NVD keyword search matches description TEXT, which omits exact versions;
        # a version-accurate query must use cpeName (CPE 2.3), not keywordSearch.
        fetch = fake_fetch({"services.nvd.nist.gov": (200, NVD_HIT)})
        nvd_cves("busybox", "1.31.0", fetch=fetch)
        url = fetch.calls[0]["url"]
        self.assertIn("cpeName=", url)
        self.assertIn("cpe%3A2.3%3Aa%3Abusybox%3Abusybox%3A1.31.0", url)
        self.assertNotIn("keywordSearch", url)

    def test_no_version_falls_back_to_keyword_search(self):
        fetch = fake_fetch({"services.nvd.nist.gov": (200, NVD_HIT)})
        nvd_cves("busybox", None, fetch=fetch)
        url = fetch.calls[0]["url"]
        self.assertIn("keywordSearch=busybox", url)
        self.assertNotIn("cpeName", url)

    def test_cpename_miss_falls_back_to_keyword_search(self):
        # miniupnpd's real CPE vendor != product, so cpeName returns nothing;
        # the gate must fall back to a keyword search to find the real CVEs.
        def fetch(url, *, headers=None, timeout=20):
            if "cpeName=" in url:
                return 200, NVD_EMPTY
            if "keywordSearch=" in url:
                return 200, NVD_HIT
            return 404, ""
        cves = nvd_cves("miniupnpd", "2.0", fetch=fetch)
        self.assertEqual([c["id"] for c in cves], ["CVE-2021-28831"])  # came from the keyword fallback

    def test_cpename_hit_does_not_fall_back(self):
        calls = []
        def fetch(url, *, headers=None, timeout=20):
            calls.append(url)
            return 200, NVD_HIT  # cpeName already has hits
        nvd_cves("busybox", "1.31.0", fetch=fetch)
        self.assertEqual(len(calls), 1)
        self.assertIn("cpeName=", calls[0])


class VersionHintTests(unittest.TestCase):
    def test_extracts_common_component_versions(self):
        strings = [
            "BusyBox v1.31.0 (2020-01-01)",
            "OpenSSL 1.0.2k  26 Jan 2017",
            "Dropbear SSH server 2019.78",
            "random unrelated string",
        ]
        hints = dict(extract_version_hints(strings))
        self.assertEqual(hints.get("busybox"), "1.31.0")
        self.assertEqual(hints.get("openssl"), "1.0.2k")
        self.assertEqual(hints.get("dropbear"), "2019.78")

    def test_no_versions_returns_empty(self):
        self.assertEqual(extract_version_hints(["nothing here", "v"]), [])

    def test_extracts_miniupnpd_from_server_banner(self):
        # router-style miniupnpd banner; the daemon version, not the UPnP protocol version
        hints = dict(extract_version_hints(["Server: UPnP/Vendor -140 ARM UPnP/1.1 MiniUPnPd/2.0"]))
        self.assertEqual(hints.get("miniupnpd"), "2.0")

    def test_generic_name_slash_version_banner_skips_protocol_tokens(self):
        hints = dict(extract_version_hints(["nginx/1.21.0", "HTTP/1.1", "UPnP/1.1", "TLSv1.2", "SIP/2.0"]))
        self.assertEqual(hints.get("nginx"), "1.21.0")
        for proto in ("http", "upnp", "tlsv1", "sip", "tls"):
            self.assertNotIn(proto, hints)


class LookupPriorArtTests(unittest.TestCase):
    def test_identifies_component_and_collects_cves(self):
        fetch = fake_fetch({
            "hashlookup.circl.lu": (200, CIRCL_KNOWN),
            "services.nvd.nist.gov": (200, NVD_HIT),
        })
        pa = lookup_prior_art("a" * 64, version_hints=[("busybox", "1.31.0")], fetch=fetch)
        self.assertIsNotNone(pa)
        self.assertEqual(pa["component"], "busybox")
        self.assertEqual(pa["version"], "1.31.0")
        self.assertEqual([c["id"] for c in pa["cves"]], ["CVE-2021-28831"])

    def test_returns_none_when_component_unidentifiable(self):
        fetch = fake_fetch({"hashlookup.circl.lu": (404, CIRCL_MISS)})
        self.assertIsNone(lookup_prior_art("b" * 64, version_hints=[], fetch=fetch))

    def test_network_failure_degrades_to_none_not_crash(self):
        def boom(url, *, headers=None, timeout=20):
            raise OSError("network down")
        self.assertIsNone(lookup_prior_art("c" * 64, version_hints=[("busybox", "1.31.0")], fetch=boom))


class CoversFindingTests(unittest.TestCase):
    PA = {
        "component": "busybox", "version": "1.31.0",
        "cves": [{"id": "CVE-2021-28831", "severity": "HIGH",
                  "summary": "decompress_gunzip.c in BusyBox mishandles the error bit",
                  "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-28831"}],
    }

    def test_covers_when_cve_summary_names_finding_symbol(self):
        finding = {"title": "OOB read", "vuln_class": "memory-safety",
                   "source_anchors": ["decompress_gunzip.c:120"], "claim": {}}
        covered, why = covers_finding(self.PA, finding)
        self.assertTrue(covered)
        self.assertIn("CVE-2021-28831", why)

    def test_not_covered_when_no_overlap_treated_as_potentially_novel(self):
        finding = {"title": "Stack overflow in telnetd", "vuln_class": "memory-safety",
                   "source_anchors": ["telnetd.c:44"], "claim": {}}
        covered, why = covers_finding(self.PA, finding)
        self.assertFalse(covered)
        self.assertIn("busybox", why.lower())

    def test_empty_cves_never_covers(self):
        covered, _ = covers_finding({"component": "x", "version": "1", "cves": []},
                                    {"title": "t", "vuln_class": "c", "source_anchors": [], "claim": {}})
        self.assertFalse(covered)


class ReceiptGatesAsKnownCveTests(unittest.TestCase):
    def test_receipt_passes_the_known_cve_transition_gate(self):
        pa = {"component": "busybox", "version": "1.31.0",
              "cves": [{"id": "CVE-2021-28831", "severity": "HIGH", "summary": "s",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-28831"}],
              "queries": ["GET https://services.nvd.nist.gov/rest/json/cves/2.0?..."]}
        receipt = prior_art_receipt(pa, "CVE-2021-28831 summary names decompress_gunzip.c")
        self.assertEqual(receipt["checker_kind"], "deterministic_tool")
        self.assertTrue(any("CVE-2021-28831" in r for r in receipt["evidence_refs"]))
        # a tool actor (!= model creator) disposing hypothesis -> known_cve must be accepted
        finding = {"id": "find_x", "tier": "hypothesis", "created_by": "spark-hunt"}
        actor = {"id": "host-verify", "kind": "tool"}
        reasons = evaluate_transition(finding, to="known_cve", actor=actor,
                                      receipt_type="prior_art_cve", receipt=receipt,
                                      duplicate_of=None, duplicate_exists=False)
        self.assertEqual(reasons, [])


class FileVersionHintsTests(unittest.TestCase):
    def test_scans_binary_for_version_banners(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            # BusyBox/OpenSSL hit curated patterns; MiniUPnPd/2.0 exercises the GENERIC
            # banner pass -- over a generator (iter_file_strings), the case that regressed.
            f.write(b"\x00\x01garbage\x00BusyBox v1.31.0 (2020)\x00\xffmore\x00OpenSSL 1.0.2k\x00"
                    b"Server: UPnP/1.1 MiniUPnPd/2.0\x00")
        self.addCleanup(os.remove, path)
        hints = dict(file_version_hints(path))
        self.assertEqual(hints.get("busybox"), "1.31.0")
        self.assertEqual(hints.get("openssl"), "1.0.2k")
        self.assertEqual(hints.get("miniupnpd"), "2.0")  # generic pass must survive generator input

    def test_extract_version_hints_accepts_a_generator_not_only_a_list(self):
        gen = (s for s in ["nginx/1.21.0", "BusyBox v1.31.0"])
        hints = dict(extract_version_hints(gen))
        self.assertEqual(hints.get("nginx"), "1.21.0")      # generic pass
        self.assertEqual(hints.get("busybox"), "1.31.0")    # curated pass

    def test_missing_file_returns_empty(self):
        self.assertEqual(file_version_hints("/no/such/file/xyz"), [])


class ClassifyForPriorArtTests(unittest.TestCase):
    FINDING_MATCH = {"title": "OOB read", "vuln_class": "memory-safety",
                     "source_anchors": ["decompress_gunzip.c:120"], "claim": {}}
    FINDING_NOVEL = {"title": "Stack overflow in vendor_cmanicd_parse", "vuln_class": "memory-safety",
                     "source_anchors": ["cmanicd.c:900"], "claim": {}}

    def test_lead_when_cve_covers_finding(self):
        fetch = fake_fetch({"hashlookup.circl.lu": (200, CIRCL_KNOWN), "services.nvd.nist.gov": (200, NVD_HIT)})
        verdict, pa, why = classify_for_prior_art("a" * 64, self.FINDING_MATCH,
                                                  version_hints=[("busybox", "1.31.0")], fetch=fetch)
        self.assertEqual(verdict, "lead")
        self.assertIn("CVE-2021-28831", why)
        self.assertEqual(pa["component"], "busybox")

    def test_novel_when_component_known_but_no_cve_covers(self):
        fetch = fake_fetch({"hashlookup.circl.lu": (200, CIRCL_KNOWN), "services.nvd.nist.gov": (200, NVD_HIT)})
        verdict, pa, why = classify_for_prior_art("a" * 64, self.FINDING_NOVEL,
                                                  version_hints=[("busybox", "1.31.0")], fetch=fetch)
        self.assertEqual(verdict, "novel")
        self.assertIsNotNone(pa)  # prior art still attached as context

    def test_unknown_when_component_unidentifiable(self):
        fetch = fake_fetch({"hashlookup.circl.lu": (404, CIRCL_MISS)})
        verdict, pa, why = classify_for_prior_art("b" * 64, self.FINDING_NOVEL, version_hints=[], fetch=fetch)
        self.assertEqual(verdict, "unknown")
        self.assertIsNone(pa)


if __name__ == "__main__":
    unittest.main()
