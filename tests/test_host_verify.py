import os
import tempfile
import unittest

from refall_lite.host_verify import file_rea_query, line_offset_rederive, normalize_claim
from refall_lite.verify import check_consistency, host_rea_facts


# A real script finding as recorded by the live hunt: bytes are reproducible
# (offset into the file + ascii-hex of the source line), but call_path is a list
# of free-text "node@file:line" strings and xrefs are {from,to} line pairs --
# neither of which is a mechanical fact the D1 gate can parse for a source file.
SCRIPT_CLAIM = {
    "bytes": [
        {"offset": 1752, "hex": "69736f203d20646576", "line": 61},
        {"offset": 1966, "hex": "6f732e706f70656e", "line": 66},
    ],
    "call_path": ["iso = dev.find('source')@vpai.py:61", "os.popen(...)@vpai.py:66"],
    "xrefs": [{"from": 61, "to": 66}],
    "detail": "narrative",
}

# A binary finding as recorded: bytes.hex is a decompiler NARRATIVE, not bytes,
# and offset is a vaddr string -- nothing reproducible as bytes.
BINARY_CLAIM = {
    "bytes": {"hex": "ulong local_458[129] (1032B); memcpy up to 2040B", "offset": "vaddr:0x41d2b8"},
    "call_path": {"edges": [["recvfrom", "FUN_0041399c@0x413a97"]]},
    "xrefs": ["0x41d2b8"],
}


class NormalizeClaimTests(unittest.TestCase):
    def test_keeps_only_requested_keys_and_canonical_bytes(self):
        out = normalize_claim(SCRIPT_CLAIM, keep=("bytes",))
        self.assertEqual(set(out), {"bytes"})
        self.assertEqual(out["bytes"], [
            {"offset": 1752, "hex": "69736f203d20646576"},
            {"offset": 1966, "hex": "6f732e706f70656e"},
        ])

    def test_drops_byte_entries_that_are_not_reproducible_hex(self):
        # binary prose bytes (dict, non-int offset, non-hex "hex") -> nothing to verify
        out = normalize_claim(BINARY_CLAIM, keep=("bytes",))
        self.assertEqual(out.get("bytes", []), [])
        # a bytes-less normalized claim must not falsely verify
        self.assertFalse(check_consistency(out, {}, {}).ok)

    def test_renames_xref_to_target_when_kept(self):
        out = normalize_claim(SCRIPT_CLAIM, keep=("bytes", "xrefs"))
        self.assertEqual(out["xrefs"], [{"from": 61, "target": 66}])

    def test_drops_freeform_string_call_path(self):
        out = normalize_claim(SCRIPT_CLAIM, keep=("bytes", "call_path"))
        self.assertNotIn("call_path", out)  # strings are not mechanical edges


class FileReaQueryTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(b"xxxxiso = dev")  # 'iso = dev' starts at offset 4
        self.addCleanup(os.remove, self.path)

    def test_read_bytes_returns_hex_at_offset(self):
        q = file_rea_query(self.path)
        got = q("read_bytes", {"offset": 4, "length": 3})
        self.assertEqual(got, b"iso".hex())

    def test_unknown_op_returns_none(self):
        self.assertIsNone(file_rea_query(self.path)("xrefs", {}))

    def test_out_of_range_returns_none(self):
        self.assertIsNone(file_rea_query(self.path)("read_bytes", {"offset": 9999, "length": 4}))


class HostFactsIntegrationTests(unittest.TestCase):
    def test_host_facts_reproduce_script_bytes_and_gate_passes(self):
        # file whose bytes match the claim at the claimed offsets
        fd, path = tempfile.mkstemp()
        buf = bytearray(b"\x00" * 2048)
        buf[1752:1752 + 9] = bytes.fromhex("69736f203d20646576")
        buf[1966:1966 + 8] = bytes.fromhex("6f732e706f70656e")
        with os.fdopen(fd, "wb") as f:
            f.write(buf)
        self.addCleanup(os.remove, path)

        claim = normalize_claim(SCRIPT_CLAIM, keep=("bytes",))
        finding = {"claim": claim, "member_sha256": "deadbeef"}
        rea_facts = host_rea_facts(finding, rea_query=file_rea_query(path))
        # host reproduced both claimed byte anchors from the file
        self.assertEqual(rea_facts["bytes"][1752], "69736f203d20646576")
        self.assertEqual(rea_facts["bytes"][1966], "6f732e706f70656e")
        # with a matching independent re-derivation, the gate accepts bytes-only
        rederived = {"bytes": claim["bytes"]}
        self.assertTrue(check_consistency(claim, rederived, rea_facts).ok)

    def test_gate_holds_when_file_bytes_differ(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(b"\x00" * 2048)  # all zeros -> won't match claimed hex
        self.addCleanup(os.remove, path)
        claim = normalize_claim(SCRIPT_CLAIM, keep=("bytes",))
        finding = {"claim": claim}
        rea_facts = host_rea_facts(finding, rea_query=file_rea_query(path))
        rederived = {"bytes": claim["bytes"]}
        self.assertFalse(check_consistency(claim, rederived, rea_facts).ok)


class LineOffsetRederiveTests(unittest.TestCase):
    # content: line1 "aaaa\n"@0, line2 "iso = dev\n"@5, line3 "bbbb\n"@15
    CONTENT = b"aaaa\n" + b"iso = dev\n" + b"bbbb\n"
    ISO_HEX = b"iso = dev".hex()  # 9 bytes at offset 5, on line 2

    def _file(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "wb") as f:
            f.write(self.CONTENT)
        self.addCleanup(os.remove, path)
        return path

    def test_consistent_anchor_is_rederived(self):
        claim = {"bytes": [{"offset": 5, "line": 2, "hex": self.ISO_HEX}]}
        out = line_offset_rederive(self._file(), claim)
        self.assertEqual(out["bytes"], [{"offset": 5, "hex": self.ISO_HEX}])

    def test_offset_outside_named_line_is_dropped(self):
        # right bytes at offset 5, but claim says line 1 (which is [0,5)) -> inconsistent
        claim = {"bytes": [{"offset": 5, "line": 1, "hex": self.ISO_HEX}]}
        self.assertEqual(line_offset_rederive(self._file(), claim).get("bytes", []), [])

    def test_wrong_hex_is_dropped(self):
        claim = {"bytes": [{"offset": 5, "line": 2, "hex": b"XXX = dev".hex()}]}
        self.assertEqual(line_offset_rederive(self._file(), claim).get("bytes", []), [])

    def test_handles_dict_shaped_single_byte_claim(self):
        # live securecleardisk.sh claims store bytes as a single dict, not a list
        claim = {"bytes": {"offset": 5, "line": 2, "hex": self.ISO_HEX}}
        out = line_offset_rederive(self._file(), claim)
        self.assertEqual(out["bytes"], [{"offset": 5, "hex": self.ISO_HEX}])

    def test_missing_line_falls_back_to_offset_confirmation(self):
        claim = {"bytes": [{"offset": 5, "hex": self.ISO_HEX}]}  # no line
        out = line_offset_rederive(self._file(), claim)
        self.assertEqual(out["bytes"], [{"offset": 5, "hex": self.ISO_HEX}])

    def test_rederive_and_host_facts_agree_so_gate_passes(self):
        path = self._file()
        claim = normalize_claim({"bytes": [{"offset": 5, "line": 2, "hex": self.ISO_HEX}]}, keep=("bytes",))
        rederived = line_offset_rederive(path, {"bytes": [{"offset": 5, "line": 2, "hex": self.ISO_HEX}]})
        rea_facts = host_rea_facts({"claim": claim}, rea_query=file_rea_query(path))
        self.assertTrue(check_consistency(claim, rederived, rea_facts).ok)


if __name__ == "__main__":
    unittest.main()
