import os
import sys

from refall_lite.stage0 import expand_image

FX = os.path.join(os.path.dirname(__file__), "fixtures", "stage0")

_WRITER = (
    "import os,sys;d=os.path.join(sys.argv[1],'usr','bin');os.makedirs(d);"
    "open(os.path.join(d,'httpd'),'wb').write(b'\\x7fELFhttpd')"
)


def _fake_squashfs_tool(image, out_dir):
    # Stub extractor: a python one-liner that emits canned files into out_dir.
    return [sys.executable, "-c", _WRITER, out_dir]


def test_flat_elf_enumerates_itself_as_single_member(tmp_path):
    out = expand_image(os.path.join(FX, "tiny.elf"), str(tmp_path), tools={})
    assert out.status == "extracted" and len(out.members) == 1
    m = out.members[0]
    assert m["path"] == "tiny.elf" and len(m["sha256"]) == 64 and m["size_bytes"] > 0
    for mm in out.members:
        assert os.path.exists(os.path.join(str(tmp_path), mm["path"]))


def test_known_container_expands_to_members(tmp_path):
    tools = {"squashfs": _fake_squashfs_tool}
    out = expand_image(os.path.join(FX, "tiny.squashfs"), str(tmp_path), tools=tools)
    assert out.status == "extracted" and len(out.members) >= 1
    assert out.members[0]["path"] == "usr/bin/httpd"


def test_container_without_tool_fails(tmp_path):
    out = expand_image(os.path.join(FX, "tiny.squashfs"), str(tmp_path), tools={})
    assert out.status == "failed" and out.reason


def test_unrecognized_blob_marks_failed_for_escalation(tmp_path):
    out = expand_image(os.path.join(FX, "random.bin"), str(tmp_path))
    assert out.status == "failed" and out.reason


def test_tool_nonzero_exit_fails(tmp_path):
    tools = {"squashfs": lambda i, o: [sys.executable, "-c", "import sys;sys.exit(3)"]}
    out = expand_image(os.path.join(FX, "tiny.squashfs"), str(tmp_path), tools=tools)
    assert out.status == "failed" and out.reason


def test_tool_exit_zero_no_files_fails(tmp_path):
    tools = {"squashfs": lambda i, o: [sys.executable, "-c", "pass"]}
    out = expand_image(os.path.join(FX, "tiny.squashfs"), str(tmp_path), tools=tools)
    assert out.status == "failed" and out.reason
