from refall_lite.rea_toolmap import (
    DEFAULT_TOOLS,
    KNOWN_TECHNIQUE_IDS,
    GENERAL_HUNT_TOOLS,
    MAX_REA_TOOLS,
    hunt_tools,
    tools_for_technique,
)


def test_known_technique_maps_to_expected_subset():
    t = {"id": "cmd_injection_sink_reachability", "ordered_steps": ["decompile", "xref", "trace call path"]}
    got = tools_for_technique(t)
    assert set(got) >= {"open_binary", "procedure_pseudo_code", "xrefs"}
    assert len(got) <= MAX_REA_TOOLS


def test_unknown_technique_returns_minimal_default_not_full_surface():
    got = tools_for_technique({"id": "nope"})
    assert got == DEFAULT_TOOLS and 0 < len(got) <= MAX_REA_TOOLS


def test_every_mapping_respects_ceiling():
    assert KNOWN_TECHNIQUE_IDS
    for tid in KNOWN_TECHNIQUE_IDS:
        assert len(tools_for_technique({"id": tid})) <= MAX_REA_TOOLS   # Review Focus: overflow guard
    assert len(DEFAULT_TOOLS) <= MAX_REA_TOOLS


def test_real_pack_ids_and_empty_input():
    assert "procedure_pseudo_code" in tools_for_technique({"id": "ghidra_decompiler_variable_slicing"})
    assert tools_for_technique({}) == DEFAULT_TOOLS
    assert tools_for_technique(None) == DEFAULT_TOOLS
    assert tools_for_technique({"id": "nope"}) is not DEFAULT_TOOLS  # defensive copy


def test_hunt_tools_general_bounded_bare():
    got = hunt_tools()
    assert got and len(got) <= MAX_REA_TOOLS
    assert got == GENERAL_HUNT_TOOLS[:MAX_REA_TOOLS]
    assert {"xrefs", "procedure_pseudo_code", "read_bytes", "build_call_path"} <= set(got)
    assert not any(t.startswith("rea_") for t in got)
    assert got is not GENERAL_HUNT_TOOLS
