"""Mechanical technique -> REA tool-subset map.

Capability routing only (a decompile technique needs decompile + xref tools);
no judgment about vulnerabilities. Names are bare (no ``rea_`` prefix); the
prefix is added later by ``build_config``. Deny-by-default: unknown or empty
techniques get DEFAULT_TOOLS, never the full REA surface.
"""
from __future__ import annotations

MAX_REA_TOOLS: int = 12

DEFAULT_TOOLS: list[str] = ["open_binary", "close_binary", "binary_overview", "list_strings"]

_TRIAGE = ["open_binary", "close_binary", "binary_overview", "list_strings",
           "search_strings", "list_procedures", "inspect_binary_layout"]
_DECOMPILE = ["open_binary", "close_binary", "binary_overview", "list_strings",
              "list_procedures", "procedure_pseudo_code", "xrefs"]
_CALLPATH = _DECOMPILE + ["find_xrefs_to_name", "build_call_path", "get_call_graph"]
_DISASM = ["open_binary", "close_binary", "binary_overview", "list_procedures",
           "procedure_assembly", "analyze_function", "xrefs", "read_bytes"]
_LAYOUT = ["open_binary", "close_binary", "binary_overview", "inspect_binary_layout",
           "list_segments", "read_bytes", "list_strings", "search_strings"]
_STRINGS = ["open_binary", "close_binary", "list_strings", "search_strings",
            "find_xrefs_to_name", "xrefs", "read_bytes"]
_NAMES = ["open_binary", "close_binary", "list_names", "list_procedures",
          "procedure_pseudo_code", "xrefs", "find_xrefs_to_name"]

_TECHNIQUE_TOOLS: dict[str, list[str]] = {
    "cmd_injection_sink_reachability": _CALLPATH,
    "karonte_constraint_aware_sink_detection": _CALLPATH,
    "karonte_return_value_path_prioritization": _CALLPATH,
    "karonte_network_string_function_taint_seeding": _CALLPATH + ["search_strings"],
    "karonte_stack_buffer_size_estimation": _DECOMPILE + ["analyze_function"],
    "karonte_heap_buffer_size_estimation": _DECOMPILE + ["analyze_function"],
    "fstm_suspect_binary_disassembly": _DISASM,
    "fstm_elf_mitigation_inventory": _LAYOUT,
    "fstm_offset_aware_string_inspection": _STRINGS,
    "fstm_firmware_image_characterization": _LAYOUT,
    "ghidra_decompiler_variable_slicing": _DECOMPILE + ["analyze_function"],
    "ghidra_callee_to_caller_interpretation": _CALLPATH,
    "ghidra_function_call_tree_traversal": _CALLPATH,
    "ghidra_direct_reference_search": _STRINGS,
    "ghidra_symbol_reference_triage": _NAMES,
    "ghidra_string_discovery_definition": _STRINGS,
    "ghidra_encoded_string_search": _STRINGS,
    "ghidra_instruction_pattern_search": _DISASM,
    "ghidra_initial_auto_analysis": _TRIAGE,
    "bmc_ilo4_hpimage_guid_dispatch_recovery": _CALLPATH,
    "bmc_ilo4_connection_vtable_execution_analysis": _CALLPATH + ["procedure_assembly"],
}

GENERAL_HUNT_TOOLS: list[str] = [
    "open_binary", "binary_overview", "list_strings", "search_strings", "list_procedures",
    "procedure_pseudo_code", "xrefs", "find_xrefs_to_name", "build_call_path", "read_bytes",
    "close_binary",
]

KNOWN_TECHNIQUE_IDS: tuple[str, ...] = tuple(_TECHNIQUE_TOOLS)


def _clamp(tools: list[str]) -> list[str]:
    """Dedupe (order-preserving) and enforce the hard ceiling; returns a new list."""
    seen: list[str] = []
    for t in tools:
        if t not in seen:
            seen.append(t)
    return seen[:MAX_REA_TOOLS]


def tools_for_technique(technique: dict | None) -> list[str]:
    """Return a bare REA tool-name list (<= MAX_REA_TOOLS) for a pack technique."""
    tid = technique.get("id") if isinstance(technique, dict) else None
    tools = _TECHNIQUE_TOOLS.get(tid) if isinstance(tid, str) else None
    return _clamp(tools if tools is not None else DEFAULT_TOOLS)


def hunt_tools() -> list[str]:
    """General bounded toolset for free-form hunting/verification (never the full REA surface)."""
    return _clamp(GENERAL_HUNT_TOOLS)
