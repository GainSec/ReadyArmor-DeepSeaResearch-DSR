# --- fwspider_telemetry loader v1 (canonical copy: fwspider_telemetry/loader_snippet.py) ---
def _load_fwspider_telemetry():
    """Import fwspider_telemetry deterministically: installed package, else a hash-verified vendored copy.

    Search order: installed (pip/uv) -> $FIRMWARE_SPIDER_TELEMETRY_PATH -> <project home>/lib for the
    project homes that exist on this host. No sys.path mutation; VENDORED.json hashes must match.
    """
    import hashlib
    import importlib
    import importlib.util
    import json
    import os
    import sys
    from pathlib import Path
    try:
        return importlib.import_module("fwspider_telemetry")
    except ImportError:
        pass
    bases = []
    if os.environ.get("FIRMWARE_SPIDER_TELEMETRY_PATH"):
        bases.append(Path(os.environ["FIRMWARE_SPIDER_TELEMETRY_PATH"]))
    for home in (os.environ.get("FIRMWARE_SPIDER_HOME"), "/Users/dsr/firmware-spider",
                 "/home/dsr/firmware-spider"):
        if home and os.path.isdir(home):
            bases.append(Path(home) / "lib")
    for base in bases:
        pkg = base / "fwspider_telemetry"
        manifest = pkg / "VENDORED.json"
        if not manifest.is_file():
            continue
        files = json.loads(manifest.read_text())["files"]
        bad = [f for f, h in files.items()
               if not (pkg / f).is_file() or hashlib.sha256((pkg / f).read_bytes()).hexdigest() != h]
        if bad:
            raise ImportError(f"vendored fwspider_telemetry at {pkg} failed hash verification: {bad[:3]}")
        spec = importlib.util.spec_from_file_location("fwspider_telemetry", pkg / "__init__.py",
                                                      submodule_search_locations=[str(pkg)])
        mod = importlib.util.module_from_spec(spec)
        sys.modules["fwspider_telemetry"] = mod
        spec.loader.exec_module(mod)
        return mod
    raise ImportError("fwspider_telemetry is not installed and no vendored copy was found; set "
                      "FIRMWARE_SPIDER_TELEMETRY_PATH or run `python3 -m fwspider_telemetry vendor --dest <home>/lib`")
# --- end fwspider_telemetry loader ---
