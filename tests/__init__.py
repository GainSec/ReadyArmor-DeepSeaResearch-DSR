"""Test package. Routes all telemetry from the suite (and the CLI/example subprocesses it spawns)
to a private temporary log directory unless FIRMWARE_SPIDER_LOG_DIR is already set."""
import atexit
import os
import shutil
import tempfile

if not os.environ.get("FIRMWARE_SPIDER_LOG_DIR"):
    _LOG_DIR = tempfile.mkdtemp(prefix="fwspider-test-logs-")
    os.environ["FIRMWARE_SPIDER_LOG_DIR"] = _LOG_DIR
    atexit.register(shutil.rmtree, _LOG_DIR, True)
os.environ.setdefault("FIRMWARE_SPIDER_DEADLETTER_DIR", tempfile.mkdtemp(prefix="fwspider-test-deadletter-"))
