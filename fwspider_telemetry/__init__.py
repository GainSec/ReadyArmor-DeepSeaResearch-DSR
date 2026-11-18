"""fwspider_telemetry: the shared Firmware Spider observability package (stdlib only).

One versioned event schema (``event-schema.json``) and one redaction rule set
(``redaction-rules.json``) are shared with the Node emitter
(``node/fwspider-telemetry.mjs``). See OBSERVABILITY.md.
"""
from .config import ObservabilityError, TelemetryConfig, project_home, resolve_log_dir
from .core import (
    SCHEMA,
    SCHEMA_VERSION,
    TAXONOMY,
    NullTelemetry,
    Telemetry,
    canonical,
    digest,
    exception_data,
    get_telemetry,
    new_id,
    set_telemetry,
)
from .model import MockModelClient, ModelCall, instrumented_model_invoke
from .redaction import REDACTED, RedactionReport, Redactor

__version__ = "1.0.0"
__all__ = [
    "ObservabilityError", "TelemetryConfig", "project_home", "resolve_log_dir", "SCHEMA", "SCHEMA_VERSION", "TAXONOMY",
    "NullTelemetry", "Telemetry", "canonical", "digest", "exception_data", "get_telemetry", "new_id", "set_telemetry",
    "MockModelClient", "ModelCall", "instrumented_model_invoke", "REDACTED", "RedactionReport", "Redactor", "__version__",
]
