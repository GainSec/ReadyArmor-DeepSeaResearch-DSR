"""RefallLite facade: the Python API over the ArcticBase REFALL state layer (lite)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from .arcticbase.store import ArcticBaseStore
from .closeout import CloseoutMixin
from .engine import EngineMixin
from .findings import FindingsMixin
from .fleet import FleetMixin
from .lineage import LineageMixin
from .observability import instrument_api, resolve_telemetry
from .reuse import ReuseMixin
from .storage import StorageMixin
from .wishlist import WishlistMixin


@instrument_api
class RefallLite(EngineMixin, FleetMixin, FindingsMixin, CloseoutMixin, LineageMixin, ReuseMixin, WishlistMixin,
                 StorageMixin):
    """Open a durable store; every method commits before returning.

    Closing and reopening (or a new process) resumes from exactly the persisted
    state. Call ``resume()`` after a crash to reclaim expired leases and check
    input drift against stage checkpoints.
    """

    def __init__(self, db_path: str | Path, *, clock: Callable[[], float] | None = None, telemetry: Any = None) -> None:
        """``telemetry``: a ``fwspider_telemetry.Telemetry`` (default: the process-wide emitter configured
        from FIRMWARE_SPIDER_* env) or ``False`` to opt out explicitly. Under the strict policy an
        unwritable log directory refuses here, before the store is opened."""
        self.telemetry = resolve_telemetry(telemetry)
        self.telemetry.start_process()
        self.store = ArcticBaseStore(db_path, clock=clock, telemetry=self.telemetry)

    def close(self) -> None:
        self.store.close()

    def __enter__(self) -> "RefallLite":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def store_info(self) -> dict:
        return {**self.store.info(), "path": str(self.store.path)}

    def ledger(self, cid: str, kind: str | None = None) -> list[dict]:
        return self.store.ledger(cid, kind)

    def verify_ledger(self, cid: str) -> dict:
        return self.store.verify_ledger(cid)
