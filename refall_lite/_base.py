"""Shared plumbing: actors, campaigns, pending actions (ArcticBase semantics)."""
from __future__ import annotations

import hashlib
from typing import Any

from .arcticbase.contracts import (
    ACTOR_KINDS,
    OPERATOR_KINDS,
    PENDING_OPEN,
    PENDING_TERMINAL,
    receipt_has_material,
)
from .arcticbase.store import ArcticBaseStore, dumps, loads, new_id


class Base:
    store: ArcticBaseStore

    # -- actors --------------------------------------------------------------
    def register_actor(self, actor_id: str, kind: str, provider: str | None = None) -> dict:
        if kind not in ACTOR_KINDS:
            raise ValueError(f"actor kind must be one of {sorted(ACTOR_KINDS)}")
        if not actor_id.strip():
            raise ValueError("actor id required")
        with self.store.tx():
            existing = self.store.one("SELECT * FROM actors WHERE id=?", (actor_id,))
            if existing and existing["kind"] != kind:
                raise ValueError(f"actor {actor_id} already registered as {existing['kind']}")
            if not existing:
                self.store.conn.execute(
                    "INSERT INTO actors(id,kind,provider,created_at) VALUES(?,?,?,?)",
                    (actor_id, kind, provider, self.store.now()),
                )
        return self.actor(actor_id)

    def actor(self, actor_id: str) -> dict:
        row = self.store.one("SELECT * FROM actors WHERE id=?", (actor_id,))
        if not row:
            raise KeyError(f"unknown actor: {actor_id}")
        return dict(row)

    def list_actors(self) -> list[dict]:
        return [dict(r) for r in self.store.all("SELECT * FROM actors ORDER BY id")]

    def _require_kind(self, actor_id: str, kinds: set[str], action: str) -> dict:
        actor = self.actor(actor_id)
        if actor["kind"] not in kinds:
            raise PermissionError(f"actor {actor_id} ({actor['kind']}) may not {action}; requires {sorted(kinds)}")
        return actor

    def _require_operator(self, actor_id: str, action: str) -> dict:
        return self._require_kind(actor_id, OPERATOR_KINDS, action)

    # -- campaigns -----------------------------------------------------------
    def get_campaign(self, campaign_id: str) -> dict:
        row = self.store.one("SELECT * FROM campaigns WHERE id=?", (campaign_id,))
        if not row:
            raise KeyError(f"unknown campaign: {campaign_id}")
        data = dict(row)
        data["config"] = loads(data["config"], {})
        return data

    def list_campaigns(self) -> list[dict]:
        return [self.get_campaign(r["id"]) for r in self.store.all("SELECT id FROM campaigns ORDER BY created_at")]

    def _ledger(self, cid: str, kind: str, action: str, actor: str | None, /, **payload: Any) -> dict:
        return self.store.append_ledger(cid, kind, action, actor, payload)

    # -- pending actions (ArcticBase pending_actions semantics) --------------
    @staticmethod
    def _pending_identity(cid: str, kind: str, *parts: str) -> str:
        return hashlib.sha1("|".join([cid, kind, *parts]).encode()).hexdigest()

    def _open_pending(
        self,
        cid: str,
        kind: str,
        title: str,
        *,
        identity_parts: tuple[str, ...],
        source_job_id: str | None = None,
        source_finding_id: str | None = None,
        source_member: str | None = None,
        scope: str | None = None,
        required_receipt_type: str | None = None,
        requested_by: str | None = None,
        priority: str = "high",
        payload: dict | None = None,
        description: str = "",
    ) -> dict:
        identity = self._pending_identity(cid, kind, *identity_parts)
        now = self.store.now()
        with self.store.tx():
            existing = self.store.one("SELECT * FROM pending_actions WHERE campaign_id=? AND identity_key=?", (cid, identity))
            if existing:
                if existing["status"] in PENDING_TERMINAL:
                    # same condition recurred after resolution: reopen, keep old resolution in history
                    history = loads(existing["payload"], {}) or {}
                    history.setdefault("prior_resolutions", []).append(loads(existing["resolution"], {}))
                    history.update(payload or {})
                    self.store.conn.execute(
                        "UPDATE pending_actions SET status='open', resolution=NULL, payload=?, updated_at=? WHERE id=?",
                        (dumps(history), now, existing["id"]),
                    )
                    self._ledger(cid, "pending-action", "reopen", requested_by, id=existing["id"], kind=kind)
                return self.get_pending_action(existing["id"])
            action_id = new_id("pa")
            self.store.conn.execute(
                "INSERT INTO pending_actions(id,campaign_id,identity_key,kind,title,description,status,priority,"
                "source_job_id,source_finding_id,source_member,scope,required_receipt_type,requested_by,payload,"
                "created_at,updated_at) VALUES(?,?,?,?,?,?,'open',?,?,?,?,?,?,?,?,?,?)",
                (action_id, cid, identity, kind, title, description, priority, source_job_id, source_finding_id,
                 source_member, scope, required_receipt_type, requested_by, dumps(payload or {}), now, now),
            )
            self._ledger(cid, "pending-action", "open", requested_by, id=action_id, kind=kind, title=title,
                         source_job_id=source_job_id, source_finding_id=source_finding_id, scope=scope)
        return self.get_pending_action(action_id)

    def get_pending_action(self, action_id: str) -> dict:
        row = self.store.one("SELECT * FROM pending_actions WHERE id=?", (action_id,))
        if not row:
            raise KeyError(f"unknown pending action: {action_id}")
        data = dict(row)
        data["payload"] = loads(data["payload"], {})
        data["resolution"] = loads(data["resolution"], None)
        return data

    def list_pending_actions(self, cid: str, *, open_only: bool = True, kind: str | None = None) -> list[dict]:
        sql = "SELECT id FROM pending_actions WHERE campaign_id=?"
        args: list[Any] = [cid]
        if open_only:
            sql += " AND status IN ('open','claimed')"
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        sql += " ORDER BY created_at, id"
        return [self.get_pending_action(r["id"]) for r in self.store.all(sql, tuple(args))]

    def _finish_pending(self, cid: str, action: dict, actor: str, status: str, receipt_type: str | None, receipt: dict) -> dict:
        resolution = {"status": status, "resolved_by": actor, "receipt_type": receipt_type,
                      "receipt": receipt, "resolved_at": self.store.now()}
        with self.store.tx():
            self.store.conn.execute(
                "UPDATE pending_actions SET status=?, resolution=?, updated_at=? WHERE id=?",
                (status, dumps(resolution), self.store.now(), action["id"]),
            )
            self._ledger(cid, "pending-action", "resolve", actor, id=action["id"], kind=action["kind"],
                         status=status, receipt_type=receipt_type, receipt=receipt)
        return self.get_pending_action(action["id"])

    def resolve_pending_action(self, cid: str, action_id: str, *, actor: str, status: str,
                               receipt_type: str | None, receipt: dict) -> dict:
        """Resolve with a typed receipt. Only supervisor/human actors may resolve."""
        self._require_operator(actor, "resolve pending actions")
        action = self.get_pending_action(action_id)
        if action["campaign_id"] != cid:
            raise ValueError("pending action does not belong to campaign")
        if action["status"] not in PENDING_OPEN:
            raise ValueError(f"pending action already {action['status']}")
        if status not in PENDING_TERMINAL:
            raise ValueError(f"status must be one of {sorted(PENDING_TERMINAL)}")
        if not receipt_type or not receipt_has_material(receipt):
            raise ValueError("pending action resolution requires receipt_type and receipt evidence")
        required = action.get("required_receipt_type")
        if required and receipt_type != required:
            raise ValueError(f"pending action requires {required} receipt")
        if action["kind"] == "fuzz_escalation" and status == "done":
            raise ValueError("use approve_escalation to approve fuzz escalation")
        with self.store.tx():
            out = self._finish_pending(cid, action, actor, status, receipt_type, receipt)
            self._cascade_pending_resolution(cid, action, actor)
        return out

    def _cascade_pending_resolution(self, cid: str, action: dict, actor: str) -> None:
        """Hook implemented by the engine (blocked/budget-blocked job cleanup)."""

    # -- lineage hooks (no-ops unless LineageMixin/ReuseMixin are composed) ----
    def _lineage_deep_refusal(self, cid: str, member_sha256: str) -> list[str]:
        return []

    def _lineage_stage_reasons(self, cid: str) -> list[str]:
        return []

    def _on_job_succeeded(self, cid: str, job: dict, payload: dict, finding_ids: list[str]) -> None:
        return None

    def _lineage_attach_finding(self, cid: str, actor: str, cand: dict, job_id: str | None) -> str | None:
        return None

    # -- wishlist hooks (no-ops unless WishlistMixin is composed) ---------------
    def _wishlist_packet(self, cid: str, job: dict) -> dict | None:
        return None

    def _wishlist_status(self, cid: str) -> dict | None:
        return None

    def _wishlist_blockers(self, cid: str, job: dict) -> list[str]:
        return []

    def _wishlist_on_stage(self, cid: str, actor: str) -> None:
        return None

    # -- storage hooks (no-ops unless StorageMixin is composed) -----------------
    def _storage_claim_block(self, cid: str, job: dict) -> str | None:
        return None

    def _storage_status(self, cid: str) -> dict | None:
        return None
