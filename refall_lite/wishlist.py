"""Single-supervisor wishlist (schema v3): durable capability requests for one DSR model lane.

Semantics adapted from REFALL-V11 (coverage_service wishlist table/CRUD, ref_all_executor provided-wishlist
preflight): a researcher records what it NEEDS instead of improvising, and delivered items are injected into
later task packets so they are reused rather than requested or rebuilt again.

DSR differences (see docs/WISHLIST.md):
  * one supervisor: any registered actor may request; only operator kinds (supervisor/human) resolve. There is
    no claiming, assignment, team, or owner model. Wishlist items are not pending_actions.
  * identity = (campaign, scope, kind, normalised item); recurrence deduplicates, reopens, or is refused with a
    ledgered decision instead of inserting a new row.
  * resolving a missing capability is an investment-triage decision (provide_now | use_existing_alternative |
    defer_with_trigger | decline) with a durable rationale, assessment and objective revisit trigger. Triggers are
    re-evaluated on recurrence, at stage transitions, and on an explicit supervisor revisit pass.
  * a blocking item must name a non-campaign scope and pauses only the jobs that depend on it.
  * every accepted or refused mutation is ledgered (kind ``wishlist``) in the same transaction and reaches
    telemetry only after COMMIT.
  * provided capabilities carry bounded provenance/version/transport/config *references*; credential values are
    refused (contracts.evaluate_capability), never stored, and never placed in packets.
Structural input errors (unknown campaign/actor/kind, empty text, cross-campaign linkage) raise and write nothing.
"""
from __future__ import annotations

from typing import Any

from ._base import Base
from .arcticbase.contracts import (
    WISH_DECLINED,
    WISH_DEDUP,
    WISH_ITEM_MAX,
    WISH_KINDS,
    WISH_OUTSTANDING,
    WISH_REOPEN,
    WISH_SCOPES,
    WISH_STATUSES,
    WISH_TEXT_MAX,
    evaluate_wish_resolution,
    fired_triggers,
    normalize_sha256,
    normalize_wish_item,
    redact,
    sha256_text,
)
from .arcticbase.store import dumps, loads, new_id

PACKET_LIMIT = 25
PACKET_TEXT = 300
HISTORY_MAX = 50
_MARKS = ",".join("?" * len(WISH_OUTSTANDING))
PACKET_RULES = [
    "Use the provided capabilities listed here before anything else; do not request or rebuild them.",
    "Do not install packages, build harnesses, or create MCP servers yourself. If a capability is missing, "
    "request it on the wishlist (kind, item, reason, required_for) and continue with what is available.",
    "Do not re-request items listed under requested or declined. For declined or deferred items, continue with the "
    "available evidence (or the named alternative) and record the missing capability as a limitation.",
    "Web search exists only as a provided web_search capability. If none is provided, no live search is available: "
    "request kind=web_search rather than guessing or simulating results.",
]


def _text(value: object, field: str, limit: int = WISH_TEXT_MAX) -> str:
    text = redact(str(value or "")).strip()
    if not text:
        raise ValueError(f"wishlist {field} required")
    if len(text) > limit:
        raise ValueError(f"wishlist {field} exceeds {limit} chars")
    return text


class WishlistMixin(Base):
    # -- reads ---------------------------------------------------------------
    def get_wish(self, wish_id: str) -> dict:
        row = self.store.one("SELECT * FROM wishlist_items WHERE id=?", (wish_id,))
        if not row:
            raise KeyError(f"unknown wishlist item: {wish_id}")
        data = dict(row)
        data["blocking"] = bool(data["blocking"])
        for key, default in (("resolution", None), ("capability", None), ("decision", None), ("history", [])):
            data[key] = loads(data[key], default)
        return data

    def list_wishes(self, cid: str, *, status: str | None = None, kind: str | None = None) -> list[dict]:
        self.get_campaign(cid)
        sql, args = "SELECT id FROM wishlist_items WHERE campaign_id=?", [cid]
        if status:
            sql += " AND status=?"
            args.append(status)
        if kind:
            sql += " AND kind=?"
            args.append(kind)
        return [self.get_wish(r["id"]) for r in self.store.all(sql + " ORDER BY created_at, id", tuple(args))]

    # -- helpers -------------------------------------------------------------
    def _wish_links(self, cid: str, *, job_id: str | None, image_id: str | None, member_sha256: str | None,
                    code_unit_id: str | None, finding_id: str | None) -> dict:
        """Optional linkage; every reference must exist in this campaign (no cross-campaign leakage)."""
        links: dict[str, str | None] = {"job": None, "image": None, "member": None, "code_unit": None, "finding": None}
        member = normalize_sha256(member_sha256) if member_sha256 else None
        if member_sha256 and not member:
            raise ValueError(f"wishlist member_sha256 must be 64-hex: {member_sha256!r}")
        checks = (("job", job_id, "SELECT id FROM jobs WHERE id=? AND campaign_id=?"),
                  ("image", image_id, "SELECT id FROM images WHERE id=? AND campaign_id=?"),
                  ("member", member, "SELECT sha256 FROM members WHERE sha256=? AND campaign_id=?"),
                  ("code_unit", code_unit_id, "SELECT id FROM code_units WHERE id=? AND campaign_id=?"),
                  ("finding", finding_id, "SELECT id FROM findings WHERE id=? AND campaign_id=?"))
        for name, ref, sql in checks:
            if ref:
                if not self.store.one(sql, (ref, cid)):
                    raise ValueError(f"wishlist {name} link {ref} does not exist in campaign {cid}")
                links[name] = ref
        return links

    def _covering_provided(self, cid: str, kind: str, item_key: str) -> dict | None:
        row = self.store.one("SELECT id FROM wishlist_items WHERE campaign_id=? AND kind=? AND item_key=? AND "
                             "scope_type='campaign' AND status='provided'", (cid, kind, item_key))
        return self.get_wish(row["id"]) if row else None

    @staticmethod
    def _append_history(wish: dict, entry: dict) -> str:
        return dumps((wish["history"] + [entry])[-HISTORY_MAX:])

    @staticmethod
    def _head(wish: dict) -> dict:
        head = {"wish_id": wish["id"], "kind": wish["kind"], "item_key": wish["item_key"], "scope": wish["scope_type"],
                "scope_ref": wish["scope_ref"]}
        head.update({k: wish[k] for k in ("job_id", "image_id", "member_sha256", "code_unit_id", "finding_id") if wish.get(k)})
        return head

    def _trigger_state(self, cid: str, request_count: int) -> dict:
        camp = self.get_campaign(cid)
        material = sorted({s.lower() for s in camp["config"].get("material_severities") or []})
        awaiting = bool(material) and bool(self.store.scalar(
            f"SELECT COUNT(*) FROM findings WHERE campaign_id=? AND tier IN ('hypothesis','independently_checked') "
            f"AND severity IN ({','.join('?' * len(material))})", (cid, *material)))
        members = self.store.scalar(
            "SELECT MAX(n) FROM (SELECT COUNT(*) n FROM code_family_members m JOIN code_families f ON f.id=m.family_id "
            "WHERE f.campaign_id=? AND f.status='approved' AND m.status='approved' GROUP BY f.id)", (cid,))
        return {"request_count": request_count, "stage": camp["current_stage"], "material_awaiting": awaiting,
                "max_family_members": int(members or 0), "now": self.store.now()}

    def _revisit_if_fired(self, cid: str, wish: dict, actor: str | None, source: str) -> bool:
        """Reopen a deferred/declined item whose objective revisit trigger holds (receipt-backed + ledgered)."""
        trigger = (wish.get("decision") or {}).get("revisit_trigger")
        if not trigger or wish["status"] not in {"deferred", *WISH_DECLINED}:
            return False
        fired = fired_triggers(trigger, self._trigger_state(cid, wish["request_count"]))
        if not fired:
            return False
        now = self.store.now()
        receipt = {"evidence_refs": [f"trigger:{f}" for f in fired], "summary": f"revisit trigger fired ({source})"}
        entry = {"event": "revisit", "actor": actor, "at": now, "from": wish["status"], "fired": fired, "source": source,
                 "prior_disposition": wish["disposition"], "prior_decision": wish["decision"],
                 "prior_resolution": wish["resolution"]}
        self.store.conn.execute(
            "UPDATE wishlist_items SET status='open', disposition=NULL, decision=NULL, resolved_by=NULL, resolution=NULL, "
            "history=?, updated_at=? WHERE id=?", (self._append_history(wish, entry), now, wish["id"]))
        self._ledger(cid, "wishlist", "revisit", actor, **self._head(wish), from_status=wish["status"],
                     prior_disposition=wish["disposition"], fired=fired, source=source, receipt=receipt)
        return True

    def _revisit_pass(self, cid: str, actor: str | None, source: str) -> list[str]:
        reopened = []
        for r in self.store.all("SELECT id FROM wishlist_items WHERE campaign_id=? AND status IN ('deferred','denied','superseded') "
                                "AND decision IS NOT NULL ORDER BY created_at, id", (cid,)):
            if self._revisit_if_fired(cid, self.get_wish(r["id"]), actor, source):
                reopened.append(r["id"])
        return reopened

    # -- request -------------------------------------------------------------
    def request_wish(self, cid: str, *, actor: str, kind: str, item: str, reason: str, required_for: str,
                     scope: str = "campaign", job_id: str | None = None, image_id: str | None = None,
                     member_sha256: str | None = None, code_unit_id: str | None = None, finding_id: str | None = None,
                     blocking: bool = False) -> dict:
        """Record a needed capability. Returns {accepted, outcome: created|deduplicated|reopened|refused, reasons, wish}."""
        self.actor(actor)
        camp = self.get_campaign(cid)
        if kind not in WISH_KINDS:
            raise ValueError(f"wishlist kind must be one of {sorted(WISH_KINDS)}")
        if scope not in WISH_SCOPES:
            raise ValueError(f"wishlist scope must be one of {list(WISH_SCOPES)}")
        if blocking and scope == "campaign":
            raise ValueError("a blocking wishlist item must name the dependent scope (job/image/member/code_unit/finding); "
                             "campaign-wide blockers would stall unrelated work")
        item_text = _text(item, "item", WISH_ITEM_MAX)
        item_key = normalize_wish_item(item_text)
        if not item_key:
            raise ValueError("wishlist item has no identifiable name")
        reason_text, needed_for = _text(reason, "reason"), _text(required_for, "required_for")
        links = self._wish_links(cid, job_id=job_id, image_id=image_id, member_sha256=member_sha256,
                                 code_unit_id=code_unit_id, finding_id=finding_id)
        scope_ref = "" if scope == "campaign" else (links[scope] or "")
        if scope != "campaign" and not scope_ref:
            raise ValueError(f"wishlist scope {scope} requires the matching {scope} link")
        identity = sha256_text("|".join([cid, scope, scope_ref, kind, item_key]))
        now = self.store.now()
        ids = {k: v for k, v in (("job_id", links["job"]), ("image_id", links["image"]), ("member_sha256", links["member"]),
                                 ("code_unit_id", links["code_unit"]), ("finding_id", links["finding"])) if v}
        head = {"kind": kind, "item_key": item_key, "scope": scope, "scope_ref": scope_ref, **ids}
        with self.store.tx():
            row = self.store.one("SELECT id FROM wishlist_items WHERE campaign_id=? AND identity_key=?", (cid, identity))
            existing = self.get_wish(row["id"]) if row else None
            covering = self._covering_provided(cid, kind, item_key) if scope != "campaign" else None
            reasons: list[str] = []
            if camp["status"] != "active":
                reasons.append(f"campaign {camp['status']}")
            elif existing and existing["status"] == "provided":
                reasons.append(f"already provided as {existing['id']}; use the provided capability")
            elif not existing and covering:
                reasons.append(f"already provided campaign-wide as {covering['id']}; use the provided capability")
            if reasons:
                self._ledger(cid, "wishlist", "request_refused", actor, **head,
                             wish_id=(existing or covering or {}).get("id"), reasons=reasons)
                return {"accepted": False, "outcome": "refused", "reasons": reasons, "wish": existing or covering}
            if existing and existing["status"] in WISH_DEDUP | WISH_DECLINED:
                count = existing["request_count"] + 1
                self.store.conn.execute(
                    "UPDATE wishlist_items SET request_count=?, blocking=MAX(blocking,?), history=?, updated_at=? WHERE id=?",
                    (count, int(bool(blocking)), self._append_history(existing, {"event": "recur", "actor": actor, "at": now, **ids}),
                     now, existing["id"]))
                existing = self.get_wish(existing["id"])
                declined: list[str] = []
                if existing["status"] in WISH_DECLINED:
                    declined = [f"{existing['status']} by the supervisor ({existing['disposition'] or 'no disposition'}); "
                                "continue with the available evidence and record the limitation"]
                    self._ledger(cid, "wishlist", "request_refused", actor, **head, wish_id=existing["id"],
                                 status=existing["status"], request_count=count, reasons=declined)
                else:
                    self._ledger(cid, "wishlist", "dedup", actor, wish_id=existing["id"], **head,
                                 status=existing["status"], request_count=count)
                if self._revisit_if_fired(cid, existing, actor, "request recurrence"):
                    return {"accepted": True, "outcome": "reopened", "reasons": [], "wish": self.get_wish(existing["id"])}
                if existing["status"] in WISH_DECLINED:
                    return {"accepted": False, "outcome": "refused", "reasons": declined, "wish": existing}
                return {"accepted": True, "outcome": "deduplicated", "reasons": [], "wish": existing}
            if existing and existing["status"] in WISH_REOPEN:
                prior = {"event": "reopen", "actor": actor, "at": now, "from": existing["status"],
                         "prior_resolution": existing["resolution"], "prior_reason": existing["reason"],
                         "prior_required_for": existing["required_for"]}
                self.store.conn.execute(
                    "UPDATE wishlist_items SET status='open', reason=?, required_for=?, blocking=?, resolved_by=NULL, "
                    "resolution=NULL, disposition=NULL, decision=NULL, request_count=request_count+1, history=?, "
                    "updated_at=? WHERE id=?",
                    (reason_text, needed_for, int(bool(blocking)), self._append_history(existing, prior), now, existing["id"]))
                self._ledger(cid, "wishlist", "reopen", actor, wish_id=existing["id"], **head, from_status=existing["status"])
                return {"accepted": True, "outcome": "reopened", "reasons": [], "wish": self.get_wish(existing["id"])}
            wish_id = new_id("wish")
            self.store.conn.execute(
                "INSERT INTO wishlist_items(id,campaign_id,identity_key,kind,item,item_key,scope_type,scope_ref,job_id,"
                "image_id,member_sha256,code_unit_id,finding_id,reason,required_for,blocking,requested_by,status,"
                "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open',?,?)",
                (wish_id, cid, identity, kind, item_text, item_key, scope, scope_ref, links["job"], links["image"],
                 links["member"], links["code_unit"], links["finding"], reason_text, needed_for, int(bool(blocking)),
                 actor, now, now))
            self._ledger(cid, "wishlist", "request", actor, wish_id=wish_id, **head, blocking=bool(blocking))
        return {"accepted": True, "outcome": "created", "reasons": [], "wish": self.get_wish(wish_id)}

    # -- resolve / triage (operator/human supervisor only) ---------------------
    def resolve_wish(self, cid: str, wish_id: str, *, actor: str, status: str, receipt: dict | None,
                     capability: dict | None = None, superseded_by: str | None = None,
                     decision: dict | None = None) -> dict:
        """Move an item along the legal lifecycle; triage targets need a disposition decision record.

        Refusals (authority, transition, receipt, capability, decision/trigger) are ledgered and change nothing else.
        """
        actor_row = self.actor(actor)
        receipt = redact(receipt) if isinstance(receipt, dict) else {}
        with self.store.tx():
            wish = self.get_wish(wish_id)
            if wish["campaign_id"] != cid:
                raise ValueError("wishlist item does not belong to campaign")
            successor = None
            if superseded_by:
                row = self.store.one("SELECT id FROM wishlist_items WHERE id=? AND campaign_id=?", (superseded_by, cid))
                successor = self.get_wish(row["id"]) if row else None
            clean, dec, reasons = evaluate_wish_resolution(
                wish, to=status, actor=actor_row, receipt=receipt, capability=capability, superseded_by=successor,
                decision=decision, state=self._trigger_state(cid, wish["request_count"]))
            if superseded_by and not successor:
                reasons.append(f"superseded_by {superseded_by} is not a wishlist item in this campaign")
            if superseded_by and status != "superseded":
                reasons.append("superseded_by is only accepted with status superseded")
            head = {**self._head(wish), "from_status": wish["status"], "to_status": status, "actor_kind": actor_row["kind"]}
            if reasons:
                # names fields only; a refused capability (possibly holding a secret) is never copied here
                self._ledger(cid, "wishlist", "resolve_refused", actor, **head, reasons=reasons)
                return {"accepted": False, "reasons": reasons, "wish": wish}
            now = self.store.now()
            resolution = {"status": status, "resolved_by": actor, "receipt": receipt, "resolved_at": now}
            entry = {"event": "resolve", "actor": actor, "at": now, "from": wish["status"], "to": status,
                     "prior_resolution": wish["resolution"], "prior_disposition": wish["disposition"]}
            if dec:
                dec.update(decided_by=actor, decided_at=now)
            if dec:  # a triage decision replaces the previous one
                disposition, decision_json = dec["disposition"], dumps(dec)
            elif status == "open":  # supervisor reopen: needs fresh triage
                disposition, decision_json = None, None
            else:  # consumed/cancelled/provided-refresh keep the standing decision
                disposition, decision_json = wish["disposition"], (dumps(wish["decision"]) if wish["decision"] else None)
            self.store.conn.execute(
                "UPDATE wishlist_items SET status=?, resolved_by=?, resolution=?, capability=COALESCE(?,capability), "
                "superseded_by=COALESCE(?,superseded_by), disposition=?, decision=?, history=?, updated_at=? WHERE id=?",
                (status, actor, dumps(resolution), dumps(clean) if status == "provided" else None,
                 successor["id"] if successor else None, disposition, decision_json,
                 self._append_history(wish, entry), now, wish_id))
            self._ledger(cid, "wishlist", "resolve", actor, **head, receipt=receipt, disposition=disposition,
                         decision=dec or None, capability=clean if status == "provided" else None,
                         superseded_by=successor["id"] if successor else None)
        return {"accepted": True, "reasons": [], "wish": self.get_wish(wish_id)}

    def revisit_wishes(self, cid: str, *, actor: str) -> dict:
        """Supervisor revisit pass: reopen deferred/declined items whose objective trigger now holds."""
        self._require_operator(actor, "revisit wishlist decisions")
        with self.store.tx():
            pending = self.store.scalar("SELECT COUNT(*) FROM wishlist_items WHERE campaign_id=? AND "
                                        "status IN ('deferred','denied','superseded') AND decision IS NOT NULL", (cid,))
            reopened = self._revisit_pass(cid, actor, "supervisor revisit pass")
        return {"evaluated": pending, "reopened": reopened}

    def _wishlist_on_stage(self, cid: str, actor: str) -> None:
        self._revisit_pass(cid, actor, f"stage transition to {self.get_campaign(cid)['current_stage']}")

    # -- packet / claim / status projections ---------------------------------
    def _job_wish_scopes(self, cid: str, job: dict) -> set[tuple[str, str]]:
        """Scopes relevant to one job: campaign-wide, the job, and its target (image, or member + its images/units/findings)."""
        scopes = {("campaign", ""), ("job", job["id"])}
        ref = job["target_ref"]
        if job["target_type"] == "image":
            scopes.add(("image", ref))
            scopes |= {("finding", r["id"]) for r in self.store.all(
                "SELECT id FROM findings WHERE campaign_id=? AND image_id=?", (cid, ref))}
        else:
            scopes.add(("member", ref))
            for sql, scope in (("SELECT DISTINCT image_id AS id FROM occurrences WHERE campaign_id=? AND member_sha256=?", "image"),
                               ("SELECT id FROM code_units WHERE campaign_id=? AND content_sha256=?", "code_unit"),
                               ("SELECT id FROM findings WHERE campaign_id=? AND member_sha256=?", "finding")):
                scopes |= {(scope, r["id"]) for r in self.store.all(sql, (cid, ref))}
        return scopes

    def _wishlist_blockers(self, cid: str, job: dict) -> list[str]:
        """Outstanding blocking items this job depends on (claims skip the job; unrelated jobs are unaffected)."""
        rows = self.store.all(f"SELECT id,scope_type,scope_ref FROM wishlist_items WHERE campaign_id=? AND blocking=1 "
                              f"AND status IN ({_MARKS}) ORDER BY created_at, id", (cid, *WISH_OUTSTANDING))
        if not rows:
            return []
        scopes = self._job_wish_scopes(cid, job)
        return [r["id"] for r in rows if (r["scope_type"], r["scope_ref"]) in scopes]

    @staticmethod
    def _packet_entry(w: dict) -> dict:
        out = {"id": w["id"], "kind": w["kind"], "item": w["item"], "item_key": w["item_key"],
               "scope": w["scope_type"] if w["scope_type"] == "campaign" else f"{w['scope_type']}:{w['scope_ref']}",
               "status": w["status"], "required_for": w["required_for"][:PACKET_TEXT]}
        decision = w["decision"] or {}
        if w["status"] == "provided":
            out["capability"] = w["capability"] or {}
        elif w["status"] in WISH_DECLINED:
            out.update(disposition=w["disposition"], rationale=str(decision.get("rationale") or "")[:PACKET_TEXT],
                       alternative_ref=decision.get("alternative_ref"), superseded_by=w["superseded_by"])
        else:
            out.update(blocking=w["blocking"], disposition=w["disposition"], revisit_trigger=decision.get("revisit_trigger"))
        return out

    def _wishlist_packet(self, cid: str, job: dict) -> dict:
        scopes = self._job_wish_scopes(cid, job)
        rows = [self.get_wish(r["id"]) for r in self.store.all(
            f"SELECT id FROM wishlist_items WHERE campaign_id=? AND status IN ('provided','denied','superseded',{_MARKS}) "
            "ORDER BY blocking DESC, updated_at DESC, id", (cid, *WISH_OUTSTANDING))]
        rows = [w for w in rows if (w["scope_type"], w["scope_ref"]) in scopes]
        groups: dict[str, list[dict]] = {"provided": [], "requested": [], "declined": []}
        for w in rows:
            groups["provided" if w["status"] == "provided" else "declined" if w["status"] in WISH_DECLINED else "requested"].append(w)
        search = next((w for w in groups["provided"] if w["kind"] == "web_search"), None)
        return {
            "protocol": "dsr.capabilities.v1",
            **{name: [self._packet_entry(w) for w in items[:PACKET_LIMIT]] for name, items in groups.items()},
            "blockers": [w["id"] for w in groups["requested"] if w["blocking"]][:PACKET_LIMIT],
            "truncated": {name: max(0, len(items) - PACKET_LIMIT) for name, items in groups.items()},
            "web_search": ({"available": True, "wish_id": search["id"], "capability": search["capability"] or {}} if search else
                           {"available": False, "requested": any(w["kind"] == "web_search" for w in groups["requested"])}),
            "rules": PACKET_RULES,
        }

    def _wishlist_status(self, cid: str) -> dict:
        counts: dict[str, Any] = {s: 0 for s in sorted(WISH_STATUSES)}
        for r in self.store.all("SELECT status, COUNT(*) n FROM wishlist_items WHERE campaign_id=? GROUP BY status", (cid,)):
            counts[r["status"]] = r["n"]
        counts["open_blocking"] = self.store.scalar(
            f"SELECT COUNT(*) FROM wishlist_items WHERE campaign_id=? AND blocking=1 AND status IN ({_MARKS})", (cid, *WISH_OUTSTANDING))
        return counts

