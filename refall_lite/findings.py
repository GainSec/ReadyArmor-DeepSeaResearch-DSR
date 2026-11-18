"""Findings, evidence promotion gates, dispositions and fuzz-ready escalation.

Tier ladder: hypothesis -> independently_checked -> validated.
Dispositions: rejected, duplicate, known_cve (suppressive; typed receipt required).
known_cve saves an already-disclosed-CVE finding as an actionable lead instead
of promoting it as novel.
Every proposal is recorded (accepted or refused, with reasons) in
finding_transitions and the ledger — adapted from ArcticBase
``CoverageStore.transition_finding``.
"""
from __future__ import annotations

from typing import Any

from ._base import Base
from .arcticbase.contracts import (
    OPERATOR_KINDS,
    TIERS,
    evaluate_finding_candidate,
    evaluate_transition,
    finding_dedup_key,
    normalize_sha256,
    receipt_has_material,
    redact,
    string_list,
)
from .arcticbase.store import dumps, loads, new_id

PROVISIONAL_NOTE = ("requested status {req!r} ignored: model conclusions are provisional until deterministic "
                    "replay or an independent non-model check promotes them")
LIST_FIELDS = ("evidence", "source_anchors", "artifact_refs", "limitations", "contributors", "repro_hints")


def _merge(existing: list, new: list) -> list:
    import json
    out, seen = [], set()
    for item in [*existing, *new]:
        key = json.dumps(item, sort_keys=True, default=str)
        if key not in seen and item not in (None, "", [], {}):
            seen.add(key)
            out.append(item)
    return out


class FindingsMixin(Base):
    # -- candidates --------------------------------------------------------
    def _candidate_from_submission(self, cid: str, job: dict, payload: dict, raw: Any) -> dict:
        cand = dict(raw) if isinstance(raw, dict) else {}
        if job["target_type"] == "member":
            cand.setdefault("member_sha256", job["target_ref"])
        else:
            cand.setdefault("image_id", job["target_ref"])
        # inherit parent evidence/anchors like REFALL validate_submission_contract
        for key in ("evidence", "source_anchors", "artifact_refs"):
            if not cand.get(key) and payload.get(key):
                cand[key] = payload[key]
        cand.setdefault("confidence", payload.get("confidence"))
        return cand

    def _candidate_reasons(self, cid: str, cand: dict) -> list[str]:
        reasons = evaluate_finding_candidate(cand)
        msha = normalize_sha256(cand.get("member_sha256"))
        if msha and not self.store.one("SELECT 1 FROM members WHERE campaign_id=? AND sha256=?", (cid, msha)):
            reasons.append("member_sha256 is not part of this campaign")
        if cand.get("image_id") and not self.store.one("SELECT 1 FROM images WHERE campaign_id=? AND id=?", (cid, cand["image_id"])):
            reasons.append("image_id is not part of this campaign")
        return reasons

    def record_finding(self, cid: str, *, actor: str, candidate: dict) -> dict:
        self.actor(actor)
        reasons = self._candidate_reasons(cid, candidate)
        if reasons:
            with self.store.tx():
                self._ledger(cid, "finding", "refuse", actor, title=candidate.get("title"), reasons=reasons)
            return {"accepted": False, "reasons": reasons, "finding": None, "merged": False}
        with self.store.tx():
            return self._record_finding_locked(cid, actor, candidate)

    def _record_finding_locked(self, cid: str, actor_id: str, cand: dict, job_id: str | None = None) -> dict:
        actor = self.actor(actor_id)
        cand = redact(cand)
        limitations = string_list(cand.get("limitations"))
        for key in ("tier", "status", "quality_tier", "repro_status"):
            req = str(cand.get(key) or "").strip()
            if req and req.lower() not in {"hypothesis", "provisionally_valid", "needs_research", "not_attempted"}:
                limitations.append(PROVISIONAL_NOTE.format(req=req))
        msha = normalize_sha256(cand.get("member_sha256")) or None
        body = {
            "description": cand.get("description", ""),
            "impact": cand.get("impact", ""),
            "confidence": cand.get("confidence", ""),
            "evidence": list(cand.get("evidence") or []),
            "claim": cand.get("claim") if isinstance(cand.get("claim"), dict) else {},
            "technique_id": str(cand.get("technique_id") or ""),
            "source_anchors": string_list(cand.get("source_anchors")),
            "artifact_refs": string_list(cand.get("artifact_refs")),
            "limitations": limitations,
            "repro_hints": string_list(cand.get("repro_hints")),
            "contributors": [actor_id],
            "history": [],
        }
        key = finding_dedup_key(cid, cand)
        now = self.store.now()
        existing = self.store.one("SELECT * FROM findings WHERE campaign_id=? AND dedup_key=?", (cid, key))
        if existing:
            payload = loads(existing["payload"], {})
            for f in LIST_FIELDS:
                payload[f] = _merge(payload.get(f) or [], body.get(f) or [])
            payload.setdefault("history", []).append({"type": "merge", "actor": actor_id, "job_id": job_id, "ts": now})
            self.store.conn.execute("UPDATE findings SET payload=?, updated_at=? WHERE id=?", (dumps(payload), now, existing["id"]))
            self._ledger(cid, "finding", "merge", actor_id, finding_id=existing["id"], job_id=job_id)
            return {"accepted": True, "reasons": [], "merged": True, "finding": self.get_finding(existing["id"])}
        canonical = self._lineage_attach_finding(cid, actor_id, cand, job_id)
        if canonical:
            payload = loads(self.store.scalar("SELECT payload FROM findings WHERE id=?", (canonical,)), {})
            payload["contributors"] = _merge(payload.get("contributors") or [], [actor_id])
            payload.setdefault("history", []).append({"type": "variant-attach", "actor": actor_id, "job_id": job_id,
                                                      "member_sha256": msha, "ts": now})
            self.store.conn.execute("UPDATE findings SET payload=?, updated_at=? WHERE id=?", (dumps(payload), now, canonical))
            return {"accepted": True, "reasons": [], "merged": True, "applicability_attached": True,
                    "finding": self.get_finding(canonical)}
        fid = new_id("find")
        self.store.conn.execute(
            "INSERT INTO findings(id,campaign_id,dedup_key,title,vuln_class,severity,tier,member_sha256,image_id,job_id,"
            "created_by,origin_kind,payload,created_at,updated_at) VALUES(?,?,?,?,?,?,'hypothesis',?,?,?,?,?,?,?,?)",
            (fid, cid, key, cand["title"].strip(), cand.get("vuln_class") or "", str(cand["severity"]).lower(), msha,
             cand.get("image_id"), job_id, actor_id, actor["kind"], dumps(body), now, now))
        self._ledger(cid, "finding", "create", actor_id, finding_id=fid, tier="hypothesis", member_sha256=msha,
                     severity=str(cand["severity"]).lower(), origin_kind=actor["kind"], job_id=job_id)
        return {"accepted": True, "reasons": [], "merged": False, "finding": self.get_finding(fid)}

    # -- reads ---------------------------------------------------------------
    def get_finding(self, finding_id: str) -> dict:
        row = self.store.one("SELECT * FROM findings WHERE id=?", (finding_id,))
        if not row:
            raise KeyError(f"unknown finding {finding_id}")
        data = dict(row)
        data.update(loads(data.pop("payload"), {}))
        data["receipts"] = [
            {**dict(r), "receipt": loads(r["receipt"], {})}
            for r in self.store.all("SELECT * FROM transition_receipts WHERE finding_id=? ORDER BY created_at, rowid", (finding_id,))
        ]
        return data

    def list_findings(self, cid: str, tier: str | None = None) -> list[dict]:
        sql, args = "SELECT id FROM findings WHERE campaign_id=?", [cid]
        if tier:
            sql += " AND tier=?"
            args.append(tier)
        return [self.get_finding(r["id"]) for r in self.store.all(sql + " ORDER BY created_at, id", tuple(args))]

    def finding_occurrences(self, finding_id: str) -> list[dict]:
        f = self.get_finding(finding_id)
        if f.get("member_sha256"):
            return self.member_occurrences(f["campaign_id"], f["member_sha256"])
        img = self.get_image(f["image_id"])
        return [{"member_sha256": None, "image_id": img["id"], "image_name": img["name"],
                 "image_sha256": img["image_sha256"], "family": img["family"], "path": None}]

    def list_transitions(self, cid: str, finding_id: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM finding_transitions WHERE campaign_id=?", [cid]
        if finding_id:
            sql += " AND finding_id=?"
            args.append(finding_id)
        out = []
        for r in self.store.all(sql + " ORDER BY created_at, rowid", tuple(args)):
            d = dict(r)
            d["reasons"] = loads(d["reasons"], [])
            d["receipt"] = loads(d["receipt"], {})
            out.append(d)
        return out

    # -- transitions -----------------------------------------------------------
    def transition_finding(self, cid: str, finding_id: str, *, actor: str, to: str, receipt_type: str | None,
                           receipt: dict | None, duplicate_of: str | None = None) -> dict:
        actor_row = self.actor(actor)
        receipt = redact(receipt) if isinstance(receipt, dict) else {}
        with self.store.tx():
            finding = self.get_finding(finding_id)
            if finding["campaign_id"] != cid:
                raise ValueError("finding does not belong to campaign")
            dup_exists = bool(duplicate_of and self.store.one(
                "SELECT 1 FROM findings WHERE id=? AND campaign_id=?", (duplicate_of, cid)))
            reasons = evaluate_transition(finding, to=to, actor=actor_row, receipt_type=receipt_type, receipt=receipt,
                                          duplicate_of=duplicate_of, duplicate_exists=dup_exists)
            status = "refused" if reasons else "accepted"
            tid = new_id("tr")
            now = self.store.now()
            self.store.conn.execute(
                "INSERT INTO finding_transitions(id,campaign_id,finding_id,from_state,to_state,actor,receipt_type,receipt,"
                "duplicate_of,status,reasons,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (tid, cid, finding_id, finding["tier"], to, actor, receipt_type, dumps(receipt), duplicate_of, status,
                 dumps(reasons), now))
            if not reasons:
                body = loads(self.store.scalar("SELECT payload FROM findings WHERE id=?", (finding_id,)), {})
                body.setdefault("history", []).append({"type": "transition", "transition_id": tid, "from": finding["tier"],
                                                       "to": to, "actor": actor, "receipt_type": receipt_type, "ts": now})
                # limitations are append-only: a promotion never drops them
                body["limitations"] = _merge(body.get("limitations") or [], string_list(receipt.get("limitations")))
                self.store.conn.execute(
                    "UPDATE findings SET tier=?, duplicate_of=COALESCE(?,duplicate_of), payload=?, updated_at=? WHERE id=?",
                    (to, duplicate_of, dumps(body), now, finding_id))
                self.store.conn.execute(
                    "INSERT INTO transition_receipts(id,transition_id,finding_id,campaign_id,receipt_type,receipt,actor,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)", (new_id("rec"), tid, finding_id, cid, receipt_type, dumps(receipt), actor, now))
            kind = "validation" if to in TIERS else "disposition-transition"
            self._ledger(cid, kind, status, actor, transition_id=tid, finding_id=finding_id, from_state=finding["tier"],
                         to_state=to, receipt_type=receipt_type, reasons=reasons, actor_kind=actor_row["kind"])
        return {"accepted": not reasons, "reasons": reasons, "transition_id": tid, "finding": self.get_finding(finding_id)}

    # -- fuzz-ready escalation ---------------------------------------------------
    def request_escalation(self, cid: str, member_sha256: str, *, actor: str, finding_id: str, receipt: dict) -> dict:
        self.actor(actor)
        camp = self.get_campaign(cid)
        reasons = []
        if camp["status"] != "active":
            reasons.append(f"campaign {camp['status']}")
        if camp["current_stage"] not in {"deep", "fuzz_ready"}:
            reasons.append("escalation requires stage deep")
        try:
            finding = self.get_finding(finding_id)
        except KeyError:
            finding = None
        if not finding or finding["campaign_id"] != cid or finding.get("member_sha256") != normalize_sha256(member_sha256):
            reasons.append("finding must exist on this member")
        elif TIERS.get(finding["tier"], -1) < TIERS["independently_checked"]:
            reasons.append(f"finding tier {finding['tier']} below independently_checked; model hypotheses cannot justify fuzzing")
        if not string_list((receipt or {}).get("artifact_refs")):
            reasons.append("escalation requires harness/build artifact_refs (fuzzing readiness)")
        if reasons:
            with self.store.tx():
                self._ledger(cid, "stage-gate", "escalation_refused", actor, member_sha256=member_sha256, reasons=reasons)
            return {"accepted": False, "reasons": reasons, "action": None}
        action = self._open_pending(cid, "fuzz_escalation", f"Escalate {member_sha256[:12]} to fuzz-ready",
                                    identity_parts=(member_sha256,), source_finding_id=finding_id, source_member=member_sha256,
                                    requested_by=actor, payload={"harness_receipt": receipt})
        return {"accepted": True, "reasons": [], "action": action}

    def approve_escalation(self, cid: str, action_id: str, *, actor: str, receipt: dict, lane_hint: str = "oss-crs-optional") -> dict:
        approver = self.actor(actor)
        action = self.get_pending_action(action_id)
        reasons = []
        if action["campaign_id"] != cid or action["kind"] != "fuzz_escalation":
            reasons.append("not a fuzz escalation for this campaign")
        if action["status"] not in {"open", "claimed"}:
            reasons.append(f"escalation already {action['status']}")
        if approver["kind"] not in OPERATOR_KINDS:
            reasons.append(f"actor kind {approver['kind']} cannot approve escalation")
        if actor == action.get("requested_by"):
            reasons.append("requester cannot approve their own escalation")
        if not receipt_has_material(receipt):
            reasons.append("approval requires receipt evidence")
        if reasons:
            with self.store.tx():
                self._ledger(cid, "stage-gate", "escalation_approval_refused", actor, action_id=action_id, reasons=reasons)
            return {"accepted": False, "reasons": reasons, "job": None}
        with self.store.tx():
            self._finish_pending(cid, action, actor, "done", "escalation_approval", receipt)
            res = self._enqueue(cid, stage="fuzz_ready", kind="fuzz-harness", target_type="member",
                                target_ref=action["source_member"], actor=actor, allow_ahead=True,
                                payload={"lane_hint": lane_hint, "finding_id": action["source_finding_id"],
                                         "harness_refs": string_list(action["payload"].get("harness_receipt", {}).get("artifact_refs"))})
        return {"accepted": not res["refused"], "reasons": res["reasons"], "job": res["job"]}
