"""Bounded campaign / job engine.

Responsibilities: campaign lifecycle, bounded job queue with leases and claim
tokens, budgets (run / stage / family / artifact; claims + cost units), retry
ceilings with failure classification, hard stop conditions, stage gates,
run manifest, checkpoints and resume.

This is *not* a planner or model supervisor: it never chooses models, never
calls workers, and never invents work. Hermes (supervisor) enqueues; workers
claim and submit; the engine enforces bounds and records everything.
"""
from __future__ import annotations

import copy
import uuid
from typing import Any

from ._base import Base
from .arcticbase.contracts import (
    CLAIMING_KINDS,
    JOB_UNRESOLVED,
    redact,
    OPERATOR_KINDS,
    STAGES,
    TIERS,
    canonical_json,
    resume_preflight,
    sha256_text,
    stable_id,
)
from .arcticbase.store import dumps, loads, new_id
from .worker import SUBMIT_SCHEMA, classify_failure, parse_submission

DEFAULTS: dict[str, Any] = {
    "max_attempts": 2,
    "lease_s": 900,
    "backoff_s": 5,
    "max_consecutive_failures": 5,
    "max_jobs": 10_000,
    "default_job_cost": 1,
    "deadline_at": None,
    "max_deep_selections": None,
    "middle_coverage_min": 0.0,
    "material_severities": ["medium", "high", "critical"],
    "methodology_bundle": None,
}
SCOPE_TYPES = ("run", "stage", "family", "artifact")


def _stage_index(stage: str) -> int:
    if stage not in STAGES:
        raise ValueError(f"unknown stage {stage!r}; stages are {STAGES}")
    return STAGES.index(stage)


def _validate_limit(scope: str, spec: Any) -> dict:
    if not isinstance(spec, dict):
        raise ValueError(f"budget {scope} must be an object")
    out = {}
    for key in ("max_claims", "max_cost"):
        value = spec.get(key)
        if value is None:
            continue
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValueError(f"budget {scope}.{key} must be a non-negative number")
        out[key] = value
    return out


class EngineMixin(Base):
    # ------------------------------------------------------------------ campaign
    def create_campaign(self, name: str, *, config: dict, actor: str) -> dict:
        self._require_operator(actor, "create campaigns")
        cfg = copy.deepcopy(DEFAULTS)
        cfg.update({k: v for k, v in (config or {}).items() if k != "budgets"})
        budgets = (config or {}).get("budgets") or {}
        run = budgets.get("run")
        if not isinstance(run, dict) or run.get("max_claims") is None or run.get("max_cost") is None:
            raise ValueError("campaign requires a bounded run budget: budgets.run.max_claims and budgets.run.max_cost")
        cfg["budgets"] = {}
        for scope, spec in budgets.items():
            stype = scope.split(":", 1)[0]
            if stype not in SCOPE_TYPES or (stype != "run" and ":" not in scope):
                raise ValueError(f"bad budget scope {scope!r}; use run, stage:<s>, family:<f>, artifact:<sha>, or <type>:*")
            cfg["budgets"][scope] = _validate_limit(scope, spec)
        if int(cfg["max_attempts"]) < 1:
            raise ValueError("max_attempts must be >= 1")
        if "lineage" in cfg:
            from .lineage import LINEAGE_DEFAULTS
            if not isinstance(cfg["lineage"], dict):
                raise ValueError("lineage config must be an object")
            unknown = sorted(set(cfg["lineage"]) - set(LINEAGE_DEFAULTS))
            if unknown:
                raise ValueError(f"unknown lineage config keys: {unknown}")
        now = self.store.now()
        cid = new_id("camp")
        with self.store.tx():
            self.store.conn.execute(
                "INSERT INTO campaigns(id,name,status,current_stage,config,created_by,created_at,updated_at) "
                "VALUES(?,?,'active','inventory',?,?,?,?)",
                (cid, name, dumps(cfg), actor, now, now),
            )
            self._ledger(cid, "campaign", "create", actor, name=name, config_sha256=sha256_text(canonical_json(cfg)))
        return self.get_campaign(cid)

    def _require_active(self, cid: str) -> dict:
        camp = self.get_campaign(cid)
        if camp["status"] != "active":
            raise ValueError(f"campaign {cid} is {camp['status']}" + (f" ({camp['stop_reason']})" if camp["stop_reason"] else ""))
        return camp

    def stop_campaign(self, cid: str, *, actor: str, reason: str) -> dict:
        self._require_operator(actor, "stop campaigns")
        self._stop(cid, "operator_stop", actor=actor, cancel_claimed=True, detail=reason)
        return self.get_campaign(cid)

    def _stop(self, cid: str, reason: str, *, actor: str | None, cancel_claimed: bool, detail: str = "") -> None:
        with self.store.tx():
            camp = self.get_campaign(cid)
            if camp["status"] != "active":
                return
            now = self.store.now()
            statuses = ("queued", "budget_blocked", "claimed") if cancel_claimed else ("queued", "budget_blocked")
            marks = ",".join("?" * len(statuses))
            cancelled = [r["id"] for r in self.store.all(
                f"SELECT id FROM jobs WHERE campaign_id=? AND status IN ({marks})", (cid, *statuses))]
            self.store.conn.execute(
                f"UPDATE jobs SET status='cancelled', claim_token=NULL, lease_expires=NULL, last_error=?, updated_at=? "
                f"WHERE campaign_id=? AND status IN ({marks})",
                (f"campaign stopped: {reason}", now, cid, *statuses),
            )
            self.store.conn.execute(
                "UPDATE campaigns SET status='stopped', stop_reason=?, updated_at=? WHERE id=?", (reason, now, cid))
            self._ledger(cid, "campaign", "stop", actor, reason=reason, detail=detail, cancelled_jobs=cancelled)

    def _check_deadline(self, cid: str) -> bool:
        camp = self.get_campaign(cid)
        deadline = camp["config"].get("deadline_at")
        if camp["status"] == "active" and deadline is not None and self.store.now() >= float(deadline):
            self._stop(cid, "deadline", actor=None, cancel_claimed=True)
            return True
        return False

    # ------------------------------------------------------------------ budgets
    def _limit(self, camp: dict, scope: str) -> dict:
        budgets = camp["config"]["budgets"]
        if scope in budgets:
            return budgets[scope]
        return budgets.get(scope.split(":", 1)[0] + ":*", {})

    def _usage(self, cid: str, scope: str) -> dict:
        row = self.store.one("SELECT claims_used,cost_used FROM budget_usage WHERE campaign_id=? AND scope=?", (cid, scope))
        return {"claims_used": row["claims_used"], "cost_used": row["cost_used"]} if row else {"claims_used": 0, "cost_used": 0.0}

    @staticmethod
    def _job_scopes(job: dict) -> list[str]:
        return ["run", f"stage:{job['stage']}", f"family:{job['family']}", f"artifact:{job['target_ref']}"]

    def _exhausted(self, camp: dict, scope: str) -> str | None:
        limit = self._limit(camp, scope)
        use = self._usage(camp["id"], scope)
        if "max_claims" in limit and use["claims_used"] >= limit["max_claims"]:
            return f"budget_exhausted:{scope}:claims"
        if "max_cost" in limit and use["cost_used"] >= limit["max_cost"]:
            return f"budget_exhausted:{scope}:cost"
        return None

    def _charge(self, cid: str, scopes: list[str], *, claims: int = 0, cost: float = 0.0) -> None:
        for scope in scopes:
            self.store.conn.execute(
                "INSERT INTO budget_usage(campaign_id,scope,claims_used,cost_used) VALUES(?,?,?,?) "
                "ON CONFLICT(campaign_id,scope) DO UPDATE SET claims_used=claims_used+excluded.claims_used, "
                "cost_used=cost_used+excluded.cost_used",
                (cid, scope, claims, cost),
            )

    def budget_usage(self, cid: str) -> dict:
        camp = self.get_campaign(cid)
        scopes = {r["scope"] for r in self.store.all("SELECT scope FROM budget_usage WHERE campaign_id=?", (cid,))}
        scopes |= {s for s in camp["config"]["budgets"] if not s.endswith(":*")}
        return {s: {**self._usage(cid, s), **self._limit(camp, s)} for s in sorted(scopes)}

    def _budget_remaining(self, camp: dict, job: dict) -> dict:
        out = {}
        for scope in self._job_scopes(job):
            limit, use = self._limit(camp, scope), self._usage(camp["id"], scope)
            key = scope.split(":", 1)[0]
            out[key] = {
                "scope": scope,
                "claims_remaining": None if "max_claims" not in limit else max(0, limit["max_claims"] - use["claims_used"]),
                "cost_remaining": None if "max_cost" not in limit else max(0, limit["max_cost"] - use["cost_used"]),
            }
        return out

    def raise_budget(self, cid: str, scope: str, *, actor: str, max_claims: float | None = None,
                     max_cost: float | None = None, reason: str = "") -> dict:
        """Operator-only budget change. Run budget exhaustion is a hard stop and is not reversible."""
        self._require_operator(actor, "change budgets")
        camp = self._require_active(cid)
        if scope.endswith(":*") or scope.split(":", 1)[0] not in SCOPE_TYPES:
            raise ValueError("raise_budget needs a concrete scope")
        with self.store.tx():
            cfg = camp["config"]
            limit = dict(self._limit(camp, scope))
            limit.update(_validate_limit(scope, {"max_claims": max_claims, "max_cost": max_cost}))
            cfg["budgets"][scope] = limit
            self.store.conn.execute("UPDATE campaigns SET config=?, updated_at=? WHERE id=?", (dumps(cfg), self.store.now(), cid))
            requeued = self._requeue_budget_blocked(cid, scope)
            self._ledger(cid, "budget", "raise", actor, scope=scope, limit=limit, reason=reason, requeued=requeued)
            for action in self.list_pending_actions(cid, kind="budget_decision"):
                if action["scope"] == scope:
                    self._finish_pending(cid, action, actor, "done", "budget_raise",
                                         {"evidence_refs": [f"budget {scope} raised to {limit}"], "summary": reason})
        return self.budget_usage(cid)

    def _requeue_budget_blocked(self, cid: str, scope: str) -> list[str]:
        ids = []
        for row in self.store.all("SELECT * FROM jobs WHERE campaign_id=? AND status='budget_blocked'", (cid,)):
            if scope in self._job_scopes(dict(row)):
                ids.append(row["id"])
                self.store.conn.execute("UPDATE jobs SET status='queued', updated_at=? WHERE id=?", (self.store.now(), row["id"]))
        return ids

    # ------------------------------------------------------------------ jobs
    def get_job(self, job_id: str) -> dict:
        row = self.store.one("SELECT * FROM jobs WHERE id=?", (job_id,))
        if not row:
            raise KeyError(f"unknown job: {job_id}")
        data = dict(row)
        data["payload"] = loads(data["payload"], {})
        data["result"] = loads(data["result"], None)
        return data

    def list_jobs(self, cid: str, *, stage: str | None = None, status: str | None = None) -> list[dict]:
        sql, args = "SELECT id FROM jobs WHERE campaign_id=?", [cid]
        if stage:
            sql += " AND stage=?"
            args.append(stage)
        if status:
            sql += " AND status=?"
            args.append(status)
        return [self.get_job(r["id"]) for r in self.store.all(sql + " ORDER BY seq", tuple(args))]

    def _enqueue(self, cid: str, *, stage: str, kind: str, target_type: str, target_ref: str, actor: str,
                 priority: int = 100, payload: dict | None = None, allow_ahead: bool = False) -> dict:
        """Returns {'job','deduplicated','refused','reasons'}; raises on structural errors."""
        camp = self._require_active(cid)
        if _stage_index(stage) > _stage_index(camp["current_stage"]) and not allow_ahead:
            raise ValueError(f"cannot enqueue {stage} work while campaign is at {camp['current_stage']}")
        if target_type == "image":
            row = self.store.one("SELECT family FROM images WHERE id=? AND campaign_id=?", (target_ref, cid))
        elif target_type == "member":
            row = self.store.one("SELECT primary_family AS family FROM members WHERE sha256=? AND campaign_id=?", (target_ref, cid))
        else:
            raise ValueError("target_type must be image or member")
        if not row:
            raise ValueError(f"unknown {target_type} {target_ref}")
        identity = f"{stage}|{kind}|{target_type}|{target_ref}"
        with self.store.tx():
            existing = self.store.one("SELECT id FROM jobs WHERE campaign_id=? AND identity_key=?", (cid, identity))
            if existing:
                return {"job": self.get_job(existing["id"]), "deduplicated": True, "refused": False, "reasons": []}
            count = self.store.scalar("SELECT COUNT(*) FROM jobs WHERE campaign_id=?", (cid,))
            if count >= int(camp["config"]["max_jobs"]):
                return {"job": None, "deduplicated": False, "refused": True,
                        "reasons": [f"max_jobs ceiling {camp['config']['max_jobs']} reached"]}
            job_id = new_id("job")
            now = self.store.now()
            seq = int(self.store.scalar("SELECT COALESCE(MAX(seq),0)+1 FROM jobs"))
            self.store.conn.execute(
                "INSERT INTO jobs(id,campaign_id,identity_key,stage,kind,target_type,target_ref,family,status,priority,"
                "max_attempts,payload,enqueued_by,seq,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,'queued',?,?,?,?,?,?,?)",
                (job_id, cid, identity, stage, kind, target_type, target_ref, row["family"], priority,
                 int(camp["config"]["max_attempts"]), dumps(payload or {}), actor, seq, now, now),
            )
            self._ledger(cid, "job", "enqueue", actor, job_id=job_id, stage=stage, kind=kind,
                         target_type=target_type, target_ref=target_ref, family=row["family"])
        return {"job": self.get_job(job_id), "deduplicated": False, "refused": False, "reasons": []}

    def enqueue_job(self, cid: str, *, stage: str, kind: str, target_type: str, target_ref: str, actor: str,
                    priority: int = 100, payload: dict | None = None) -> dict:
        self._require_operator(actor, "enqueue jobs")
        if stage == "deep":
            raise ValueError("deep jobs are created only by select_for_deep (operator-selected, justified, capped)")
        if stage == "fuzz_ready":
            raise ValueError("fuzz_ready jobs are created only by approve_escalation")
        expected = "image" if stage == "inventory" else "member"
        if target_type != expected:
            raise ValueError(f"{stage} jobs target {expected}s")
        return self._enqueue(cid, stage=stage, kind=kind, target_type=target_type, target_ref=target_ref,
                             actor=actor, priority=priority, payload=payload)

    def _bulk(self, cid: str, refs: list[str], **kw: Any) -> dict:
        out = {"enqueued": 0, "deduplicated": 0, "refused": 0, "reasons": [], "job_ids": []}
        for ref in refs:
            res = self.enqueue_job(cid, target_ref=ref, **kw)
            if res["refused"]:
                out["refused"] += 1
                out["reasons"].extend(r for r in res["reasons"] if r not in out["reasons"])
            elif res["deduplicated"]:
                out["deduplicated"] += 1
            else:
                out["enqueued"] += 1
                out["job_ids"].append(res["job"]["id"])
        return out

    def enqueue_image_jobs(self, cid: str, *, stage: str, kind: str, actor: str) -> dict:
        self._require_active(cid)
        refs = [r["id"] for r in self.store.all("SELECT id FROM images WHERE campaign_id=? ORDER BY ingest_seq", (cid,))]
        return self._bulk(cid, refs, stage=stage, kind=kind, target_type="image", actor=actor)

    def enqueue_member_jobs(self, cid: str, *, stage: str, kind: str, actor: str) -> dict:
        """One job per *unique* member SHA-256 — identical members are analysed once."""
        camp = self._require_active(cid)
        if _stage_index(stage) > _stage_index(camp["current_stage"]):
            raise ValueError(f"cannot enqueue {stage} work while campaign is at {camp['current_stage']}")
        refs = [r["sha256"] for r in self.store.all(
            "SELECT sha256 FROM members WHERE campaign_id=? ORDER BY created_at, sha256", (cid,))]
        return self._bulk(cid, refs, stage=stage, kind=kind, target_type="member", actor=actor)

    def cancel_job(self, cid: str, job_id: str, *, actor: str, reason: str) -> dict:
        self._require_operator(actor, "cancel jobs")
        job = self.get_job(job_id)
        if job["campaign_id"] != cid:
            raise ValueError("job does not belong to campaign")
        if job["status"] in {"succeeded", "cancelled"}:
            return job
        with self.store.tx():
            self.store.conn.execute(
                "UPDATE jobs SET status='cancelled', claim_token=NULL, lease_expires=NULL, last_error=?, updated_at=? WHERE id=?",
                (f"cancelled: {reason}", self.store.now(), job_id))
            self._ledger(cid, "job", "cancel", actor, job_id=job_id, reason=reason, from_status=job["status"])
        return self.get_job(job_id)

    # ------------------------------------------------------------------ claim
    def _reclaim_expired(self, cid: str) -> list[str]:
        now = self.store.now()
        ids = []
        for row in self.store.all(
                "SELECT id FROM jobs WHERE campaign_id=? AND status='claimed' AND lease_expires IS NOT NULL AND lease_expires < ?",
                (cid, now)):
            self._record_failure(cid, self.get_job(row["id"]), "lease_expired", "lease expired before submission",
                                 cost=0.0, actor=None)
            ids.append(row["id"])
        return ids

    def claim_job(self, cid: str, *, worker: str, stage: str | None = None) -> dict:
        self._require_kind(worker, CLAIMING_KINDS, "claim jobs")
        with self.store.tx():
            self._check_deadline(cid)
            self._reclaim_expired(cid)
            camp = self.get_campaign(cid)
            if camp["status"] != "active":
                return {"claimed": False, "job": None, "reason": f"campaign {camp['status']}: {camp['stop_reason'] or ''}".strip()}
            run_exhausted = self._exhausted(camp, "run")
            if run_exhausted:
                self._stop(cid, "budget_exhausted:run", actor=None, cancel_claimed=False, detail=run_exhausted)
                return {"claimed": False, "job": None, "reason": run_exhausted.rsplit(":", 1)[0]}
            now = self.store.now()
            sql = ("SELECT * FROM jobs WHERE campaign_id=? AND status='queued' AND not_before<=? ")
            args: list[Any] = [cid, now]
            if stage:
                sql += "AND stage=? "
                args.append(stage)
            sql += "ORDER BY priority, seq"
            current = _stage_index(camp["current_stage"])
            waiting: list[str] = []
            storage_paused: list[str] = []
            for row in self.store.all(sql, tuple(args)):
                job = dict(row)
                if _stage_index(job["stage"]) > current:
                    continue
                blocked = next((r for s in self._job_scopes(job)[1:] if (r := self._exhausted(camp, s))), None)
                if blocked:
                    self._budget_block(cid, job, blocked)
                    continue
                if self._wishlist_blockers(cid, job):  # pauses only work that depends on an outstanding blocker
                    waiting.append(job["id"])
                    continue
                if self._storage_claim_block(cid, job):  # disk pressure pauses only declared storage-heavy jobs
                    storage_paused.append(job["id"])
                    continue
                token = uuid.uuid4().hex
                lease = now + float(camp["config"]["lease_s"])
                self.store.conn.execute(
                    "UPDATE jobs SET status='claimed', attempts=attempts+1, claimed_by=?, claim_token=?, lease_expires=?, "
                    "updated_at=? WHERE id=?", (worker, token, lease, now, job["id"]))
                self._charge(cid, self._job_scopes(job), claims=1)
                self._ledger(cid, "job", "claim", worker, job_id=job["id"], attempt=job["attempts"] + 1, lease_expires=lease)
                return {"claimed": True, "job": self.get_job(job["id"]), "reason": ""}
            return {"claimed": False, "job": None, "reason": "no claimable jobs",
                    **({"wishlist_blocked": waiting} if waiting else {}),
                    **({"storage_paused": storage_paused} if storage_paused else {})}

    def _budget_block(self, cid: str, job: dict, reason: str) -> None:
        scope = reason.split(":", 1)[1].rsplit(":", 1)[0]
        self.store.conn.execute("UPDATE jobs SET status='budget_blocked', last_error=?, updated_at=? WHERE id=?",
                                (reason, self.store.now(), job["id"]))
        self._ledger(cid, "budget", "block", None, job_id=job["id"], scope=scope, reason=reason)
        self._open_pending(cid, "budget_decision", f"Budget exhausted for {scope}", identity_parts=(scope,),
                           scope=scope, description="raise_budget or resolve (cancels blocked jobs in scope)")

    # ------------------------------------------------------------------ packets / submit / fail
    def job_packet(self, cid: str, job_id: str) -> dict:
        """Bounded task packet handed to a worker adapter (provider neutral)."""
        camp = self.get_campaign(cid)
        job = self.get_job(job_id)
        if job["campaign_id"] != cid:  # never mix one campaign's budgets/capabilities with another's job
            raise ValueError("job does not belong to campaign")
        target: dict[str, Any] = {"type": job["target_type"], "ref": job["target_ref"], "family": job["family"]}
        if job["target_type"] == "member":
            target["member"] = self.get_member(cid, job["target_ref"])
            target["occurrences_sample"] = self.member_occurrences(cid, job["target_ref"])[:20]
        else:
            target["image"] = self.get_image(job["target_ref"])
        return {
            "protocol": "refall-lite.job.v1",
            "submit_schema": SUBMIT_SCHEMA,
            "campaign_id": cid,
            "job": {k: job[k] for k in ("id", "stage", "kind", "attempts", "max_attempts", "claim_token", "lease_expires", "payload")},
            "target": target,
            "budget_remaining": self._budget_remaining(camp, job),
            "required_outputs": ["summary", "evidence", "confidence", "limitations", "source_anchors|artifact_refs", "cost_units"],
            "rules": [
                "All model conclusions are provisional hypotheses until a deterministic replay or independent non-model check promotes them.",
                "Do not claim validation; requested tiers above hypothesis are ignored and recorded as a limitation.",
                "Every finding needs evidence plus source_anchors or artifact_refs; state limitations honestly.",
                "Stay inside the job target and budget; report cost_units consumed.",
            ],
            "methodology_bundle": camp["config"].get("methodology_bundle"),
            # provided capabilities to reuse + outstanding requests (incl. blockers) for this job's scope
            "capabilities": self._wishlist_packet(cid, job),
        }

    def _audit_refused_submit(self, cid: str, job: dict, reason: str) -> None:
        self._ledger(cid, "runtime-event", "submission_refused", job.get("claimed_by"), job_id=job["id"],
                     job_status=job["status"], reason=reason)

    def _check_claim(self, cid: str, job_id: str, token: str) -> tuple[dict | None, str]:
        job = self.get_job(job_id)
        if job["campaign_id"] != cid:
            return None, "job does not belong to campaign"
        if job["status"] != "claimed":
            self._audit_refused_submit(cid, job, f"job is {job['status']}, not claimed")
            return None, f"job is {job['status']}, not claimed; late or stale submission refused"
        if token != job["claim_token"]:
            self._audit_refused_submit(cid, job, "claim token mismatch")
            return None, "claim token mismatch; stale or foreign worker"
        return job, ""

    def submit_result(self, cid: str, job_id: str, claim_token: str, submission: dict | str) -> dict:
        with self.store.tx():
            self._check_deadline(cid)
            self._reclaim_expired(cid)
            job, err = self._check_claim(cid, job_id, claim_token)
            if not job:
                return {"accepted": False, "errors": [err], "finding_ids": [], "job": self.get_job(job_id)}
            payload, errors = parse_submission(redact(submission), defaults={
                "job_id": job_id, "campaign_id": cid, "produced_by": job["claimed_by"]})
            if payload is not None and payload.get("job_id") != job_id:
                errors.append("submission job_id does not match claimed job")
            if payload is not None and payload.get("type") == "failure" and not errors:
                out = self._record_failure(cid, job, str(payload.get("failure_class") or payload.get("status")),
                                           str(payload.get("summary") or ""), cost=self._cost(cid, payload),
                                           actor=job["claimed_by"])
                return {"accepted": False, "errors": ["worker reported failure"], "finding_ids": [], **out}
            candidates = []
            if payload is not None and not errors:
                for idx, raw in enumerate(payload.get("findings") or []):
                    cand = self._candidate_from_submission(cid, job, payload, raw)
                    reasons = self._candidate_reasons(cid, cand)
                    errors.extend(f"finding[{idx}]: {r}" for r in reasons)
                    candidates.append(cand)
            if errors:
                fclass = "missing_terminal_submit" if errors == ["missing refall-submit block"] else "malformed_terminal_submit"
                out = self._record_failure(cid, job, fclass, "; ".join(errors), cost=self._cost(cid, payload),
                                           actor=job["claimed_by"])
                return {"accepted": False, "errors": errors, "finding_ids": [], **out}
            assert payload is not None
            cost = self._cost(cid, payload)
            result = {k: payload.get(k) for k in ("summary", "status", "evidence", "source_anchors", "artifact_refs",
                                                  "confidence", "limitations", "produced_by", "worker")}
            # Optional domain evidence is persisted verbatim, never synthesized by the kernel.
            for key in ("pack_sha256", "method_usage", "dsr_analysis", "unknowns"):
                if key in payload:
                    result[key] = payload[key]
            now = self.store.now()
            self.store.conn.execute(
                "UPDATE jobs SET status='succeeded', claim_token=NULL, lease_expires=NULL, result=?, cost_used=cost_used+?, "
                "failure_class=NULL, updated_at=? WHERE id=?", (dumps(result), cost, now, job_id))
            self.store.conn.execute("UPDATE campaigns SET consecutive_failures=0, updated_at=? WHERE id=?", (now, cid))
            self._charge(cid, self._job_scopes(job), cost=cost)
            self._ledger(cid, "job", "succeed", job["claimed_by"], job_id=job_id, cost_units=cost,
                         summary=payload.get("summary"), result_sha256=sha256_text(canonical_json(result)))
            finding_ids = []
            for cand in candidates:
                rec = self._record_finding_locked(cid, job["claimed_by"], cand, job_id=job_id)
                finding_ids.append(rec["finding"]["id"])
            self._on_job_succeeded(cid, job, payload, finding_ids)
            self._post_charge_stop_check(cid)
        return {"accepted": True, "errors": [], "finding_ids": finding_ids, "job": self.get_job(job_id)}

    def _cost(self, cid: str, payload: dict | None) -> float:
        camp = self.get_campaign(cid)
        raw = (payload or {}).get("cost_units", camp["config"]["default_job_cost"])
        try:
            value = float(raw)
        except (TypeError, ValueError):
            value = float(camp["config"]["default_job_cost"])
        return max(0.0, value)

    def fail_job(self, cid: str, job_id: str, claim_token: str, *, status: str, error: str = "",
                 cost_units: float | None = None) -> dict:
        with self.store.tx():
            self._check_deadline(cid)
            self._reclaim_expired(cid)
            job, err = self._check_claim(cid, job_id, claim_token)
            if not job:
                return {"accepted": False, "errors": [err], "job": self.get_job(job_id), "outcome": None}
            error = redact(error)
            cost = self._cost(cid, {} if cost_units is None else {"cost_units": cost_units})
            out = self._record_failure(cid, job, status, error, cost=cost, actor=job["claimed_by"])
        return {"accepted": True, "errors": [], **out}

    def _record_failure(self, cid: str, job: dict, status: str, error: str, *, cost: float, actor: str | None) -> dict:
        """Retry ceiling + classification (adapted from REFALL runtime_invocation)."""
        cls = classify_failure(status)
        camp = self.get_campaign(cid)
        now = self.store.now()
        attempts, max_attempts = int(job["attempts"]), int(job["max_attempts"])
        if camp["status"] != "active":
            state = "cancelled"
        elif not cls["retryable"]:
            state = "blocked"
        elif attempts < max_attempts:
            state = "queued"
        else:
            state = "dead"
        not_before = now + float(camp["config"]["backoff_s"]) * attempts if state == "queued" else 0
        self.store.conn.execute(
            "UPDATE jobs SET status=?, claim_token=NULL, lease_expires=NULL, not_before=?, failure_class=?, last_error=?, "
            "cost_used=cost_used+?, updated_at=? WHERE id=?",
            (state, not_before, cls["failure_class"], error[:2000], cost, now, job["id"]))
        self.store.conn.execute(
            "UPDATE campaigns SET consecutive_failures=consecutive_failures+1, updated_at=? WHERE id=?", (now, cid))
        self._charge(cid, self._job_scopes(job), cost=cost)
        outcome = {"state": state, "failure_class": cls["failure_class"], "retryable": cls["retryable"] and state == "queued",
                   "attempt": attempts, "max_attempts": max_attempts, "next_action": cls["next_action"] if state == "queued" else "operator_attention"}
        self._ledger(cid, "job", "fail", actor, job_id=job["id"], cost_units=cost, error=error[:500], **outcome)
        if state in {"dead", "blocked"}:
            self._open_pending(cid, "operator_attention",
                               f"Job {job['id']} {state}: {cls['failure_class']}", identity_parts=(job["id"],),
                               source_job_id=job["id"], payload={"error": error[:500], "attempts": attempts})
        camp = self.get_campaign(cid)
        if camp["status"] == "active" and camp["consecutive_failures"] >= int(camp["config"]["max_consecutive_failures"]):
            self._stop(cid, "consecutive_failures", actor=None, cancel_claimed=False,
                       detail=f"{camp['consecutive_failures']} consecutive failures")
        self._post_charge_stop_check(cid)
        return {"job": self.get_job(job["id"]), "outcome": outcome}

    def _post_charge_stop_check(self, cid: str) -> None:
        """Stop when the run budget is spent and nothing is in flight (in-flight jobs may finish)."""
        camp = self.get_campaign(cid)
        if camp["status"] != "active":
            return
        exhausted = self._exhausted(camp, "run")
        in_flight = self.store.scalar("SELECT COUNT(*) FROM jobs WHERE campaign_id=? AND status='claimed'", (cid,))
        if exhausted and not in_flight:
            self._stop(cid, "budget_exhausted:run", actor=None, cancel_claimed=False, detail=exhausted)

    def _cascade_pending_resolution(self, cid: str, action: dict, actor: str) -> None:
        now = self.store.now()
        if action["kind"] == "operator_attention" and action.get("source_job_id"):
            job = self.get_job(action["source_job_id"])
            if job["status"] == "blocked":
                self.store.conn.execute("UPDATE jobs SET status='cancelled', updated_at=? WHERE id=?", (now, job["id"]))
                self._ledger(cid, "job", "cancel", actor, job_id=job["id"], reason="operator resolved blocked job")
        if action["kind"] == "budget_decision" and action.get("scope"):
            for row in self.store.all("SELECT * FROM jobs WHERE campaign_id=? AND status='budget_blocked'", (cid,)):
                if action["scope"] in self._job_scopes(dict(row)):
                    self.store.conn.execute("UPDATE jobs SET status='cancelled', updated_at=? WHERE id=?", (now, row["id"]))
                    self._ledger(cid, "job", "cancel", actor, job_id=row["id"], reason=f"budget decision for {action['scope']}")

    # ------------------------------------------------------------------ stage gates
    def stage_gate(self, cid: str) -> dict:
        camp = self.get_campaign(cid)
        stage = camp["current_stage"]
        reasons: list[str] = []
        if stage == STAGES[-1]:
            return {"stage": stage, "next": None, "passed": False, "reasons": ["already at final stage"]}
        nxt = STAGES[_stage_index(stage) + 1]
        unresolved = self.store.scalar(
            f"SELECT COUNT(*) FROM jobs WHERE campaign_id=? AND stage=? AND status IN ({','.join('?' * len(JOB_UNRESOLVED))})",
            (cid, stage, *sorted(JOB_UNRESOLVED)))
        if unresolved:
            reasons.append(f"active {stage} jobs: {unresolved}")
        if stage == "inventory":
            images = self.store.all("SELECT id,name FROM images WHERE campaign_id=?", (cid,))
            if not images:
                reasons.append("no images ingested")
            missing = [r["name"] for r in images if not self.store.scalar(
                "SELECT COUNT(*) FROM jobs WHERE campaign_id=? AND stage='inventory' AND target_ref=? "
                "AND status IN ('succeeded','dead','cancelled')", (cid, r["id"]))]
            if missing:
                reasons.append(f"images without terminal inventory: {', '.join(sorted(missing))}")
            if images and not self.store.scalar(
                    "SELECT COUNT(*) FROM jobs WHERE campaign_id=? AND stage='inventory' AND status='succeeded'", (cid,)):
                reasons.append("no inventory job succeeded")
        elif stage == "middle":
            families = [r["family"] for r in self.store.all("SELECT DISTINCT family FROM occurrences WHERE campaign_id=?", (cid,))]
            uncovered = [f for f in families if not self.store.scalar(
                "SELECT COUNT(*) FROM jobs j JOIN occurrences o ON o.campaign_id=j.campaign_id AND o.member_sha256=j.target_ref "
                "WHERE j.campaign_id=? AND j.stage='middle' AND j.status='succeeded' AND o.family=?", (cid, f))]
            if uncovered:
                reasons.append(f"families without middle-depth coverage: {', '.join(sorted(uncovered))}")
            total = self.store.scalar("SELECT COUNT(*) FROM members WHERE campaign_id=?", (cid,)) or 0
            done = self.store.scalar("SELECT COUNT(DISTINCT target_ref) FROM jobs WHERE campaign_id=? AND stage='middle' AND status='succeeded'", (cid,))
            minimum = float(camp["config"].get("middle_coverage_min") or 0)
            if total and done / total < minimum:
                reasons.append(f"middle coverage {done}/{total} below {minimum:.0%}")
            reasons.extend(self._lineage_stage_reasons(cid))
        elif stage == "deep":
            approved = self.store.scalar(
                "SELECT COUNT(*) FROM pending_actions WHERE campaign_id=? AND kind='fuzz_escalation' AND status='done'", (cid,))
            if not approved:
                reasons.append("no approved fuzz escalation")
        return {"stage": stage, "next": nxt, "passed": not reasons, "reasons": reasons}

    def advance_stage(self, cid: str, *, actor: str) -> dict:
        self._require_operator(actor, "advance stages")
        self._require_active(cid)
        with self.store.tx():
            gate = self.stage_gate(cid)
            self._ledger(cid, "stage-gate", "advance" if gate["passed"] else "refuse", actor, **gate)
            if gate["passed"]:
                self.store.conn.execute("UPDATE campaigns SET current_stage=?, updated_at=? WHERE id=?",
                                        (gate["next"], self.store.now(), cid))
                hashes = {f"image:{r['id']}": r["image_sha256"] for r in self.store.all(
                    "SELECT id,image_sha256 FROM images WHERE campaign_id=?", (cid,))}
                self.checkpoint(cid, stage=gate["stage"], key=f"stage-complete:{gate['stage']}", input_hashes=hashes, actor=actor)
                self._wishlist_on_stage(cid, actor)  # revisit deferred/declined capability decisions at stage transitions
        return {"advanced": gate["passed"], "stage": self.get_campaign(cid)["current_stage"], "reasons": gate["reasons"]}

    def select_for_deep(self, cid: str, member_sha256: str, *, actor: str, reason: str, kind: str = "deep-analysis") -> dict:
        """Selective deep work: operator-chosen, justified, after middle-depth success, capped."""
        self._require_operator(actor, "select members for deep analysis")
        camp = self._require_active(cid)
        if _stage_index(camp["current_stage"]) < _stage_index("deep"):
            raise ValueError(f"deep selection requires stage deep; campaign is at {camp['current_stage']}")
        reasons = []
        if not str(reason or "").strip():
            reasons.append("deep selection requires a reason")
        if not self.store.one("SELECT 1 FROM members WHERE campaign_id=? AND sha256=?", (cid, member_sha256)):
            reasons.append("unknown member")
        elif not self.store.scalar("SELECT COUNT(*) FROM jobs WHERE campaign_id=? AND stage='middle' AND target_ref=? AND status='succeeded'",
                                   (cid, member_sha256)):
            reasons.append("member has no succeeded middle-depth job")
        else:
            reasons.extend(self._lineage_deep_refusal(cid, member_sha256))
        existing = self.store.one("SELECT id FROM jobs WHERE campaign_id=? AND stage='deep' AND target_ref=? AND kind!='delta-analysis'",
                                  (cid, member_sha256))
        if existing and not reasons:
            return {"accepted": True, "deduplicated": True, "reasons": [], "job": self.get_job(existing["id"])}
        cap = camp["config"].get("max_deep_selections")
        if cap is not None and self.store.scalar("SELECT COUNT(*) FROM jobs WHERE campaign_id=? AND stage='deep' AND kind!='delta-analysis'",
                                                 (cid,)) >= int(cap):
            reasons.append(f"max_deep_selections {cap} reached")
        if reasons:
            self._ledger(cid, "stage-gate", "deep_select_refused", actor, member_sha256=member_sha256, reasons=reasons)
            return {"accepted": False, "deduplicated": False, "reasons": reasons, "job": None}
        res = self._enqueue(cid, stage="deep", kind=kind, target_type="member", target_ref=member_sha256,
                            actor=actor, payload={"reason": reason})
        return {"accepted": not res["refused"], "deduplicated": res["deduplicated"], "reasons": res["reasons"], "job": res["job"]}

    # ------------------------------------------------------------------ manifest / checkpoint / resume
    def put_manifest(self, cid: str, *, run_id: str, actor: str, **fields: Any) -> dict:
        camp = self.get_campaign(cid)
        manifest_id = stable_id("manifest", {"campaign_id": cid, "run_id": run_id})
        now = self.store.now()
        with self.store.tx():
            existing = self.store.one("SELECT payload,created_at FROM run_manifests WHERE id=?", (manifest_id,))
            record = loads(existing["payload"], {}) if existing else {}
            record.update({k: v for k, v in fields.items() if v is not None})
            record.update({
                "manifest_id": manifest_id, "campaign_id": cid, "run_id": run_id,
                "layer": "ArcticBase REFALL state layer (lite)",
                "config_hashes": {"campaign_config": sha256_text(canonical_json(camp["config"]))},
                "stage_status": {"current_stage": camp["current_stage"], "status": camp["status"]},
                "checkpoint_ids": [r["id"] for r in self.store.all("SELECT id FROM stage_checkpoints WHERE campaign_id=? ORDER BY seq", (cid,))],
                "updated_at": now,
            })
            record.setdefault("created_at", now)
            self.store.conn.execute(
                "INSERT INTO run_manifests(id,campaign_id,run_id,payload,created_at,updated_at) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at",
                (manifest_id, cid, run_id, dumps(record), existing["created_at"] if existing else now, now))
            self._ledger(cid, "manifest", "put", actor, manifest_id=manifest_id, run_id=run_id)
        return record

    def get_manifest(self, cid: str) -> dict | None:
        row = self.store.one("SELECT payload FROM run_manifests WHERE campaign_id=? ORDER BY updated_at DESC, rowid DESC LIMIT 1", (cid,))
        return loads(row["payload"], None) if row else None

    def checkpoint(self, cid: str, *, stage: str, key: str, input_hashes: dict[str, str], actor: str,
                   output_refs: list[str] | None = None, status: str = "completed") -> dict:
        _stage_index(stage)
        now = self.store.now()
        manifest = self.get_manifest(cid)
        with self.store.tx():
            existing = self.store.one("SELECT id,created_at FROM stage_checkpoints WHERE campaign_id=? AND checkpoint_key=?", (cid, key))
            ckpt_id = existing["id"] if existing else new_id("ckpt")
            seq = int(self.store.scalar("SELECT COALESCE(MAX(seq),0)+1 FROM stage_checkpoints"))
            self.store.conn.execute(
                "INSERT INTO stage_checkpoints(id,campaign_id,run_id,stage,checkpoint_key,status,input_hashes,output_refs,created_at,updated_at,seq) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(campaign_id,checkpoint_key) DO UPDATE SET status=excluded.status, "
                "input_hashes=excluded.input_hashes, output_refs=excluded.output_refs, updated_at=excluded.updated_at, seq=excluded.seq",
                (ckpt_id, cid, (manifest or {}).get("run_id"), stage, key, status, dumps(input_hashes),
                 dumps(output_refs or []), existing["created_at"] if existing else now, now, seq))
            self._ledger(cid, "checkpoint", "put", actor, checkpoint_id=ckpt_id, key=key, stage=stage, input_hashes=input_hashes)
        return {"id": ckpt_id, "key": key, "stage": stage, "input_hashes": input_hashes, "status": status}

    def list_checkpoints(self, cid: str) -> list[dict]:
        out = []
        for r in self.store.all("SELECT * FROM stage_checkpoints WHERE campaign_id=? ORDER BY seq", (cid,)):
            d = dict(r)
            d["input_hashes"] = loads(d["input_hashes"], {})
            d["output_refs"] = loads(d["output_refs"], [])
            out.append(d)
        return out

    def resume_preflight(self, cid: str, *, current_hashes: dict[str, str] | None = None) -> dict:
        """Read-only checkpoint hash check; no leases, pending actions or ledger writes."""
        self.get_campaign(cid)
        expected: dict[str, str] = {}
        for ck in self.list_checkpoints(cid):
            expected.update({str(k): str(v) for k, v in ck["input_hashes"].items()})
        return resume_preflight(expected, current_hashes)

    def resume(self, cid: str, *, actor: str, current_hashes: dict[str, str] | None = None) -> dict:
        """Restart entry point after a crash/reopen: reclaim leases, enforce deadline, check drift."""
        self._require_operator(actor, "resume campaigns")
        with self.store.tx():
            self._check_deadline(cid)
            reclaimed = self._reclaim_expired(cid) if self.get_campaign(cid)["status"] == "active" else []
            pre = self.resume_preflight(cid, current_hashes=current_hashes)
            if not pre["accepted"]:
                self._open_pending(cid, "resume_drift_decision", "Resume input hashes drifted",
                                   identity_parts=(sha256_text(canonical_json(pre["changes"])),),
                                   payload={"changes": pre["changes"]})
            self._ledger(cid, "runtime-event", "resume", actor, reclaimed=reclaimed, preflight=pre["status"])
        return {"campaign": self.get_campaign(cid), "manifest": self.get_manifest(cid), "preflight": pre,
                "reclaimed": reclaimed, "status": self.status(cid)}

    # ------------------------------------------------------------------ status
    def status(self, cid: str) -> dict:
        camp = self.get_campaign(cid)
        jobs: dict[str, int] = {}
        by_stage: dict[str, dict[str, int]] = {}
        for r in self.store.all("SELECT stage,status,COUNT(*) n FROM jobs WHERE campaign_id=? GROUP BY stage,status", (cid,)):
            jobs[r["status"]] = jobs.get(r["status"], 0) + r["n"]
            by_stage.setdefault(r["stage"], {})[r["status"]] = r["n"]
        tiers = {r["tier"]: r["n"] for r in self.store.all("SELECT tier,COUNT(*) n FROM findings WHERE campaign_id=? GROUP BY tier", (cid,))}
        return {
            "campaign": {k: camp[k] for k in ("id", "name", "status", "current_stage", "stop_reason", "consecutive_failures")},
            "images": self.store.scalar("SELECT COUNT(*) FROM images WHERE campaign_id=?", (cid,)),
            "families": [r["family"] for r in self.store.all("SELECT DISTINCT family FROM images WHERE campaign_id=? ORDER BY family", (cid,))],
            "unique_members": self.store.scalar("SELECT COUNT(*) FROM members WHERE campaign_id=?", (cid,)),
            "member_occurrences": self.store.scalar("SELECT COUNT(*) FROM occurrences WHERE campaign_id=?", (cid,)),
            "jobs": jobs,
            "jobs_by_stage": by_stage,
            "findings": {t: tiers.get(t, 0) for t in [*TIERS, "rejected", "duplicate", "known_cve"]},
            "pending_open": len(self.list_pending_actions(cid)),
            "wishlist": self._wishlist_status(cid),
            "storage": self._storage_status(cid),
            "budgets": self.budget_usage(cid),
            "stage_gate": self.stage_gate(cid) if camp["status"] == "active" else None,
            "operator_kinds": sorted(OPERATOR_KINDS),
        }
