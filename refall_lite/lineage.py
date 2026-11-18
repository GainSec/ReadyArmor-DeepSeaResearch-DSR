"""Cross-firmware code lineage and knowledge reuse (ArcticBase REFALL Lite, schema v2).

Tier 0 (exact SHA-256 content objects) is the baseline member table. This module
adds code units, versioned fingerprint observations from *external* analyzers,
auditable similarity edges, code families (lineage clusters), representatives,
bounded delta jobs, analysis/delta receipts and reuse records.

Equivalence rules (enforced by ``evaluate_pair``; policy is per campaign):
- metadata signals (language, ISA, compiler, toolchain, package name, file type,
  SONAME) are candidate-generation only and never count toward equivalence;
- observations from model/supervisor actors never qualify (provisional);
- a policy pass needs >= ``min_signal_kinds`` qualifying signal kinds drawn from
  >= ``min_tiers`` distinct tiers, *and* (by default) one exact tier-1/2 anchor
  (normalized digest, build id, package@version, version string). One fuzzy
  score — however high — never passes on its own;
- every derived decision carries method, score, confidence, evidence and the
  fingerprint ``algorithm_version``; changing that version stales all derived
  similarity/reuse so it can no longer skip work.
"""
from __future__ import annotations

import copy
from typing import Any

from ._base import Base
from .arcticbase.contracts import (
    INDEPENDENT_KINDS,
    OPERATOR_KINDS,
    STAGES,
    canonical_json,
    normalize_sha256,
    receipt_has_material,
    sha256_text,
    stable_id,
    string_list,
)
from .arcticbase.store import dumps, loads, new_id

COMPARATOR = "lite-multisignal-v1"
DELTA_KIND = "delta-analysis"

# kind -> (tier, mode). mode: exact | set | metadata | scoped
SIGNALS: dict[str, tuple[int | None, str]] = {
    "normalized_digest": (1, "exact"),
    "build_id": (2, "exact"),
    "package_version": (2, "exact"),
    "version_string": (2, "exact"),
    "source_paths": (2, "set"),
    "symbol_set": (2, "set"),
    "import_set": (2, "set"),
    "export_set": (2, "set"),
    "function_hashes": (3, "set"),
    "cfg_features": (3, "set"),
    "strings_constants": (3, "set"),
    # tier 4: deterministic behavioral evidence (e.g. digest of replayed protocol I/O traces)
    "behavior_digest": (4, "exact"),
    # a role *label* (web_handler, updater, ...) is a capability description, not equivalence evidence;
    # it is used for exposure-aware prioritisation and representative choice only.
    "behavioral_role": (None, "metadata"),
    "language": (None, "metadata"),
    "isa": (None, "metadata"),
    "compiler": (None, "metadata"),
    "toolchain": (None, "metadata"),
    "package_name": (None, "metadata"),
    "file_type": (None, "metadata"),
    "soname": (None, "metadata"),
    "artifact_class": (None, "metadata"),
    "scoped_digest": (None, "scoped"),
}
MAX_SET_ITEMS = 100_000

LINEAGE_DEFAULTS: dict[str, Any] = {
    "algorithm_version": "lite-fp-v1",
    "min_signal_kinds": 2,
    "min_tiers": 2,
    "fuzzy_min_score": 0.85,
    "require_exact_anchor": True,
    "auto_approve": False,
    "max_candidate_pairs": 2000,
    "max_delta_jobs": 200,
    "max_delta_items": 50,
    "require_before_deep": None,  # None = required once fingerprints exist
    "exposed_roles": ["web_handler", "auth_service", "updater", "network_daemon", "parser", "remote_management"],
}


def merge_lineage_config(raw: dict | None) -> dict:
    cfg = copy.deepcopy(LINEAGE_DEFAULTS)
    cfg.update({k: v for k, v in (raw or {}).items() if k in LINEAGE_DEFAULTS})
    return cfg


def _normalize_value(kind: str, mode: str, value: Any) -> Any:
    if mode == "set":
        if not isinstance(value, list) or not value:
            raise ValueError(f"{kind} observation value must be a non-empty list")
        items = sorted({str(v).strip() for v in value if str(v).strip()})
        if len(items) > MAX_SET_ITEMS:
            raise ValueError(f"{kind} set exceeds {MAX_SET_ITEMS} items")
        return items
    if mode == "scoped":
        if not isinstance(value, dict) or not str(value.get("scope") or "").strip():
            raise ValueError("scoped_digest value must be {scope, digest}")
        digest = normalize_sha256(value.get("digest"))
        if not digest:
            raise ValueError("scoped_digest digest must be sha256 hex")
        return {"scope": str(value["scope"]).strip(), "digest": digest}
    if value in (None, "", [], {}):
        raise ValueError(f"{kind} observation value is empty")
    return value if not isinstance(value, str) else value.strip()


def evaluate_pair(obs_a: list[dict], obs_b: list[dict], policy: dict) -> dict:
    """Deterministic multi-signal comparison of two code units' observations."""
    def group(rows):
        out: dict[str, list[dict]] = {}
        for r in rows:
            out.setdefault(r["kind"], []).append(r)
        return out

    ga, gb = group(obs_a), group(obs_b)
    qualifying, below, metadata, non_qualifying = [], [], [], []
    for kind in sorted(set(ga) & set(gb)):
        tier, mode = SIGNALS[kind]
        if mode == "scoped":
            continue
        best: dict | None = None
        for ra in ga[kind]:
            for rb in gb[kind]:
                if mode in {"exact", "metadata"}:
                    if ra["value_digest"] != rb["value_digest"]:
                        continue
                    score = 1.0
                else:
                    if ra["analyzer"] != rb["analyzer"]:
                        continue  # fuzzy features are only comparable within one analyzer
                    sa, sb = set(loads(ra["value"], [])), set(loads(rb["value"], []))
                    score = round(len(sa & sb) / len(sa | sb), 6) if sa | sb else 0.0
                    if score == 0:
                        continue
                cand = {"kind": kind, "tier": tier, "mode": mode, "score": score,
                        "qualifies": bool(ra["qualifies"] and rb["qualifies"]),
                        "analyzer": ra["analyzer"], "observation_ids": sorted([ra["id"], rb["id"]])}
                key = (cand["qualifies"], score)
                if best is None or key > (best["qualifies"], best["score"]):
                    best = cand
        if best is None:
            continue
        if mode == "metadata":
            metadata.append(best)
        elif not best["qualifies"]:
            non_qualifying.append(best)
        elif mode == "set" and best["score"] < float(policy["fuzzy_min_score"]):
            below.append(best)
        else:
            qualifying.append(best)
    kinds = {s["kind"] for s in qualifying}
    tiers = {s["tier"] for s in qualifying}
    anchor = any(s["mode"] == "exact" and (s["tier"] or 9) <= 2 for s in qualifying)
    structural = bool(qualifying or below or non_qualifying)
    reasons: list[str] = []
    if not structural:
        reasons.append("metadata-only signals (language/ISA/compiler/package name) never imply equivalence"
                       if metadata else "no shared signals")
    if len(kinds) < int(policy["min_signal_kinds"]):
        reasons.append(f"{len(kinds)} qualifying signal kinds < min_signal_kinds {policy['min_signal_kinds']}")
    if len(tiers) < int(policy["min_tiers"]):
        reasons.append(f"{len(tiers)} distinct evidence tiers < min_tiers {policy['min_tiers']}")
    if policy.get("require_exact_anchor") and not anchor:
        reasons.append("no exact tier-1/2 anchor (normalized digest, build id, package@version, version string)")
    passed = structural and not reasons
    if non_qualifying:
        reasons.append("note: model/supervisor-sourced observations are candidate-generation only")
    if qualifying:
        score = round(sum(s["score"] for s in qualifying) / len(qualifying), 6)
    else:
        score = round(max([s["score"] for s in below + non_qualifying] or [0.0]), 6)
    confidence = "high" if passed and len(kinds) >= 3 else "medium" if passed else "low"
    return {"policy_passed": passed, "score": score, "confidence": confidence, "reasons": reasons,
            "structural": bool(structural),
            "evidence": {"qualifying": qualifying, "below_threshold": below, "non_qualifying": non_qualifying,
                         "metadata_only": metadata, "policy": {k: policy[k] for k in
                         ("min_signal_kinds", "min_tiers", "fuzzy_min_score", "require_exact_anchor")}}}


class LineageMixin(Base):
    # ------------------------------------------------------------------ config
    def lineage_config(self, cid: str) -> dict:
        return merge_lineage_config(self.get_campaign(cid)["config"].get("lineage"))

    def _alg(self, cid: str) -> str:
        return self.lineage_config(cid)["algorithm_version"]

    # ------------------------------------------------------------------ code units
    def register_code_unit(self, cid: str, content_sha256: str, *, actor: str, granularity: str = "file",
                           name: str = "", parent_unit_id: str | None = None) -> dict:
        self.actor(actor)
        sha = normalize_sha256(content_sha256)
        if not self.store.one("SELECT 1 FROM members WHERE campaign_id=? AND sha256=?", (cid, sha)):
            raise ValueError("code unit content must be an ingested content object (member sha256)")
        if granularity not in {"file", "function", "module"}:
            raise ValueError("granularity must be file, function, or module")
        if granularity != "file" and not name:
            raise ValueError("function/module code units need a name")
        uid = stable_id("cu", {"campaign_id": cid, "sha256": sha, "granularity": granularity, "name": name})
        with self.store.tx():
            cur = self.store.conn.execute(
                "INSERT OR IGNORE INTO code_units(id,campaign_id,content_sha256,granularity,name,parent_unit_id,created_by,created_at) "
                "VALUES(?,?,?,?,?,?,?,?)", (uid, cid, sha, granularity, name, parent_unit_id, actor, self.store.now()))
            if cur.rowcount:
                self._ledger(cid, "lineage", "code_unit", actor, unit_id=uid, content_sha256=sha, granularity=granularity, name=name)
        return self.get_code_unit(uid)

    def get_code_unit(self, unit_id: str) -> dict:
        row = self.store.one("SELECT * FROM code_units WHERE id=?", (unit_id,))
        if not row:
            raise KeyError(f"unknown code unit {unit_id}")
        return dict(row)

    def list_code_units(self, cid: str, content_sha256: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM code_units WHERE campaign_id=?", [cid]
        if content_sha256:
            sql += " AND content_sha256=?"
            args.append(normalize_sha256(content_sha256))
        return [dict(r) for r in self.store.all(sql + " ORDER BY created_at, id", tuple(args))]

    def _file_unit(self, cid: str, content_sha256: str) -> str | None:
        return self.store.scalar("SELECT id FROM code_units WHERE campaign_id=? AND content_sha256=? AND granularity='file'",
                                 (cid, content_sha256))

    # ------------------------------------------------------------------ observations
    def ingest_fingerprints(self, cid: str, *, actor: str, observations: list[dict], content_sha256: str | None = None,
                            unit_id: str | None = None, granularity: str = "file", name: str = "") -> dict:
        actor_row = self.actor(actor)
        camp = self.get_campaign(cid)
        if camp["status"] == "closed":
            raise ValueError("campaign is closed")
        alg = self._alg(cid)
        with self.store.tx():
            if unit_id:
                unit = self.get_code_unit(unit_id)
                if unit["campaign_id"] != cid:
                    raise ValueError("code unit belongs to another campaign")
            else:
                if not content_sha256:
                    raise ValueError("content_sha256 or unit_id required")
                unit = self.register_code_unit(cid, content_sha256, actor=actor, granularity=granularity, name=name)
            rows = []
            for o in observations:
                kind = str(o.get("kind") or "")
                if kind not in SIGNALS:
                    raise ValueError(f"unknown signal kind {kind!r}; registered kinds: {sorted(SIGNALS)}")
                version = str(o.get("algorithm_version") or alg)
                if version != alg:
                    raise ValueError(f"observation algorithm_version {version!r} != campaign fingerprint algorithm {alg!r}")
                if not o.get("analyzer") or not o.get("analyzer_version"):
                    raise ValueError("observation requires analyzer and analyzer_version")
                tier, mode = SIGNALS[kind]
                value = _normalize_value(kind, mode, o.get("value"))
                rows.append((kind, tier, mode, value, o))
            accepted = 0
            for kind, tier, mode, value, o in rows:
                vtext = canonical_json(value)
                digest = sha256_text(vtext)
                oid = stable_id("obs", {"unit": unit["id"], "kind": kind, "analyzer": o["analyzer"], "alg": alg, "digest": digest})
                cur = self.store.conn.execute(
                    "INSERT OR IGNORE INTO fingerprint_observations(id,campaign_id,code_unit_id,kind,tier,mode,value,value_digest,"
                    "analyzer,analyzer_version,algorithm_version,source_actor,source_kind,qualifies,confidence,evidence,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (oid, cid, unit["id"], kind, tier, mode, vtext, digest, str(o["analyzer"]), str(o["analyzer_version"]), alg,
                     actor, actor_row["kind"], int(actor_row["kind"] in INDEPENDENT_KINDS), o.get("confidence"),
                     dumps(o.get("evidence") or {}), self.store.now()))
                accepted += cur.rowcount
            self._ledger(cid, "lineage", "fingerprints", actor, unit_id=unit["id"], accepted=accepted,
                         duplicates=len(rows) - accepted, algorithm_version=alg, source_kind=actor_row["kind"])
        return {"unit_id": unit["id"], "accepted": accepted, "duplicates": len(rows) - accepted, "algorithm_version": alg}

    def unit_observations(self, unit_id: str, *, current_only: bool = True) -> list[dict]:
        unit = self.get_code_unit(unit_id)
        sql, args = "SELECT * FROM fingerprint_observations WHERE code_unit_id=?", [unit_id]
        if current_only:
            sql += " AND algorithm_version=?"
            args.append(self._alg(unit["campaign_id"]))
        out = []
        for r in self.store.all(sql + " ORDER BY kind, analyzer, id", tuple(args)):
            d = dict(r)
            d["value"] = loads(d["value"], d["value"])
            d["evidence"] = loads(d["evidence"], {})
            out.append(d)
        return out

    def _raw_obs(self, cid: str, alg: str) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for r in self.store.all("SELECT * FROM fingerprint_observations WHERE campaign_id=? AND algorithm_version=? ORDER BY id", (cid, alg)):
            out.setdefault(r["code_unit_id"], []).append(dict(r))
        return out

    def _obs_digest(self, cid: str, alg: str) -> str:
        ids = [r["id"] for r in self.store.all(
            "SELECT id FROM fingerprint_observations WHERE campaign_id=? AND algorithm_version=? ORDER BY id", (cid, alg))]
        return sha256_text(canonical_json(ids))

    # ------------------------------------------------------------------ edges
    def _edge(self, row: Any) -> dict:
        d = dict(row)
        d["evidence"] = loads(d["evidence"], {})
        d["decision"] = loads(d["decision"], None)
        d["policy_passed"] = bool(d["policy_passed"])
        d["override"] = bool(d["override"])
        return d

    def get_edge(self, edge_id: str) -> dict:
        row = self.store.one("SELECT * FROM similarity_edges WHERE id=?", (edge_id,))
        if not row:
            raise KeyError(f"unknown edge {edge_id}")
        return self._edge(row)

    def list_similarity_edges(self, cid: str, *, unit_id: str | None = None, status: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM similarity_edges WHERE campaign_id=?", [cid]
        if unit_id:
            sql += " AND (unit_a=? OR unit_b=?)"
            args += [unit_id, unit_id]
        if status:
            sql += " AND status=?"
            args.append(status)
        return [self._edge(r) for r in self.store.all(sql + " ORDER BY unit_a, unit_b, id", tuple(args))]

    def _store_edge(self, cid: str, a: str, b: str, ev: dict, actor: str, policy: dict, alg: str) -> tuple[dict, str]:
        a, b = sorted([a, b])
        eid = stable_id("edge", {"campaign_id": cid, "a": a, "b": b, "method": COMPARATOR, "alg": alg})
        existing = self.store.one("SELECT * FROM similarity_edges WHERE id=?", (eid,))
        now = self.store.now()
        status = "approved" if (ev["policy_passed"] and policy.get("auto_approve")) else "candidate"
        if existing:
            if existing["status"] == "candidate" and canonical_json(loads(existing["evidence"], {})) != canonical_json(ev["evidence"]):
                status = "approved" if (ev["policy_passed"] and policy.get("auto_approve")) else "candidate"
                self.store.conn.execute(
                    "UPDATE similarity_edges SET score=?, confidence=?, policy_passed=?, evidence=?, status=?, "
                    "decided_by=?, updated_at=? WHERE id=?",
                    (ev["score"], ev["confidence"], int(ev["policy_passed"]), dumps(ev["evidence"]), status,
                     f"policy:{COMPARATOR}" if status == "approved" else None, now, eid))
                self._ledger(cid, "lineage", "edge_reevaluated", actor, edge_id=eid, score=ev["score"],
                             policy_passed=ev["policy_passed"], status=status)
                return self.get_edge(eid), "updated"
            return self._edge(existing), "existing"
        self.store.conn.execute(
            "INSERT INTO similarity_edges(id,campaign_id,unit_a,unit_b,method,algorithm_version,score,confidence,policy_passed,"
            "evidence,status,decided_by,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (eid, cid, a, b, COMPARATOR, alg, ev["score"], ev["confidence"], int(ev["policy_passed"]), dumps(ev["evidence"]),
             status, f"policy:{COMPARATOR}" if status == "approved" else None, actor, now, now))
        self._ledger(cid, "lineage", "edge", actor, edge_id=eid, unit_a=a, unit_b=b, method=COMPARATOR, algorithm_version=alg,
                     score=ev["score"], confidence=ev["confidence"], policy_passed=ev["policy_passed"], status=status,
                     reasons=ev["reasons"], qualifying=[s["kind"] for s in ev["evidence"]["qualifying"]])
        return self.get_edge(eid), "created"

    def compare_units(self, cid: str, unit_a: str, unit_b: str, *, actor: str) -> dict:
        self._require_operator(actor, "compare code units")
        alg, policy = self._alg(cid), self.lineage_config(cid)
        ua, ub = self.get_code_unit(unit_a), self.get_code_unit(unit_b)
        if ua["content_sha256"] == ub["content_sha256"] and ua["granularity"] == ub["granularity"] == "file":
            return {"edge": None, "evaluation": {"policy_passed": True, "reasons": ["tier 0: identical content object"], "tier": 0}}
        obs = self._raw_obs(cid, alg)
        ev = evaluate_pair(obs.get(unit_a, []), obs.get(unit_b, []), policy)
        with self.store.tx():
            if not ev["structural"]:
                self._ledger(cid, "lineage", "candidate_rejected", actor, unit_a=unit_a, unit_b=unit_b, reasons=ev["reasons"])
                return {"edge": None, "evaluation": ev}
            edge, _ = self._store_edge(cid, unit_a, unit_b, ev, actor, policy, alg)
        return {"edge": edge, "evaluation": ev}

    def _decide_edge(self, cid: str, edge_id: str, *, actor: str, approve: bool, receipt_type: str | None, receipt: dict | None) -> dict:
        act = self._require_operator(actor, "decide similarity edges")
        edge = self.get_edge(edge_id)
        reasons = []
        if edge["campaign_id"] != cid:
            reasons.append("edge not in campaign")
        if edge["status"] in {"stale", "rejected"} or (approve and edge["status"] == "approved"):
            reasons.append(f"edge is {edge['status']}")
        if edge["algorithm_version"] != self._alg(cid):
            reasons.append("edge algorithm_version is not current")
        override = False
        if approve and not edge["policy_passed"]:
            if act["kind"] != "human" or receipt_type != "human_lineage_review" or not receipt_has_material(receipt):
                reasons.append("edge below lineage policy threshold: only a human with a human_lineage_review receipt may override")
            else:
                override = True
        if not approve and (not receipt_type or not receipt_has_material(receipt)):
            reasons.append("rejecting an edge requires receipt_type and receipt evidence")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "lineage", "edge_decision_refused", actor, edge_id=edge_id, approve=approve, reasons=reasons)
                return {"accepted": False, "reasons": reasons, "edge": edge}
            status = "approved" if approve else "rejected"
            self.store.conn.execute(
                "UPDATE similarity_edges SET status=?, override=?, decided_by=?, decision=?, updated_at=? WHERE id=?",
                (status, int(override), actor, dumps({"receipt_type": receipt_type, "receipt": receipt or {}}), self.store.now(), edge_id))
            self._ledger(cid, "lineage", f"edge_{status}", actor, edge_id=edge_id, override=override, receipt_type=receipt_type)
        return {"accepted": True, "reasons": [], "edge": self.get_edge(edge_id)}

    def approve_edge(self, cid: str, edge_id: str, *, actor: str, receipt_type: str | None = None, receipt: dict | None = None) -> dict:
        return self._decide_edge(cid, edge_id, actor=actor, approve=True, receipt_type=receipt_type, receipt=receipt)

    def reject_edge(self, cid: str, edge_id: str, *, actor: str, receipt_type: str | None, receipt: dict | None) -> dict:
        return self._decide_edge(cid, edge_id, actor=actor, approve=False, receipt_type=receipt_type, receipt=receipt)

    def _usable_edge(self, e: dict) -> bool:
        return e["status"] == "approved" or (e["status"] == "candidate" and e["policy_passed"])

    # ------------------------------------------------------------------ families
    def _family(self, row: Any) -> dict:
        d = dict(row)
        d["policy"] = loads(d["policy"], {})
        d["decision"] = loads(d["decision"], None)
        d["representative_rationale"] = loads(d["representative_rationale"], None)
        d["members"] = [
            {**dict(m), "via_edges": loads(m["via_edges"], [])}
            for m in self.store.all("SELECT * FROM code_family_members WHERE family_id=? ORDER BY code_unit_id", (d["id"],))
        ]
        contents = [self.get_code_unit(m["code_unit_id"])["content_sha256"] for m in d["members"] if m["status"] == "approved"]
        fams = set()
        for c in contents:
            fams |= {r["family"] for r in self.store.all("SELECT DISTINCT family FROM occurrences WHERE campaign_id=? AND member_sha256=?",
                                                          (d["campaign_id"], c))}
        d["product_families"] = sorted(fams)
        return d

    def get_family(self, family_id: str) -> dict:
        row = self.store.one("SELECT * FROM code_families WHERE id=?", (family_id,))
        if not row:
            raise KeyError(f"unknown code family {family_id}")
        return self._family(row)

    def list_families(self, cid: str, status: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM code_families WHERE campaign_id=?", [cid]
        if status:
            sql += " AND status=?"
            args.append(status)
        return [self._family(r) for r in self.store.all(sql + " ORDER BY created_at, id", tuple(args))]

    def family_of(self, cid: str, unit_id: str | None) -> dict | None:
        """Approved, current (non-stale) family in which ``unit_id`` is an approved member."""
        if not unit_id:
            return None
        row = self.store.one(
            "SELECT f.* FROM code_families f JOIN code_family_members m ON m.family_id=f.id "
            "WHERE f.campaign_id=? AND m.code_unit_id=? AND m.status='approved' AND f.status='approved' AND f.algorithm_version=?",
            (cid, unit_id, self._alg(cid)))
        return self._family(row) if row else None

    def _connected(self, units: list[str], edges: list[dict]) -> tuple[bool, list[str]]:
        adj: dict[str, set[str]] = {u: set() for u in units}
        used = []
        for e in edges:
            if e["unit_a"] in adj and e["unit_b"] in adj:
                adj[e["unit_a"]].add(e["unit_b"])
                adj[e["unit_b"]].add(e["unit_a"])
                used.append(e["id"])
        seen, stack = set(), [units[0]]
        while stack:
            u = stack.pop()
            if u not in seen:
                seen.add(u)
                stack.extend(adj[u] - seen)
        return seen == set(units), sorted(used)

    def _create_family(self, cid: str, units: list[str], edge_ids: list[str], actor: str, *, approved: bool, name: str | None) -> tuple[str, bool]:
        alg, policy = self._alg(cid), self.lineage_config(cid)
        identity = sha256_text(canonical_json({"alg": alg, "units": sorted(units)}))
        fid = stable_id("fam", {"campaign_id": cid, "identity": identity})
        now = self.store.now()
        status = "approved" if approved else "proposed"
        cur = self.store.conn.execute(
            "INSERT OR IGNORE INTO code_families(id,campaign_id,identity_key,name,status,algorithm_version,policy,created_by,"
            "decided_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (fid, cid, identity, name, status, alg, dumps(policy), actor, f"policy:{COMPARATOR}" if approved else None, now, now))
        if not cur.rowcount:
            return fid, False
        for u in sorted(units):
            self._add_member(cid, fid, u, edge_ids, actor, status)
        self._ledger(cid, "lineage", "family_created", actor, family_id=fid, status=status, units=sorted(units),
                     edges=edge_ids, algorithm_version=alg, method=COMPARATOR)
        if not approved:
            self._open_pending(cid, "lineage_review", f"Review proposed code family {fid}", identity_parts=(fid,),
                               requested_by=actor, payload={"family_id": fid, "edges": edge_ids})
        return fid, True

    def _add_member(self, cid: str, fid: str, unit: str, edge_ids: list[str], actor: str, status: str) -> bool:
        now = self.store.now()
        cur = self.store.conn.execute(
            "INSERT OR IGNORE INTO code_family_members(family_id,code_unit_id,campaign_id,status,equivalence_tier,via_edges,added_by,"
            "created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (fid, unit, cid, status, self._member_tier(unit, edge_ids), dumps(edge_ids), actor, now, now))
        return bool(cur.rowcount)

    def _member_tier(self, unit: str, edge_ids: list[str]) -> int | None:
        tiers = []
        for eid in edge_ids:
            e = self.get_edge(eid)
            if unit in (e["unit_a"], e["unit_b"]):
                tiers += [s["tier"] for s in e["evidence"].get("qualifying", []) if s.get("tier")]
        return min(tiers) if tiers else None

    def propose_cluster(self, cid: str, unit_ids: list[str], *, actor: str, name: str | None = None) -> dict:
        self._require_operator(actor, "propose code families")
        units = sorted(set(unit_ids))
        reasons = []
        if len(units) < 2:
            reasons.append("a code family needs at least two code units")
        edges = [e for e in self.list_similarity_edges(cid) if self._usable_edge(e) and e["algorithm_version"] == self._alg(cid)]
        ok, used = self._connected(units, edges) if len(units) >= 2 else (False, [])
        if len(units) >= 2 and not ok:
            reasons.append("units are not connected by policy-passing or approved similarity edges")
        for u in units:
            if self.store.one("SELECT 1 FROM code_family_members m JOIN code_families f ON f.id=m.family_id WHERE m.code_unit_id=? "
                              "AND f.status IN ('approved','proposed') AND m.status IN ('approved','proposed')", (u,)):
                reasons.append(f"unit {u} already in an active family")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "lineage", "family_refused", actor, units=units, reasons=reasons)
                return {"accepted": False, "reasons": reasons, "family": None}
            fid, _ = self._create_family(cid, units, used, actor, approved=False, name=name)
        return {"accepted": True, "reasons": [], "family": self.get_family(fid)}

    def approve_cluster(self, cid: str, family_id: str, *, actor: str, receipt_type: str | None = None,
                        receipt: dict | None = None) -> dict:
        act = self._require_operator(actor, "approve code families")
        fam = self.get_family(family_id)
        reasons = []
        if fam["campaign_id"] != cid:
            reasons.append("family not in campaign")
        if fam["status"] in {"rejected", "stale"}:
            reasons.append(f"family is {fam['status']}")
        if fam["algorithm_version"] != self._alg(cid):
            reasons.append("family algorithm_version is not current")
        proposed = [m for m in fam["members"] if m["status"] == "proposed"]
        if fam["status"] == "approved" and not proposed:
            reasons.append("nothing proposed to approve")
        edge_ids = sorted({e for m in proposed for e in m["via_edges"]})
        for eid in edge_ids:
            e = self.get_edge(eid)
            if e["status"] in {"rejected", "stale"}:
                reasons.append(f"edge {eid} is {e['status']}")
            elif not e["policy_passed"] and e["status"] != "approved":
                reasons.append(f"edge {eid} below policy threshold; approve it explicitly (human override) first")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "lineage", "family_approval_refused", actor, family_id=family_id, reasons=reasons)
                return {"accepted": False, "reasons": reasons, "family": fam}
            now = self.store.now()
            for eid in edge_ids:
                self.store.conn.execute("UPDATE similarity_edges SET status='approved', decided_by=?, updated_at=? "
                                        "WHERE id=? AND status='candidate'", (actor, now, eid))
            self.store.conn.execute("UPDATE code_family_members SET status='approved', updated_at=? WHERE family_id=? AND status='proposed'",
                                    (now, family_id))
            self.store.conn.execute("UPDATE code_families SET status='approved', decided_by=?, decision=?, updated_at=? WHERE id=?",
                                    (actor, dumps({"receipt_type": receipt_type, "receipt": receipt or {}, "edges": edge_ids}), now, family_id))
            self._ledger(cid, "lineage", "family_approved", actor, family_id=family_id, edges=edge_ids,
                         members=[m["code_unit_id"] for m in proposed], actor_kind=act["kind"])
            self._close_review(cid, family_id, actor, "approved", edge_ids)
            if not self.get_family(family_id)["representative_unit_id"]:
                self._auto_representative(cid, family_id, actor)
        return {"accepted": True, "reasons": [], "family": self.get_family(family_id)}

    def reject_cluster(self, cid: str, family_id: str, *, actor: str, receipt_type: str | None, receipt: dict | None) -> dict:
        self._require_operator(actor, "reject code families")
        fam = self.get_family(family_id)
        reasons = []
        if not receipt_type or not receipt_has_material(receipt):
            reasons.append("rejecting a family requires receipt_type and receipt evidence")
        if fam["status"] in {"rejected", "stale"}:
            reasons.append(f"family is {fam['status']}")
        with self.store.tx():
            if reasons:
                return {"accepted": False, "reasons": reasons, "family": fam}
            now = self.store.now()
            self.store.conn.execute("UPDATE code_family_members SET status='rejected', updated_at=? WHERE family_id=? AND status='proposed'",
                                    (now, family_id))
            if fam["status"] == "proposed":
                self.store.conn.execute("UPDATE code_families SET status='rejected', decided_by=?, decision=?, updated_at=? WHERE id=?",
                                        (actor, dumps({"receipt_type": receipt_type, "receipt": receipt}), now, family_id))
            self._ledger(cid, "lineage", "family_rejected", actor, family_id=family_id, receipt_type=receipt_type)
            self._close_review(cid, family_id, actor, "rejected", [])
        return {"accepted": True, "reasons": [], "family": self.get_family(family_id)}

    def _close_review(self, cid: str, family_id: str, actor: str, outcome: str, edge_ids: list[str]) -> None:
        for action in self.list_pending_actions(cid, kind="lineage_review"):
            if action["payload"].get("family_id") == family_id:
                self._finish_pending(cid, action, actor, "done", "lineage_review",
                                     {"evidence_refs": [f"family {family_id} {outcome}", *edge_ids]})

    # ------------------------------------------------------------------ representatives
    def _rep_scores(self, cid: str, fam: dict) -> list[dict]:
        cfg = self.lineage_config(cid)
        members = [m["code_unit_id"] for m in fam["members"] if m["status"] == "approved"]
        edges = [e for e in self.list_similarity_edges(cid) if e["status"] == "approved"]
        out = []
        for u in members:
            unit = self.get_code_unit(u)
            occ = self.store.all("SELECT family FROM occurrences WHERE campaign_id=? AND member_sha256=?", (cid, unit["content_sha256"]))
            obs = self.unit_observations(u)
            exposed = any(o["kind"] == "behavioral_role" and o["value"] in cfg["exposed_roles"] for o in obs)
            central = sum(e["score"] for e in edges if u in (e["unit_a"], e["unit_b"]) and
                          ({e["unit_a"], e["unit_b"]} - {u}) <= set(members))
            analyzed = bool(self.store.scalar("SELECT COUNT(*) FROM analysis_receipts WHERE campaign_id=? AND content_sha256=? "
                                              "AND analysis_kind='full' AND derived_from IS NULL", (cid, unit["content_sha256"])))
            coverage = len(occ) + 2 * len({r["family"] for r in occ})
            evidence = sum(1 for o in obs if o["qualifies"] and o["mode"] in {"exact", "set"})
            score = round(2 * coverage + 3 * int(exposed) + 2 * central + 0.1 * evidence + 5 * int(analyzed), 6)
            out.append({"unit_id": u, "score": score, "coverage": coverage, "exposure": exposed, "centrality": round(central, 6),
                        "evidence_signals": evidence, "already_analyzed": analyzed})
        return sorted(out, key=lambda r: (-r["score"], r["unit_id"]))

    def _auto_representative(self, cid: str, family_id: str, actor: str) -> dict | None:
        fam = self.get_family(family_id)
        scores = self._rep_scores(cid, fam)
        if not scores:
            return None
        return self._set_representative(cid, fam, scores[0]["unit_id"], actor, {"method": "lite-rep-score-v1", "scores": scores})

    def _set_representative(self, cid: str, fam: dict, unit_id: str, actor: str, rationale: dict) -> dict:
        now = self.store.now()
        self.store.conn.execute("UPDATE representatives SET active=0 WHERE family_id=?", (fam["id"],))
        self.store.conn.execute("INSERT INTO representatives(id,campaign_id,family_id,code_unit_id,rationale,selected_by,active,created_at) "
                                "VALUES(?,?,?,?,?,?,1,?)", (new_id("rep"), cid, fam["id"], unit_id, dumps(rationale), actor, now))
        self.store.conn.execute("UPDATE code_families SET representative_unit_id=?, representative_rationale=?, updated_at=? WHERE id=?",
                                (unit_id, dumps(rationale), now, fam["id"]))
        self._ledger(cid, "lineage", "representative", actor, family_id=fam["id"], unit_id=unit_id, rationale=rationale)
        return self.get_family(fam["id"])

    def select_representative(self, cid: str, family_id: str, *, actor: str, unit_id: str | None = None) -> dict:
        self._require_operator(actor, "select representatives")
        fam = self.get_family(family_id)
        reasons = []
        if fam["status"] != "approved" or fam["algorithm_version"] != self._alg(cid):
            reasons.append(f"family is {fam['status']} (needs approved, current algorithm)")
        approved = {m["code_unit_id"] for m in fam["members"] if m["status"] == "approved"}
        if unit_id and unit_id not in approved:
            reasons.append("representative must be an approved family member")
        if reasons:
            return {"accepted": False, "reasons": reasons, "family": fam}
        with self.store.tx():
            scores = self._rep_scores(cid, fam)
            chosen = unit_id or scores[0]["unit_id"]
            fam = self._set_representative(cid, fam, chosen, actor, {"method": "operator" if unit_id else "lite-rep-score-v1", "scores": scores})
        return {"accepted": True, "reasons": [], "family": fam}

    # ------------------------------------------------------------------ lineage pass
    def run_lineage_pass(self, cid: str, *, actor: str) -> dict:
        """Fingerprint-driven clustering: candidate generation -> edges -> families -> representatives."""
        self._require_operator(actor, "run lineage passes")
        alg, policy = self._alg(cid), self.lineage_config(cid)
        with self.store.tx():
            obs = self._raw_obs(cid, alg)
            units = {u["id"]: u for u in self.list_code_units(cid) if u["id"] in obs}
            # inverted index -> candidate pairs (structural first, then metadata-only), bounded
            structural: dict[tuple[str, str], None] = {}
            meta_pairs: dict[tuple[str, str], None] = {}
            index: dict[tuple[str, str, str], set[str]] = {}
            for uid, rows in obs.items():
                for r in rows:
                    if r["mode"] == "scoped":
                        continue
                    keys = ([(r["kind"], r["mode"], e) for e in loads(r["value"], [])] if r["mode"] == "set"
                            else [(r["kind"], r["mode"], r["value_digest"])])
                    for k in keys:
                        index.setdefault(k, set()).add(uid)
            for (kind, mode, _), members in sorted(index.items()):
                ordered = sorted(members)
                for i, a in enumerate(ordered):
                    for b in ordered[i + 1:]:
                        ua, ub = units[a], units[b]
                        if ua["granularity"] != ub["granularity"] or (ua["content_sha256"] == ub["content_sha256"] and ua["granularity"] == "file"):
                            continue
                        (meta_pairs if mode == "metadata" else structural)[(a, b)] = None
            cap = int(policy["max_candidate_pairs"])
            pairs = list(structural)[:cap]
            meta_only = [p for p in meta_pairs if p not in structural][:max(0, cap - len(pairs))]
            truncated = len(structural) + len([p for p in meta_pairs if p not in structural]) > cap
            created = existing = 0
            for a, b in pairs:
                ev = evaluate_pair(obs.get(a, []), obs.get(b, []), policy)
                if not ev["structural"]:
                    continue
                _, how = self._store_edge(cid, a, b, ev, actor, policy, alg)
                created += how == "created"
                existing += how != "created"
            # families from connected components over usable edges
            edges = [e for e in self.list_similarity_edges(cid) if e["algorithm_version"] == alg and self._usable_edge(e)]
            adj: dict[str, set[str]] = {}
            for e in edges:
                adj.setdefault(e["unit_a"], set()).add(e["unit_b"])
                adj.setdefault(e["unit_b"], set()).add(e["unit_a"])
            seen: set[str] = set()
            proposed, extended, auto, conflicts = [], [], [], []
            for start in sorted(adj):
                if start in seen:
                    continue
                comp, stack = set(), [start]
                while stack:
                    u = stack.pop()
                    if u not in comp:
                        comp.add(u)
                        stack.extend(adj[u] - comp)
                seen |= comp
                comp_edges = sorted(e["id"] for e in edges if e["unit_a"] in comp)
                active = sorted({r["family_id"] for r in self.store.all(
                    f"SELECT m.family_id FROM code_family_members m JOIN code_families f ON f.id=m.family_id "
                    f"WHERE f.campaign_id=? AND f.algorithm_version=? AND f.status IN ('approved','proposed') "
                    f"AND m.code_unit_id IN ({','.join('?' * len(comp))})", (cid, alg, *sorted(comp)))})
                if len(active) > 1:
                    conflicts.append(active)
                    self._open_pending(cid, "lineage_review", "Lineage component spans multiple families",
                                       identity_parts=("merge", *active), requested_by=actor, payload={"families": active})
                    continue
                if active:
                    fid = active[0]
                    fam = self.get_family(fid)
                    known = {m["code_unit_id"] for m in fam["members"]}
                    status = "approved" if policy["auto_approve"] and all(self.get_edge(e)["policy_passed"] for e in comp_edges) else "proposed"
                    added = [u for u in sorted(comp - known) if self._add_member(cid, fid, u, comp_edges, actor, status)]
                    if added:
                        extended.append(fid)
                        self._ledger(cid, "lineage", "family_extended", actor, family_id=fid, added=added, status=status)
                        if status == "proposed":
                            self._open_pending(cid, "lineage_review", f"Review family extension {fid}", identity_parts=(fid,),
                                               requested_by=actor, payload={"family_id": fid, "added": added})
                    continue
                approve = bool(policy["auto_approve"]) and all(self.get_edge(e)["policy_passed"] for e in comp_edges)
                fid, new = self._create_family(cid, sorted(comp), comp_edges, actor, approved=approve, name=None)
                if new:
                    (auto if approve else proposed).append(fid)
                    if approve:
                        self.store.conn.execute("UPDATE similarity_edges SET status='approved', decided_by=? WHERE id IN "
                                                f"({','.join('?' * len(comp_edges))}) AND status='candidate'",
                                                (f"policy:{COMPARATOR}", *comp_edges))
            for fam in self.list_families(cid, status="approved"):
                rep = fam["representative_unit_id"]
                if fam["algorithm_version"] == alg and (not rep or rep not in {m["code_unit_id"] for m in fam["members"] if m["status"] == "approved"}):
                    self._auto_representative(cid, fam["id"], actor)
            digest = self._obs_digest(cid, alg)
            summary = {"algorithm_version": alg, "method": COMPARATOR, "units": len(units), "pairs_examined": len(pairs) + len(meta_only),
                       "edges_created": created, "edges_existing": existing, "metadata_only_rejected": len(meta_only),
                       "candidate_pairs_truncated": truncated, "families_proposed": proposed, "families_auto_approved": auto,
                       "families_extended": sorted(set(extended)), "merge_conflicts": conflicts, "observations_digest": digest}
            self._ledger(cid, "lineage", "pass", actor, **summary)
            self.checkpoint(cid, stage=self.get_campaign(cid)["current_stage"], key=f"lineage-pass:{alg}", input_hashes={},
                            output_refs=[f"observations:{digest}"], actor=actor)
        return summary

    # ------------------------------------------------------------------ stage-gate / scheduler hooks
    def _lineage_stage_reasons(self, cid: str) -> list[str]:
        cfg = self.lineage_config(cid)
        alg = cfg["algorithm_version"]
        n_obs = self.store.scalar("SELECT COUNT(*) FROM fingerprint_observations WHERE campaign_id=? AND algorithm_version=?", (cid, alg))
        required = cfg["require_before_deep"] if cfg["require_before_deep"] is not None else bool(n_obs)
        if not required:
            return []
        reasons = []
        refs = self.store.scalar("SELECT output_refs FROM stage_checkpoints WHERE campaign_id=? AND checkpoint_key=?", (cid, f"lineage-pass:{alg}"))
        if refs is None:
            reasons.append(f"lineage pass required before deep analysis (fingerprint + cluster under {alg})")
        elif f"observations:{self._obs_digest(cid, alg)}" not in loads(refs, []):
            reasons.append("lineage pass outdated: fingerprint observations changed since the last pass")
        pending = [f["id"] for f in self.list_families(cid) if f["algorithm_version"] == alg and
                   (f["status"] == "proposed" or any(m["status"] == "proposed" for m in f["members"]))]
        if pending:
            reasons.append(f"code families awaiting lineage review: {', '.join(pending)}")
        return reasons

    def _eligible_rep_receipt(self, cid: str, fam: dict) -> dict | None:
        rep = fam.get("representative_unit_id")
        if not rep:
            return None
        content = self.get_code_unit(rep)["content_sha256"]
        row = self.store.one("SELECT * FROM analysis_receipts WHERE campaign_id=? AND content_sha256=? AND analysis_kind='full' "
                             "AND outcome IN ('findings','negative') AND derived_from IS NULL ORDER BY created_at DESC, rowid DESC LIMIT 1",
                             (cid, content))
        return self._receipt(row) if row else None

    def _lineage_deep_refusal(self, cid: str, member_sha256: str) -> list[str]:
        fam = self.family_of(cid, self._file_unit(cid, member_sha256))
        if not fam or fam["representative_unit_id"] == self._file_unit(cid, member_sha256):
            return []
        receipt = self._eligible_rep_receipt(cid, fam)
        if not receipt:
            return []
        return [f"lineage variant of code family {fam['id']}: representative receipt {receipt['id']} exists; "
                "schedule bounded delta work (plan_lineage_work) instead of a full repeat"]

    def _priority(self, cid: str, fam: dict) -> int:
        cfg = self.lineage_config(cid)
        exposed = any(o["kind"] == "behavioral_role" and o["value"] in cfg["exposed_roles"]
                      for m in fam["members"] if m["status"] == "approved" for o in self.unit_observations(m["code_unit_id"]))
        return max(10, 100 - 20 * (len(fam["product_families"]) - 1) - (10 if exposed else 0))

    def _delta_items(self, cid: str, rep: str, variant: str, limit: int) -> tuple[list[dict], bool]:
        def sets(u):
            out: dict[str, set[str]] = {}
            for o in self.unit_observations(u):
                if o["mode"] == "set" and o["qualifies"]:
                    out.setdefault(o["kind"], set()).update(o["value"])
            return out
        a, b = sets(rep), sets(variant)
        items = []
        for kind in sorted(set(a) | set(b)):
            for e in sorted(b.get(kind, set()) - a.get(kind, set())):
                items.append({"kind": kind, "change": "added", "item": e})
            for e in sorted(a.get(kind, set()) - b.get(kind, set())):
                items.append({"kind": kind, "change": "removed", "item": e})
        return items[:limit], len(items) > limit

    def plan_lineage_work(self, cid: str, *, actor: str, kind: str = "deep-analysis") -> dict:
        """Scheduler: one representative per approved family, bounded delta jobs for variants.

        All jobs go through the normal engine enqueue path, so campaign budgets, max_jobs,
        retry ceilings, stop conditions and closeout blocking apply unchanged.
        """
        self._require_operator(actor, "plan lineage work")
        camp = self._require_active(cid)
        if STAGES.index(camp["current_stage"]) < STAGES.index("deep"):
            raise ValueError(f"lineage work planning requires stage deep; campaign is at {camp['current_stage']}")
        cfg, alg = self.lineage_config(cid), self._alg(cid)
        out: dict[str, list] = {"representative_jobs": [], "delta_jobs": [], "skipped": [], "refused": []}
        with self.store.tx():
            for fam in self.list_families(cid, status="approved"):
                if fam["algorithm_version"] != alg:
                    continue
                if not fam["representative_unit_id"]:
                    fam = self._auto_representative(cid, fam["id"], actor) or fam
                rep = fam["representative_unit_id"]
                rep_sha = self.get_code_unit(rep)["content_sha256"]
                prio = self._priority(cid, fam)
                if not self._middle_done(cid, rep_sha):
                    out["skipped"].append({"family_id": fam["id"], "unit_id": rep, "reason": "representative lacks succeeded middle job"})
                    continue
                receipt = self._eligible_rep_receipt(cid, fam)
                if not receipt:
                    if self.store.one("SELECT 1 FROM jobs WHERE campaign_id=? AND stage='deep' AND target_ref=? AND kind!=?",
                                      (cid, rep_sha, DELTA_KIND)):
                        out["skipped"].append({"family_id": fam["id"], "unit_id": rep, "reason": "representative job already scheduled"})
                        continue
                    cap = camp["config"].get("max_deep_selections")
                    if cap is not None and self._full_deep_count(cid) >= int(cap):
                        out["refused"].append({"family_id": fam["id"], "unit_id": rep, "reason": f"max_deep_selections {cap} reached"})
                        continue
                    res = self._enqueue(cid, stage="deep", kind=kind, target_type="member", target_ref=rep_sha, actor=actor, priority=prio,
                                        payload={"lineage_role": "representative", "family_id": fam["id"], "algorithm_version": alg,
                                                 "reason": f"representative of code family {fam['id']}"})
                    if res["refused"]:
                        out["refused"].append({"family_id": fam["id"], "unit_id": rep, "reason": "; ".join(res["reasons"])})
                    elif not res["deduplicated"]:
                        out["representative_jobs"].append(res["job"]["id"])
                    continue
                for m in fam["members"]:
                    v = m["code_unit_id"]
                    if m["status"] != "approved" or v == rep:
                        continue
                    v_sha = self.get_code_unit(v)["content_sha256"]
                    if v_sha == rep_sha:
                        continue
                    if self.store.one("SELECT 1 FROM jobs WHERE campaign_id=? AND stage='deep' AND kind=? AND target_ref=?", (cid, DELTA_KIND, v_sha)):
                        continue
                    if self.store.scalar("SELECT COUNT(*) FROM analysis_receipts WHERE campaign_id=? AND content_sha256=? AND analysis_kind='full' "
                                         "AND derived_from IS NULL", (cid, v_sha)):
                        out["skipped"].append({"family_id": fam["id"], "unit_id": v, "reason": "variant already fully analyzed"})
                        continue
                    if not self._middle_done(cid, v_sha):
                        out["skipped"].append({"family_id": fam["id"], "unit_id": v, "reason": "variant lacks succeeded middle job"})
                        continue
                    if len(self.list_delta_jobs(cid)) >= int(cfg["max_delta_jobs"]):
                        out["refused"].append({"family_id": fam["id"], "unit_id": v, "reason": f"max_delta_jobs {cfg['max_delta_jobs']} reached"})
                        continue
                    items, truncated = self._delta_items(cid, rep, v, int(cfg["max_delta_items"]))
                    edge = next((e["id"] for e in self.list_similarity_edges(cid, unit_id=v) if {e["unit_a"], e["unit_b"]} == {v, rep}), None)
                    res = self._enqueue(cid, stage="deep", kind=DELTA_KIND, target_type="member", target_ref=v_sha, actor=actor, priority=prio,
                                        payload={"lineage_role": "delta", "family_id": fam["id"], "representative_unit_id": rep,
                                                 "representative_receipt_id": receipt["id"], "variant_unit_id": v, "edge_id": edge,
                                                 "algorithm_version": alg, "delta_items": items, "delta_truncated": truncated})
                    if res["refused"]:
                        out["refused"].append({"family_id": fam["id"], "unit_id": v, "reason": "; ".join(res["reasons"])})
                        continue
                    out["delta_jobs"].append(res["job"]["id"])
                    self._record_reuse(cid, "representative_analysis", receipt["id"], v, fam["id"], actor,
                                       {"method": COMPARATOR, "edge_id": edge, "delta_job_id": res["job"]["id"],
                                        "note": "representative analysis reused; variant gets bounded delta job, not a full repeat"})
            self._ledger(cid, "lineage", "plan", actor, **{k: v for k, v in out.items()})
        return out

    def _middle_done(self, cid: str, sha: str) -> bool:
        return bool(self.store.scalar("SELECT COUNT(*) FROM jobs WHERE campaign_id=? AND stage='middle' AND target_ref=? AND status='succeeded'",
                                      (cid, sha)))

    def _full_deep_count(self, cid: str) -> int:
        return int(self.store.scalar("SELECT COUNT(*) FROM jobs WHERE campaign_id=? AND stage='deep' AND kind!=?", (cid, DELTA_KIND)))

    def list_delta_jobs(self, cid: str) -> list[dict]:
        return [self.get_job(r["id"]) for r in self.store.all("SELECT id FROM jobs WHERE campaign_id=? AND kind=? ORDER BY seq", (cid, DELTA_KIND))]

    # ------------------------------------------------------------------ receipts / reuse
    def _receipt(self, row: Any) -> dict:
        d = dict(row)
        for k, default in (("checked_scope", []), ("checked_digests", {}), ("finding_ids", []), ("evidence", {})):
            d[k] = loads(d[k], default)
        return d

    def list_analysis_receipts(self, cid: str, unit_id: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM analysis_receipts WHERE campaign_id=?", [cid]
        if unit_id:
            sql += " AND content_sha256=?"
            args.append(self.get_code_unit(unit_id)["content_sha256"])
        return [self._receipt(r) for r in self.store.all(sql + " ORDER BY created_at, rowid", tuple(args))]

    def list_delta_receipts(self, cid: str) -> list[dict]:
        out = []
        for r in self.store.all("SELECT * FROM delta_receipts WHERE campaign_id=? ORDER BY created_at, rowid", (cid,)):
            d = dict(r)
            d["changed_items"] = loads(d["changed_items"], [])
            d["evidence"] = loads(d["evidence"], {})
            out.append(d)
        return out

    def _on_job_succeeded(self, cid: str, job: dict, payload: dict, finding_ids: list[str]) -> None:
        if job["target_type"] != "member" or job["stage"] not in {"middle", "deep"}:
            return
        role = (job.get("payload") or {}).get("lineage_role")
        akind = "delta" if job["kind"] == DELTA_KIND else ("full" if job["stage"] == "deep" else "middle")
        outcome = payload.get("outcome") if payload.get("outcome") in {"findings", "negative", "inconclusive"} else (
            "findings" if finding_ids else "negative")
        digests = {str(k): normalize_sha256(v) for k, v in (payload.get("checked_digests") or {}).items() if normalize_sha256(v)}
        rid = new_id("arc")
        self.store.conn.execute(
            "INSERT OR IGNORE INTO analysis_receipts(id,campaign_id,code_unit_id,content_sha256,job_id,analysis_kind,lineage_role,outcome,"
            "checked_scope,checked_digests,finding_ids,evidence,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (rid, cid, self._file_unit(cid, job["target_ref"]), job["target_ref"], job["id"], akind, role, outcome,
             dumps(string_list(payload.get("checked_scope"))), dumps(digests), dumps(finding_ids),
             dumps({"summary": payload.get("summary"), "artifact_refs": payload.get("artifact_refs") or [],
                    "source_anchors": payload.get("source_anchors") or [], "limitations": payload.get("limitations") or []}),
             self.store.now()))
        self._ledger(cid, "lineage", "analysis_receipt", job.get("claimed_by"), receipt_id=rid, job_id=job["id"],
                     analysis_kind=akind, outcome=outcome, lineage_role=role)
        if akind == "delta":
            jp = job["payload"]
            delta = payload.get("delta") if isinstance(payload.get("delta"), dict) else {}
            d_out = delta.get("outcome") if delta.get("outcome") in {"consistent", "diverged", "inconclusive"} else "inconclusive"
            self.store.conn.execute(
                "INSERT OR IGNORE INTO delta_receipts(id,campaign_id,job_id,family_id,variant_unit_id,representative_receipt_id,outcome,"
                "changed_items,evidence,algorithm_version,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (new_id("drc"), cid, job["id"], jp.get("family_id"), jp.get("variant_unit_id"), jp.get("representative_receipt_id"),
                 d_out, dumps(string_list(delta.get("changed_items"))), dumps({"summary": payload.get("summary")}),
                 jp.get("algorithm_version"), self.store.now()))
            self._ledger(cid, "lineage", "delta_receipt", job.get("claimed_by"), job_id=job["id"], outcome=d_out,
                         family_id=jp.get("family_id"))

    def _record_reuse(self, cid: str, kind: str, source_receipt_id: str, target_unit: str, family_id: str | None,
                      actor: str, basis: dict) -> dict:
        alg = self._alg(cid)
        rid = stable_id("reuse", {"cid": cid, "kind": kind, "src": source_receipt_id, "dst": target_unit, "alg": alg})
        cur = self.store.conn.execute(
            "INSERT OR IGNORE INTO reuse_records(id,campaign_id,kind,source_receipt_id,target_unit_id,family_id,basis,algorithm_version,"
            "actor,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (rid, cid, kind, source_receipt_id, target_unit, family_id, dumps(basis), alg, actor, self.store.now()))
        if cur.rowcount:
            self._ledger(cid, "lineage", "reuse", actor, reuse_id=rid, kind=kind, source_receipt_id=source_receipt_id,
                         target_unit_id=target_unit, family_id=family_id, algorithm_version=alg, basis=basis)
        return self._reuse(self.store.one("SELECT * FROM reuse_records WHERE id=?", (rid,)))

    def _reuse(self, row: Any) -> dict:
        d = dict(row)
        d["basis"] = loads(d["basis"], {})
        d["stale"] = bool(d["stale"])
        return d

    def list_reuse(self, cid: str) -> list[dict]:
        return [self._reuse(r) for r in self.store.all("SELECT * FROM reuse_records WHERE campaign_id=? ORDER BY created_at, id", (cid,))]

    def reuse_negative_result(self, cid: str, receipt_id: str, target_unit_id: str, *, actor: str) -> dict:
        """Reuse a negative analysis only when the checked code scopes and relevant config are proven equivalent."""
        self._require_kind(actor, OPERATOR_KINDS | {"tool"}, "reuse negative results")
        row = self.store.one("SELECT * FROM analysis_receipts WHERE id=?", (receipt_id,))
        if not row:
            raise KeyError(f"unknown analysis receipt {receipt_id}")
        src = self._receipt(row)
        target = self.get_code_unit(target_unit_id)
        alg = self._alg(cid)
        reasons = []
        if src["campaign_id"] != cid or target["campaign_id"] != cid:
            reasons.append("receipt/unit not in campaign")
        if src["outcome"] != "negative":
            reasons.append("only negative analysis receipts can be reused as negative results")
        if src["derived_from"]:
            reasons.append("source receipt is itself derived; reuse from the original analysis")
        scopes = src["checked_digests"]
        if not any(k.startswith("code:") for k in scopes):
            reasons.append("receipt declares no checked code scope (code:*) with digest")
        if not any(k.startswith("config:") for k in scopes):
            reasons.append("receipt declares no relevant configuration scope (config:*) with digest")
        have: dict[str, set[str]] = {}
        obs_ids: list[str] = []
        for o in self.unit_observations(target_unit_id):
            if o["kind"] == "scoped_digest" and o["qualifies"]:
                have.setdefault(o["value"]["scope"], set()).add(o["value"]["digest"])
                obs_ids.append(o["id"])
        same_bytes = target["content_sha256"] == src["content_sha256"]
        matched = []
        for scope, digest in sorted(scopes.items()):
            if scope.startswith("code:") and same_bytes:
                matched.append(scope)
            elif digest in have.get(scope, set()):
                matched.append(scope)
            else:
                reasons.append(f"scope {scope} not proven equivalent on target ({'differs' if scope in have else 'missing'})")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "lineage", "reuse_refused", actor, kind="negative_result", source_receipt_id=receipt_id,
                             target_unit_id=target_unit_id, reasons=reasons)
                return {"accepted": False, "reasons": reasons, "reuse": None}
            basis = {"method": "scoped-digest-equality-v1", "matched_scopes": matched, "source_digests": scopes,
                     "target_observation_ids": sorted(obs_ids), "same_bytes": same_bytes, "algorithm_version": alg}
            reuse = self._record_reuse(cid, "negative_result", receipt_id, target_unit_id, None, actor, basis)
            self.store.conn.execute(
                "INSERT INTO analysis_receipts(id,campaign_id,code_unit_id,content_sha256,job_id,analysis_kind,lineage_role,outcome,"
                "checked_scope,checked_digests,finding_ids,evidence,derived_from,created_at) "
                "SELECT ?,?,?,?,NULL,?,'reused','negative',?,?,'[]',?,?,? WHERE NOT EXISTS "
                "(SELECT 1 FROM analysis_receipts WHERE campaign_id=? AND code_unit_id=? AND derived_from=?)",
                (new_id("arc"), cid, target_unit_id, target["content_sha256"], src["analysis_kind"], dumps(src["checked_scope"]),
                 dumps(scopes), dumps({"reuse_id": reuse["id"]}), receipt_id, self.store.now(), cid, target_unit_id, receipt_id))
        return {"accepted": True, "reasons": [], "reuse": reuse}

    # ------------------------------------------------------------------ algorithm version change
    def set_fingerprint_algorithm(self, cid: str, version: str, *, actor: str, reason: str) -> dict:
        self._require_operator(actor, "change the fingerprint algorithm version")
        camp = self.get_campaign(cid)
        old = self._alg(cid)
        if not version or version == old:
            raise ValueError("new algorithm version must differ from the current one")
        with self.store.tx():
            cfg = camp["config"]
            lin = dict(cfg.get("lineage") or {})
            lin["algorithm_version"] = version
            cfg["lineage"] = lin
            now = self.store.now()
            self.store.conn.execute("UPDATE campaigns SET config=?, updated_at=? WHERE id=?", (dumps(cfg), now, cid))
            stale_edges = self.store.all("SELECT id,status FROM similarity_edges WHERE campaign_id=? AND algorithm_version!=? "
                                         "AND status!='stale'", (cid, version))
            for e in stale_edges:
                self.store.conn.execute("UPDATE similarity_edges SET decision=?, status='stale', updated_at=? WHERE id=?",
                                        (dumps({"prior_status": e["status"], "stale_reason": f"algorithm {old} -> {version}"}), now, e["id"]))
            n_edges = len(stale_edges)
            fams = [r["id"] for r in self.store.all("SELECT id FROM code_families WHERE campaign_id=? AND algorithm_version!=? "
                                                     "AND status NOT IN ('stale','rejected')", (cid, version))]
            self.store.conn.execute("UPDATE code_families SET status='stale', updated_at=? WHERE campaign_id=? AND algorithm_version!=? "
                                    "AND status NOT IN ('stale','rejected')", (now, cid, version))
            n_reuse = self.store.conn.execute("UPDATE reuse_records SET stale=1 WHERE campaign_id=? AND algorithm_version!=? AND stale=0",
                                              (cid, version)).rowcount
            n_app = self.store.conn.execute(
                "UPDATE finding_applicability SET stale=1, updated_at=? WHERE campaign_id=? AND derived_via='lineage' "
                "AND COALESCE(algorithm_version,'')!=? AND stale=0", (now, cid, version)).rowcount
            cancelled = []
            for j in self.list_delta_jobs(cid):
                if j["status"] in {"queued", "budget_blocked"} and j["payload"].get("algorithm_version") != version:
                    self.store.conn.execute("UPDATE jobs SET status='cancelled', last_error=?, updated_at=? WHERE id=?",
                                            (f"lineage algorithm changed {old} -> {version}", now, j["id"]))
                    cancelled.append(j["id"])
            for action in self.list_pending_actions(cid, kind="lineage_review"):
                self._finish_pending(cid, action, actor, "cancelled", "algorithm_change",
                                     {"evidence_refs": [f"fingerprint algorithm {old} -> {version}"]})
            out = {"previous": old, "current": version, "stale_edges": n_edges, "stale_families": fams, "stale_reuse": n_reuse,
                   "stale_applicability": n_app, "cancelled_delta_jobs": cancelled}
            self._ledger(cid, "lineage", "algorithm_changed", actor, reason=reason, **out)
        return out

    # ------------------------------------------------------------------ queries
    def lineage(self, cid: str, content_sha256: str) -> dict:
        sha = normalize_sha256(content_sha256)
        member = self.get_member(cid, sha)
        occ = self.member_occurrences(cid, sha)
        units = self.list_code_units(cid, content_sha256=sha)
        unit_ids = {u["id"] for u in units}
        fams = [f for f in self.list_families(cid) if unit_ids & {m["code_unit_id"] for m in f["members"]}]
        return {
            "content": member,
            "tier0": {"sha256": sha, "occurrence_count": len(occ), "product_families": sorted({o["family"] for o in occ}),
                      "images": sorted({o["image_name"] for o in occ})},
            "occurrences": occ,
            "code_units": units,
            "observations": {u: self.unit_observations(u) for u in sorted(unit_ids)},
            "families": [{k: f[k] for k in ("id", "status", "algorithm_version", "representative_unit_id", "product_families", "members")} for f in fams],
            "edges": [e for u in sorted(unit_ids) for e in self.list_similarity_edges(cid, unit_id=u)],
            "receipts": [r for r in self.list_analysis_receipts(cid) if r["content_sha256"] == sha],
            "reuse": [r for r in self.list_reuse(cid) if r["target_unit_id"] in unit_ids],
            "algorithm_version": self._alg(cid),
        }

    def reusable_knowledge(self, cid: str, content_sha256: str) -> dict:
        """What prior analysis/findings/attack-chain knowledge applies (or is candidate) for this content."""
        sha = normalize_sha256(content_sha256)
        unit = self._file_unit(cid, sha)
        fam = self.family_of(cid, unit)
        contents = {sha}
        if fam:
            contents |= {self.get_code_unit(m["code_unit_id"])["content_sha256"] for m in fam["members"] if m["status"] == "approved"}
        findings = [f for f in self.list_findings(cid) if f.get("member_sha256") in contents]
        app = [r for r in self.list_applicability(cid) if r["content_sha256"] == sha]
        nodes = [n for n in self.attack_chain(cid)["nodes"] if (fam and n["family_id"] == fam["id"]) or n["code_unit_id"] == unit]
        return {
            "content_sha256": sha, "family": fam and {k: fam[k] for k in ("id", "status", "representative_unit_id", "product_families")},
            "representative_receipt": fam and self._eligible_rep_receipt(cid, fam),
            "receipts": [r for r in self.list_analysis_receipts(cid) if r["content_sha256"] == sha],
            "findings": [{"id": f["id"], "title": f["title"], "tier": f["tier"], "origin_content": f["member_sha256"],
                          "reuse_status": "origin" if f["member_sha256"] == sha else "candidate_only"} for f in findings],
            "applicability": app,
            "attack_chain_nodes": nodes,
            "reuse": [r for r in self.list_reuse(cid) if r["target_unit_id"] == unit],
            "note": "Reused knowledge from other family members is candidate-only until per-variant applicability gates pass.",
        }
