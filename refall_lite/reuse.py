"""Per-occurrence finding applicability and attack-chain knowledge reuse.

Reuse rules (addendum):
- a finding is one record; every artifact occurrence it may affect gets an
  applicability row. Rows propagated by exact bytes inherit only the
  byte-invariant code gates; rows propagated by lineage start with every gate
  pending. Both start ``candidate_applicable``.
- ``applicable`` is reached only when every required gate (code_path,
  version_constraints, configuration, exposure, preconditions) passes with a
  tool/human receipt. Negative states (not_applicable, not_present, fixed,
  unreachable) need the matching failed gate and never generalise to siblings.
- attack-chain shared component nodes are linked once; reachability/exposure
  nodes, edges and preconditions are product-specific. A reused edge starts as
  ``candidate`` with fresh ``unknown`` preconditions for that product.
"""
from __future__ import annotations

from typing import Any

from ._base import Base
from .arcticbase.contracts import DISPOSITIONS, INDEPENDENT_KINDS, OPERATOR_KINDS, receipt_has_material, sha256_text, stable_id
from .arcticbase.store import dumps, loads, new_id

GATES = ["code_path", "version_constraints", "configuration", "exposure", "preconditions"]
BYTE_INVARIANT_GATES = {"code_path", "version_constraints"}
NEGATIVE_STATES = {
    "not_present": {"code_path", "version_constraints"},
    "fixed": {"code_path", "version_constraints"},
    "unreachable": {"exposure", "preconditions"},
    "not_applicable": set(GATES),
    "unknown": set(),
}
APPLICABILITY_STATES = {"candidate_applicable", "applicable", *NEGATIVE_STATES}


class ReuseMixin(Base):
    # ------------------------------------------------------------------ applicability
    def _app(self, row: Any) -> dict:
        d = dict(row)
        d["checks"] = loads(d["checks"], {})
        d["evidence"] = loads(d["evidence"], [])
        d["decision"] = loads(d["decision"], None)
        d["stale"] = bool(d["stale"])
        tier = self.store.scalar("SELECT tier FROM findings WHERE id=?", (d["finding_id"],))
        d["finding_tier"] = tier
        d["validated_on_target"] = d["state"] == "applicable" and tier == "validated" and not d["stale"]
        return d

    def get_applicability(self, row_id: str) -> dict:
        row = self.store.one("SELECT * FROM finding_applicability WHERE id=?", (row_id,))
        if not row:
            raise KeyError(f"unknown applicability row {row_id}")
        return self._app(row)

    def list_applicability(self, cid: str, *, finding_id: str | None = None, state: str | None = None) -> list[dict]:
        sql, args = "SELECT * FROM finding_applicability WHERE campaign_id=?", [cid]
        if finding_id:
            sql += " AND finding_id=?"
            args.append(finding_id)
        if state:
            sql += " AND state=?"
            args.append(state)
        return [self._app(r) for r in self.store.all(sql + " ORDER BY content_sha256, image_id, path", tuple(args))]

    def _insert_applicability(self, cid: str, finding_id: str, content: str, via: str, family_id: str | None,
                              actor: str, evidence: list | None = None) -> tuple[int, int]:
        alg = self.lineage_config(cid)["algorithm_version"]
        created = existing = 0
        now = self.store.now()
        for occ in self.member_occurrences(cid, content):
            checks = {g: {"status": "pending"} for g in GATES}
            if via == "exact":
                for g in BYTE_INVARIANT_GATES:
                    checks[g] = {"status": "passed", "basis": "tier0: identical content sha256 to the finding's origin", "actor": "refall-lite"}
            rid = stable_id("app", {"f": finding_id, "img": occ["image_id"], "path": occ["path"]})
            cur = self.store.conn.execute(
                "INSERT OR IGNORE INTO finding_applicability(id,campaign_id,finding_id,image_id,path,content_sha256,code_unit_id,"
                "product_family,derived_via,via_family_id,algorithm_version,state,checks,evidence,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,'candidate_applicable',?,?,?,?)",
                (rid, cid, finding_id, occ["image_id"], occ["path"], content, self._file_unit(cid, content), occ["family"], via,
                 family_id, alg if via == "lineage" else None, dumps(checks), dumps(evidence or []), now, now))
            if cur.rowcount:
                created += 1
            else:
                existing += 1
                if evidence:
                    cur_ev = loads(self.store.scalar("SELECT evidence FROM finding_applicability WHERE id=?", (rid,)), [])
                    self.store.conn.execute("UPDATE finding_applicability SET evidence=?, updated_at=? WHERE id=?",
                                            (dumps(cur_ev + [e for e in evidence if e not in cur_ev]), now, rid))
        return created, existing

    def propagate_finding(self, cid: str, finding_id: str, *, actor: str) -> dict:
        """Create candidate applicability rows for every occurrence of the origin content and its lineage variants."""
        self._require_operator(actor, "propagate findings")
        f = self.get_finding(finding_id)
        if f["campaign_id"] != cid or not f.get("member_sha256"):
            raise ValueError("finding must belong to campaign and anchor to a member sha256")
        if f["tier"] in DISPOSITIONS:
            raise ValueError(f"finding is {f['tier']}")
        with self.store.tx():
            created, existing = self._insert_applicability(cid, finding_id, f["member_sha256"], "exact", None, actor)
            fam = self.family_of(cid, self._file_unit(cid, f["member_sha256"]))
            variants = []
            if fam:
                for m in fam["members"]:
                    if m["status"] != "approved":
                        continue
                    content = self.get_code_unit(m["code_unit_id"])["content_sha256"]
                    if content == f["member_sha256"]:
                        continue
                    c, e = self._insert_applicability(cid, finding_id, content, "lineage", fam["id"], actor)
                    created, existing = created + c, existing + e
                    variants.append(content)
            self._ledger(cid, "applicability", "propagate", actor, finding_id=finding_id, created=created, existing=existing,
                         family_id=fam and fam["id"], variant_contents=variants, state="candidate_applicable")
        return {"created": created, "existing": existing, "family_id": fam and fam["id"],
                "rows": self.list_applicability(cid, finding_id=finding_id)}

    def _lineage_attach_finding(self, cid: str, actor: str, cand: dict, job_id: str | None) -> str | None:
        """A variant's 'new' finding with the same root cause attaches to the canonical record."""
        sha = cand.get("member_sha256")
        fam = self.family_of(cid, self._file_unit(cid, sha)) if sha else None
        if not fam:
            return None
        contents = {self.get_code_unit(m["code_unit_id"])["content_sha256"] for m in fam["members"] if m["status"] == "approved"}
        norm = lambda v: " ".join(str(v or "").lower().split())
        for f in self.list_findings(cid):
            if (f.get("member_sha256") in contents and f["member_sha256"] != sha and f["tier"] not in DISPOSITIONS
                    and norm(f["vuln_class"]) == norm(cand.get("vuln_class")) and norm(f["title"]) == norm(cand.get("title"))):
                ev = [{"actor": actor, "job_id": job_id, "evidence": cand.get("evidence") or [], "limitations": cand.get("limitations") or [],
                       "source_anchors": cand.get("source_anchors") or [], "artifact_refs": cand.get("artifact_refs") or []}]
                self._insert_applicability(cid, f["id"], sha, "lineage", fam["id"], actor, evidence=ev)
                self._ledger(cid, "applicability", "attach", actor, finding_id=f["id"], content_sha256=sha, family_id=fam["id"],
                             job_id=job_id, note="variant report attached to canonical finding; candidate only")
                return f["id"]
        return None

    def record_applicability_check(self, cid: str, row_id: str, *, gate: str, status: str, actor: str, receipt: dict) -> dict:
        act = self.actor(actor)
        row = self.get_applicability(row_id)
        reasons = []
        if row["campaign_id"] != cid:
            reasons.append("row not in campaign")
        if gate not in GATES:
            reasons.append(f"gate must be one of {GATES}")
        if status not in {"passed", "failed"}:
            reasons.append("status must be passed or failed")
        if act["kind"] not in INDEPENDENT_KINDS:
            reasons.append(f"actor kind {act['kind']} cannot decide applicability gates (tool/human only)")
        if not receipt_has_material(receipt):
            reasons.append("gate decision requires receipt evidence")
        if row["stale"]:
            reasons.append("row is stale (lineage algorithm changed); re-propagate under the current algorithm")
        if row["state"] not in {"candidate_applicable", "unknown"}:
            reasons.append(f"row already decided: {row['state']}")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "applicability", "check_refused", actor, row_id=row_id, gate=gate, reasons=reasons)
                return {"accepted": False, "reasons": reasons, "row": row}
            checks = row["checks"]
            checks[gate] = {"status": status, "actor": actor, "receipt": receipt, "ts": self.store.now()}
            state, decision = row["state"], row["decision"]
            if all(checks[g]["status"] == "passed" for g in GATES):
                state, decision = "applicable", {"basis": "all applicability gates passed", "gates": GATES}
            self.store.conn.execute("UPDATE finding_applicability SET checks=?, state=?, decision=?, updated_at=? WHERE id=?",
                                    (dumps(checks), state, dumps(decision), self.store.now(), row_id))
            self._ledger(cid, "applicability", "check", actor, row_id=row_id, finding_id=row["finding_id"], gate=gate,
                         status=status, state=state)
        return {"accepted": True, "reasons": [], "row": self.get_applicability(row_id)}

    def decide_applicability(self, cid: str, row_id: str, *, state: str, actor: str, receipt_type: str | None, receipt: dict) -> dict:
        act = self.actor(actor)
        row = self.get_applicability(row_id)
        reasons = []
        if state not in NEGATIVE_STATES:
            reasons.append("decide_applicability sets negative/unknown states; 'applicable' is reached only via passing gates")
        allowed = INDEPENDENT_KINDS | ({"supervisor"} if state == "unknown" else set())
        if act["kind"] not in allowed:
            reasons.append(f"actor kind {act['kind']} cannot set {state}")
        if not receipt_type or not receipt_has_material(receipt):
            reasons.append("decision requires receipt_type and receipt evidence")
        if row["state"] not in {"candidate_applicable", "unknown"}:
            reasons.append(f"row already decided: {row['state']}")
        needed = NEGATIVE_STATES.get(state, set())
        if needed and not any(row["checks"].get(g, {}).get("status") == "failed" for g in needed):
            reasons.append(f"{state} requires a failed gate among {sorted(needed)}")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "applicability", "decision_refused", actor, row_id=row_id, state=state, reasons=reasons)
                return {"accepted": False, "reasons": reasons, "row": row}
            self.store.conn.execute(
                "UPDATE finding_applicability SET state=?, decided_by=?, decision=?, updated_at=? WHERE id=?",
                (state, actor, dumps({"receipt_type": receipt_type, "receipt": receipt}), self.store.now(), row_id))
            self._ledger(cid, "applicability", "decide", actor, row_id=row_id, finding_id=row["finding_id"], state=state,
                         receipt_type=receipt_type, note="negative decisions never generalise to sibling occurrences")
        return {"accepted": True, "reasons": [], "row": self.get_applicability(row_id)}

    # ------------------------------------------------------------------ attack chains
    def _node(self, row: Any) -> dict:
        d = dict(row)
        d["evidence"] = loads(d["evidence"], {})
        tier = self.store.scalar("SELECT tier FROM findings WHERE id=?", (d["finding_id"],)) if d["finding_id"] else None
        d["status"] = ("confirmed" if tier == "validated" else "refuted" if tier == "rejected"
                       else "known" if tier == "known_cve" else "candidate")
        return d

    def _chain_edge(self, row: Any) -> dict:
        d = dict(row)
        d["evidence"] = loads(d["evidence"], {})
        pres = []
        for p in self.store.all("SELECT * FROM attack_chain_preconditions WHERE edge_id=? ORDER BY ordinal", (d["id"],)):
            pd = dict(p)
            pd["evidence"] = loads(pd["evidence"], {})
            pres.append(pd)
        d["preconditions"] = pres
        states = [p["state"] for p in pres]
        d["status"] = ("refuted" if "unsatisfied" in states else "confirmed" if states and all(s == "satisfied" for s in states)
                       else "candidate")
        return d

    def add_chain_node(self, cid: str, *, actor: str, kind: str, label: str, scope: str, code_unit_id: str | None = None,
                       family_id: str | None = None, finding_id: str | None = None, product_family: str | None = None,
                       image_id: str | None = None, evidence: dict | None = None) -> dict:
        self.actor(actor)
        if scope not in {"shared", "product"}:
            raise ValueError("scope must be shared or product")
        if scope == "shared" and not (family_id or code_unit_id):
            raise ValueError("shared nodes anchor to a code family or code unit")
        if scope == "product":
            if not product_family:
                raise ValueError("product nodes need product_family")
            if not self.store.one("SELECT 1 FROM images WHERE campaign_id=? AND family=?", (cid, product_family)):
                raise ValueError(f"unknown product family {product_family}")
        norm = " ".join(label.lower().split())
        key = (f"shared|{kind}|{family_id or code_unit_id}|{norm}" if scope == "shared"
               else f"product|{kind}|{product_family}|{image_id or ''}|{norm}")
        nid = stable_id("node", {"cid": cid, "key": key})
        with self.store.tx():
            cur = self.store.conn.execute(
                "INSERT OR IGNORE INTO attack_chain_nodes(id,campaign_id,node_key,kind,label,scope,code_unit_id,family_id,finding_id,"
                "product_family,image_id,evidence,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (nid, cid, key, kind, label, scope, code_unit_id, family_id, finding_id, product_family, image_id,
                 dumps(evidence or {}), actor, self.store.now()))
            if cur.rowcount:
                self._ledger(cid, "attack-chain", "node", actor, node_id=nid, kind=kind, scope=scope, family_id=family_id,
                             product_family=product_family, finding_id=finding_id)
        return self._node(self.store.one("SELECT * FROM attack_chain_nodes WHERE id=?", (nid,)))

    def add_chain_edge(self, cid: str, src_node_id: str, dst_node_id: str, *, actor: str, relation: str,
                       preconditions: list[str], evidence: dict | None = None, _reused_from: str | None = None) -> dict:
        self.actor(actor)
        src = self.store.one("SELECT * FROM attack_chain_nodes WHERE id=? AND campaign_id=?", (src_node_id, cid))
        dst = self.store.one("SELECT * FROM attack_chain_nodes WHERE id=? AND campaign_id=?", (dst_node_id, cid))
        if not src or not dst:
            raise ValueError("both nodes must exist in campaign")
        pres = [p.strip() for p in preconditions if str(p).strip()]
        if not pres:
            raise ValueError("attack-chain edges need at least one explicit precondition")
        product = src["product_family"] or dst["product_family"]
        key = f"{src_node_id}|{dst_node_id}|{relation}"
        eid = stable_id("cedge", {"cid": cid, "key": key})
        now = self.store.now()
        with self.store.tx():
            cur = self.store.conn.execute(
                "INSERT OR IGNORE INTO attack_chain_edges(id,campaign_id,edge_key,src_node_id,dst_node_id,relation,product_family,"
                "reused_from_edge_id,evidence,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (eid, cid, key, src_node_id, dst_node_id, relation, product, _reused_from, dumps(evidence or {}), actor, now, now))
            if cur.rowcount:
                for i, text in enumerate(pres):
                    self.store.conn.execute(
                        "INSERT INTO attack_chain_preconditions(id,campaign_id,edge_id,ordinal,description,state,created_at,updated_at) "
                        "VALUES(?,?,?,?,?,'unknown',?,?)", (new_id("pre"), cid, eid, i, text, now, now))
                self._ledger(cid, "attack-chain", "edge", actor, edge_id=eid, src=src_node_id, dst=dst_node_id, relation=relation,
                             product_family=product, preconditions=pres, reused_from=_reused_from, status="candidate")
        return self._chain_edge(self.store.one("SELECT * FROM attack_chain_edges WHERE id=?", (eid,)))

    def check_precondition(self, cid: str, precondition_id: str, *, state: str, actor: str, receipt: dict) -> dict:
        act = self.actor(actor)
        row = self.store.one("SELECT * FROM attack_chain_preconditions WHERE id=? AND campaign_id=?", (precondition_id, cid))
        if not row:
            raise KeyError(f"unknown precondition {precondition_id}")
        reasons = []
        if state not in {"satisfied", "unsatisfied"}:
            reasons.append("state must be satisfied or unsatisfied")
        if act["kind"] not in INDEPENDENT_KINDS:
            reasons.append(f"actor kind {act['kind']} cannot decide preconditions (tool/human only)")
        if not receipt_has_material(receipt):
            reasons.append("precondition decision requires receipt evidence")
        with self.store.tx():
            if reasons:
                self._ledger(cid, "attack-chain", "precondition_refused", actor, precondition_id=precondition_id, reasons=reasons)
                return {"accepted": False, "reasons": reasons, "edge": self._chain_edge(self.store.one(
                    "SELECT * FROM attack_chain_edges WHERE id=?", (row["edge_id"],)))}
            self.store.conn.execute("UPDATE attack_chain_preconditions SET state=?, evidence=?, checked_by=?, updated_at=? WHERE id=?",
                                    (state, dumps(receipt), actor, self.store.now(), precondition_id))
            edge = self._chain_edge(self.store.one("SELECT * FROM attack_chain_edges WHERE id=?", (row["edge_id"],)))
            self._ledger(cid, "attack-chain", "precondition", actor, precondition_id=precondition_id, edge_id=edge["id"],
                         state=state, edge_status=edge["status"], product_family=edge["product_family"])
        return {"accepted": True, "reasons": [], "edge": edge}

    def reuse_chain_node(self, cid: str, shared_node_id: str, *, product_family: str, actor: str, entry_label: str,
                         template_edge_id: str | None = None, relation: str = "reaches") -> dict:
        """Link a product to an existing shared component node; reachability stays product-specific (candidate)."""
        self._require_operator(actor, "reuse attack-chain components")
        node = self.store.one("SELECT * FROM attack_chain_nodes WHERE id=? AND campaign_id=?", (shared_node_id, cid))
        reasons = []
        if not node or node["scope"] != "shared":
            reasons.append("reuse requires an existing shared node")
        contents: set[str] = set()
        if node and node["family_id"]:
            fam = self.get_family(node["family_id"])
            if fam["status"] != "approved":
                reasons.append(f"component family is {fam['status']}")
            contents = {self.get_code_unit(m["code_unit_id"])["content_sha256"] for m in fam["members"] if m["status"] == "approved"}
        elif node and node["code_unit_id"]:
            contents = {self.get_code_unit(node["code_unit_id"])["content_sha256"]}
        present = bool(contents) and bool(self.store.scalar(
            f"SELECT COUNT(*) FROM occurrences WHERE campaign_id=? AND family=? AND member_sha256 IN ({','.join('?' * len(contents))})",
            (cid, product_family, *sorted(contents)))) if contents else False
        if node and not present:
            reasons.append(f"product family {product_family} does not ship the shared component")
        template = None
        if not reasons:
            if template_edge_id:
                template = self.store.one("SELECT * FROM attack_chain_edges WHERE id=? AND dst_node_id=?", (template_edge_id, shared_node_id))
            else:
                template = self.store.one("SELECT * FROM attack_chain_edges WHERE dst_node_id=? ORDER BY created_at LIMIT 1", (shared_node_id,))
            if not template:
                reasons.append("no template edge into the shared node; add an edge with explicit preconditions instead")
        if reasons:
            with self.store.tx():
                self._ledger(cid, "attack-chain", "reuse_refused", actor, node_id=shared_node_id, product_family=product_family, reasons=reasons)
            return {"accepted": False, "reasons": reasons, "product_node": None, "edge": None}
        assert template is not None
        descs = [p["description"] for p in self._chain_edge(template)["preconditions"]]
        with self.store.tx():
            entry = self.add_chain_node(cid, actor=actor, kind="entry_point", label=entry_label, scope="product", product_family=product_family)
            edge = self.add_chain_edge(cid, entry["id"], shared_node_id, actor=actor, relation=relation, preconditions=descs,
                                       evidence={"reused_shared_node": shared_node_id, "template_edge": template["id"]},
                                       _reused_from=template["id"])
            self._ledger(cid, "attack-chain", "reuse", actor, node_id=shared_node_id, product_family=product_family,
                         edge_id=edge["id"], template_edge_id=template["id"], note="shared component linked once; reachability candidate")
        return {"accepted": True, "reasons": [], "product_node": entry, "edge": edge}

    def attack_chain(self, cid: str, product_family: str | None = None) -> dict:
        nodes = [self._node(r) for r in self.store.all("SELECT * FROM attack_chain_nodes WHERE campaign_id=? ORDER BY created_at, id", (cid,))]
        edges = [self._chain_edge(r) for r in self.store.all("SELECT * FROM attack_chain_edges WHERE campaign_id=? ORDER BY created_at, id", (cid,))]
        if product_family:
            nodes = [n for n in nodes if n["scope"] == "shared" or n["product_family"] == product_family]
            edges = [e for e in edges if e["product_family"] == product_family]
        return {"product_family": product_family, "nodes": nodes, "edges": edges,
                "digest": sha256_text(dumps([(e["id"], e["status"]) for e in edges]))}
