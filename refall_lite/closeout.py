"""Report state and closeout gate (adapted from ArcticBase ``closeout_gate.py``).

Check shape: {id, status: pass|fail|warn|not_applicable, count, blocking, details}.
Closeout passes only when no blocking check fails. Lite has no override path.
"""
from __future__ import annotations

from typing import Any

from ._base import Base
from .arcticbase.contracts import JOB_UNRESOLVED, REPORT_NEUTRAL_KINDS, TIERS, canonical_json, sha256_text, stable_id
from .arcticbase.store import dumps, loads, new_id

NOTICE = ("REFALL Lite campaign report (ArcticBase REFALL state layer, lite profile). Findings below tier 'validated' are "
          "provisional hypotheses. Contents reflect only metadata and evidence submitted to this campaign; if inputs were "
          "synthetic, no real firmware was analyzed.")


def _check(cid: str, passed: bool, blocking: bool, details: list) -> dict:
    return {"id": cid, "status": "pass" if passed else ("fail" if blocking else "warn"),
            "count": 0 if passed else len(details), "blocking": blocking, "details": details}


class CloseoutMixin(Base):
    def _material(self, cid: str) -> set[str]:
        return {s.lower() for s in self.get_campaign(cid)["config"].get("material_severities") or []}

    # -- report --------------------------------------------------------------
    def draft_report(self, cid: str, *, actor: str) -> dict:
        self._require_operator(actor, "draft reports")
        camp = self.get_campaign(cid)
        material = self._material(cid)
        with self.store.tx():
            watermark = self.store.ledger_watermark(cid)
            grouped: dict[str, list] = {t: [] for t in [*TIERS, "rejected", "duplicate", "known_cve"]}
            for f in self.list_findings(cid):
                occ = self.finding_occurrences(f["id"])
                grouped[f["tier"]].append({
                    "id": f["id"], "title": f["title"], "severity": f["severity"], "vuln_class": f["vuln_class"],
                    "tier": f["tier"], "provisional": f["tier"] != "validated", "material": f["severity"] in material,
                    "member_sha256": f["member_sha256"], "origin_kind": f["origin_kind"],
                    "occurrences": [{k: o[k] for k in ("image_name", "family", "path")} for o in occ],
                    "families": sorted({o["family"] for o in occ}),
                    "source_anchors": f.get("source_anchors", []), "artifact_refs": f.get("artifact_refs", []),
                    "limitations": f.get("limitations", []),
                    "receipts": [{"receipt_type": r["receipt_type"], "actor": r["actor"]} for r in f["receipts"]],
                    "duplicate_of": f["duplicate_of"],
                })
            st = self.status(cid)
            content = {
                "notice": NOTICE,
                "campaign": {"id": cid, "name": camp["name"], "stage": camp["current_stage"], "status": camp["status"],
                             "stop_reason": camp["stop_reason"]},
                "fleet": {"images": st["images"], "families": st["families"], "unique_members": st["unique_members"],
                          "member_occurrences": st["member_occurrences"]},
                "jobs": st["jobs_by_stage"],
                "budgets": st["budgets"],
                "findings": grouped,
                "pending_open": [{"id": a["id"], "kind": a["kind"], "title": a["title"]} for a in self.list_pending_actions(cid)],
                "lineage": self._lineage_report(cid),
                "ledger_watermark": watermark,
            }
            digest = sha256_text(canonical_json(content))
            rid = new_id("rep")
            self.store.conn.execute(
                "INSERT INTO reports(id,campaign_id,ledger_watermark,content,content_sha256,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                (rid, cid, watermark, dumps(content), digest, actor, self.store.now()))
            self._ledger(cid, "report", "draft", actor, report_id=rid, content_sha256=digest, ledger_watermark=watermark)
        return {"id": rid, "content": content, "content_sha256": digest, "ledger_watermark": watermark}

    def get_report(self, cid: str) -> dict | None:
        row = self.store.one("SELECT * FROM reports WHERE campaign_id=? ORDER BY ledger_watermark DESC, created_at DESC, rowid DESC LIMIT 1", (cid,))
        if not row:
            return None
        return {"id": row["id"], "content": loads(row["content"], {}), "content_sha256": row["content_sha256"],
                "ledger_watermark": row["ledger_watermark"]}

    # -- gate ----------------------------------------------------------------
    def closeout_gate(self, cid: str) -> dict:
        camp = self.get_campaign(cid)
        material = self._material(cid)
        checks: list[dict[str, Any]] = []
        marks = ",".join("?" * len(JOB_UNRESOLVED))
        unresolved = [f"{r['id']}:{r['status']}" for r in self.store.all(
            f"SELECT id,status FROM jobs WHERE campaign_id=? AND status IN ({marks}) ORDER BY seq", (cid, *sorted(JOB_UNRESOLVED)))]
        checks.append(_check("jobs-unresolved", not unresolved, True, unresolved))
        open_pending = [f"{a['id']}:{a['kind']}" for a in self.list_pending_actions(cid)]
        checks.append(_check("pending-actions-open", not open_pending, True, open_pending))
        findings = self.list_findings(cid)
        unvalidated = [f["id"] for f in findings if f["severity"] in material and f["tier"] in {"hypothesis", "independently_checked"}]
        checks.append(_check("material-findings-unvalidated", not unvalidated, True, unvalidated))
        bad_valid = [f["id"] for f in findings if f["tier"] == "validated" and not any(
            r["receipt_type"] == "deterministic_replay" for r in f["receipts"])]
        checks.append(_check("validated-without-replay", not bad_valid, True, bad_valid))
        checks.append(_check("manifest-present", self.get_manifest(cid) is not None, True, [] if self.get_manifest(cid) else ["missing"]))
        report = self.get_report(cid)
        if not report:
            checks.append(_check("report-current", False, True, ["missing"]))
        else:
            stale = self.store.scalar(
                f"SELECT COUNT(*) FROM ledger WHERE campaign_id=? AND seq>? AND kind NOT IN ({','.join('?' * len(REPORT_NEUTRAL_KINDS))})",
                (cid, report["ledger_watermark"], *sorted(REPORT_NEUTRAL_KINDS)))
            checks.append(_check("report-current", not stale, True, [f"stale: {stale} state changes since report {report['id']}"] if stale else []))
        ledger = self.store.verify_ledger(cid)
        checks.append(_check("ledger-integrity", ledger["ok"], True, [] if ledger["ok"] else [f"bad seq {ledger.get('bad_seq')}"]))
        checks.extend(self._lineage_closeout_checks(cid, material, findings))
        # non-blocking
        low = [f["id"] for f in findings if f["severity"] not in material and f["tier"] in {"hypothesis", "independently_checked"}]
        checks.append(_check("non-material-hypotheses", not low, False, low))
        refused = [t["id"] for t in self.list_transitions(cid) if t["status"] == "refused"]
        checks.append(_check("refused-transitions", not refused, False, refused))
        checks.append(_check("campaign-stopped", camp["status"] != "stopped", False,
                             [camp["stop_reason"]] if camp["status"] == "stopped" else []))
        total = self.store.scalar("SELECT COUNT(*) FROM members WHERE campaign_id=?", (cid,)) or 0
        covered = self.store.scalar("SELECT COUNT(DISTINCT target_ref) FROM jobs WHERE campaign_id=? AND stage='middle' AND status='succeeded'", (cid,))
        checks.append(_check("middle-coverage", not total or covered >= total, False, [f"{covered}/{total} unique members"] if total and covered < total else []))
        blockers = [c["id"] for c in checks if c["blocking"] and c["status"] == "fail"]
        return {"campaign_id": cid, "passed": not blockers, "blockers": blockers, "checks": checks,
                "summary": {"findings": len(findings), "unvalidated_material": len(unvalidated), "unresolved_jobs": len(unresolved),
                            "pending_open": len(open_pending), "ledger_entries": ledger["entries"]}}

    # -- lineage / reuse ------------------------------------------------------
    def _lineage_closeout_checks(self, cid: str, material: set[str], findings: list[dict]) -> list[dict]:
        sev = {f["id"]: f["severity"] for f in findings}
        rows = self.list_applicability(cid)
        cand_mat = [r["id"] for r in rows if r["state"] == "candidate_applicable" and sev.get(r["finding_id"]) in material]
        cand_low = [r["id"] for r in rows if r["state"] == "candidate_applicable" and sev.get(r["finding_id"]) not in material]
        unknown = [r["id"] for r in rows if r["state"] == "unknown"]
        stale_rows = [r["id"] for r in rows if r["stale"]]
        chain = self.attack_chain(cid)
        cand_edges = [e["id"] for e in chain["edges"] if e["status"] == "candidate"]
        stale_f = [f["id"] for f in self.list_families(cid, status="stale")]
        stale_e = len(self.list_similarity_edges(cid, status="stale"))
        return [
            _check("applicability-unresolved", not cand_mat, True, cand_mat),
            _check("applicability-unresolved-nonmaterial", not cand_low, False, cand_low),
            _check("applicability-unknown", not unknown, False, unknown),
            _check("applicability-stale", not stale_rows, False, stale_rows),
            _check("attack-chain-candidate-edges", not cand_edges, False, cand_edges),
            _check("lineage-stale", not (stale_f or stale_e), False, stale_f + ([f"{stale_e} stale similarity edges"] if stale_e else [])),
        ]

    def _lineage_report(self, cid: str) -> dict:
        fams = []
        for f in self.list_families(cid):
            fams.append({"id": f["id"], "status": f["status"], "algorithm_version": f["algorithm_version"],
                         "representative_unit_id": f["representative_unit_id"], "product_families": f["product_families"],
                         "members": [{"code_unit_id": m["code_unit_id"], "status": m["status"],
                                      "content_sha256": self.get_code_unit(m["code_unit_id"])["content_sha256"]} for m in f["members"]]})
        app: dict[str, list] = {}
        for r in self.list_applicability(cid):
            app.setdefault(r["finding_id"], []).append({
                "image_id": r["image_id"], "path": r["path"], "product_family": r["product_family"], "derived_via": r["derived_via"],
                "state": r["state"], "candidate_only": r["state"] == "candidate_applicable", "stale": r["stale"],
                "validated_on_target": r["validated_on_target"],
                "gates": {g: c.get("status") for g, c in r["checks"].items()}})
        chain = self.attack_chain(cid)
        return {
            "fingerprint_algorithm_version": self.lineage_config(cid)["algorithm_version"],
            "families": fams,
            "delta_receipts": [{k: d[k] for k in ("job_id", "family_id", "variant_unit_id", "outcome")} for d in self.list_delta_receipts(cid)],
            "reuse": [{k: r[k] for k in ("kind", "source_receipt_id", "target_unit_id", "algorithm_version", "stale")} for r in self.list_reuse(cid)],
            "applicability": app,
            "attack_chain": {
                "nodes": [{k: n[k] for k in ("id", "kind", "label", "scope", "family_id", "product_family", "status")} for n in chain["nodes"]],
                "edges": [{"id": e["id"], "src": e["src_node_id"], "dst": e["dst_node_id"], "product_family": e["product_family"],
                           "status": e["status"], "candidate_only": e["status"] == "candidate",
                           "preconditions": [{"description": p["description"], "state": p["state"]} for p in e["preconditions"]]}
                          for e in chain["edges"]],
            },
        }

    def closeout(self, cid: str, *, actor: str) -> dict:
        """Evaluate the gate, persist a CloseoutPackage, close the campaign only if it passed."""
        self._require_operator(actor, "close out campaigns")
        with self.store.tx():
            gate = self.closeout_gate(cid)
            manifest = self.get_manifest(cid) or {}
            report = self.get_report(cid) or {}
            pkg = {
                "closeout_id": stable_id("closeout", {"campaign_id": cid, "manifest_id": manifest.get("manifest_id"),
                                                      "report_sha256": report.get("content_sha256"), "checks": gate["checks"]}),
                "campaign_id": cid, "manifest_id": manifest.get("manifest_id"), "report_id": report.get("id"),
                "report_sha256": report.get("content_sha256"), "passed": gate["passed"], "blockers": gate["blockers"],
                "checks": gate["checks"], "created_at": self.store.now(),
            }
            self.store.conn.execute("INSERT INTO closeouts(id,campaign_id,passed,payload,created_by,created_at) VALUES(?,?,?,?,?,?)",
                                    (new_id("co"), cid, int(gate["passed"]), dumps(pkg), actor, pkg["created_at"]))
            self._ledger(cid, "closeout-gate", "pass" if gate["passed"] else "blocked", actor,
                         closeout_id=pkg["closeout_id"], blockers=gate["blockers"])
            if gate["passed"]:
                self.store.conn.execute("UPDATE campaigns SET status='closed', updated_at=? WHERE id=?", (self.store.now(), cid))
        return pkg

    def get_closeout(self, cid: str) -> dict | None:
        row = self.store.one("SELECT payload FROM closeouts WHERE campaign_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1", (cid,))
        return loads(row["payload"], None) if row else None
