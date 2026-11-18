"""Cross-firmware code lineage and knowledge reuse (addendum acceptance tests)."""
from __future__ import annotations

from refall_lite import RefallLite
from tests.helpers import check_receipt, good_result, members, model_finding, replay_receipt, sha
from tests.lineage_helpers import ALG, FUNCS, LineageCase, obs, strong_obs


class ExactContentTests(LineageCase):
    def test_exact_content_different_paths_images_one_unit_all_occurrences(self):
        cid = self.campaign()
        X = sha("libcrypto-same-bytes")
        self.lite.ingest_image(cid, family="router", name="r1", image_sha256=sha("r1"), actor="hermes", members=[
            {"path": "/usr/lib/libcrypto.so", "sha256": X},
            {"path": "/rescue/lib/libcrypto.so", "sha256": X, "container": "rescue.squashfs", "offset": 4096}])
        self.lite.ingest_image(cid, family="cam", name="c1", image_sha256=sha("c1"), actor="hermes", members=[
            {"path": "/lib/libcrypto.so.3", "sha256": X, "package": "openssl-3.0"}])
        u1 = self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=X, observations=[obs("soname", "libcrypto.so.3")])
        u2 = self.lite.register_code_unit(cid, X, actor="fp-tool")
        self.assertEqual(u1["unit_id"], u2["id"])
        self.assertEqual(len(self.lite.list_code_units(cid, content_sha256=X)), 1)
        view = self.lite.lineage(cid, X)
        self.assertEqual(view["tier0"]["occurrence_count"], 3)
        self.assertEqual(sorted(o["family"] for o in view["occurrences"]), ["cam", "router", "router"])
        rescue = next(o for o in view["occurrences"] if o["path"].startswith("/rescue"))
        self.assertEqual((rescue["container"], rescue["offset"]), ("rescue.squashfs", 4096))
        self.to_middle(cid)
        res = self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        self.assertEqual(res["enqueued"], 1)  # one content analysis unit


class LineageClusteringTests(LineageCase):
    def test_strong_multisignal_lineage_one_representative_plus_bounded_delta(self):
        cid = self.lineage_campaign(lineage={"max_delta_items": 5})
        fam_id, plan = self.to_deep_with_family(cid, drain_rep=False)
        fam = self.lite.get_family(fam_id)
        self.assertEqual(fam["status"], "approved")
        units = {self.unit(cid, c) for c in (self.A, self.B, self.C)}
        self.assertEqual({m["code_unit_id"] for m in fam["members"] if m["status"] == "approved"}, units)
        self.assertNotIn(self.unit(cid, self.U), {m["code_unit_id"] for m in fam["members"]})
        rep = fam["representative_unit_id"]
        self.assertIn(rep, units)
        self.assertTrue(fam["representative_rationale"])
        # before a representative receipt exists, only the representative is scheduled
        self.assertEqual(len(plan["representative_jobs"]), 1)
        self.assertEqual(plan["delta_jobs"], [])
        rep_job = self.lite.get_job(plan["representative_jobs"][0])
        self.assertEqual(rep_job["payload"]["lineage_role"], "representative")
        self.assertLess(rep_job["priority"], 100)  # shared across product families => prioritised
        claim = self.lite.claim_job(cid, worker="claude", stage="deep")
        self.lite.submit_result(cid, claim["job"]["id"], claim["job"]["claim_token"], good_result(summary="rep deep"))
        plan2 = self.lite.plan_lineage_work(cid, actor="hermes")
        self.assertEqual(len(plan2["delta_jobs"]), 2)
        for jid in plan2["delta_jobs"]:
            job = self.lite.get_job(jid)
            self.assertEqual(job["kind"], "delta-analysis")
            self.assertEqual(job["payload"]["family_id"], fam_id)
            self.assertTrue(job["payload"]["representative_receipt_id"])
            self.assertLessEqual(len(job["payload"]["delta_items"]), 5)
        self.assertEqual(self.lite.plan_lineage_work(cid, actor="hermes")["delta_jobs"], [])
        variant = next(c for c in (self.A, self.B, self.C) if self.unit(cid, c) != rep)
        refused = self.lite.select_for_deep(cid, variant, actor="hermes", reason="full repeat?")
        self.assertFalse(refused["accepted"])
        self.assertIn("delta", " ".join(refused["reasons"]))

    def test_similarity_edges_preserve_method_score_evidence_confidence_version(self):
        cid = self.lineage_campaign()
        self.fingerprint_all(cid)
        self.lite.run_lineage_pass(cid, actor="hermes")
        edges = self.lite.list_similarity_edges(cid)
        self.assertEqual(len(edges), 3)  # A-B, A-C, B-C ; U never paired into an edge
        for e in edges:
            self.assertEqual(e["algorithm_version"], ALG)
            self.assertEqual(e["method"], "lite-multisignal-v1")
            self.assertGreater(e["score"], 0.8)
            self.assertIn(e["confidence"], {"medium", "high"})
            self.assertTrue(e["policy_passed"])
            kinds = {s["kind"] for s in e["evidence"]["qualifying"]}
            self.assertTrue({"package_version", "function_hashes"} <= kinds)
            self.assertTrue(all(s["observation_ids"] for s in e["evidence"]["qualifying"]))
            self.assertNotIn("language", kinds)
            self.assertIn("language", {s["kind"] for s in e["evidence"]["metadata_only"]})

    def test_same_language_alone_never_clusters(self):
        cid = self.campaign()
        p, q = sha("p"), sha("q")
        self.lite.ingest_image(cid, family="f", name="i", image_sha256=sha("i"), actor="hermes",
                               members=[{"path": "/p", "sha256": p}, {"path": "/q", "sha256": q}])
        meta = [obs("language", "C"), obs("isa", "arm"), obs("compiler", "gcc-12"), obs("toolchain", "buildroot-2023"),
                obs("package_name", "busybox"), obs("file_type", "elf-exec")]
        self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=p, observations=meta)
        self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=q, observations=meta)
        res = self.lite.run_lineage_pass(cid, actor="hermes")
        self.assertEqual(res["edges_created"], 0)
        self.assertEqual(res["metadata_only_rejected"], 1)
        self.assertEqual(self.lite.list_families(cid), [])
        prop = self.lite.propose_cluster(cid, [self.unit(cid, p), self.unit(cid, q)], actor="hermes")
        self.assertFalse(prop["accepted"])
        cmp = self.lite.compare_units(cid, self.unit(cid, p), self.unit(cid, q), actor="hermes")
        self.assertIsNone(cmp["edge"])
        self.assertIn("metadata-only", " ".join(cmp["evaluation"]["reasons"]))
        events = [e for e in self.lite.ledger(cid, "lineage") if e["action"] == "pass"]
        self.assertEqual(events[-1]["payload"]["metadata_only_rejected"], 1)

    def test_single_fuzzy_signal_never_auto_approved(self):
        cid = self.campaign(lineage={"auto_approve": True})
        p, q = sha("p"), sha("q")
        self.lite.ingest_image(cid, family="f", name="i", image_sha256=sha("i"), actor="hermes",
                               members=[{"path": "/p", "sha256": p}, {"path": "/q", "sha256": q}])
        self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=p, observations=[obs("function_hashes", FUNCS)])
        self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=q, observations=[obs("function_hashes", FUNCS[:19] + ["x"])])
        res = self.lite.run_lineage_pass(cid, actor="hermes")
        self.assertEqual(res["edges_created"], 1)
        self.assertEqual(res["families_auto_approved"], [])
        edge = self.lite.list_similarity_edges(cid)[0]
        self.assertEqual(edge["status"], "candidate")
        self.assertFalse(edge["policy_passed"])
        self.assertGreater(edge["score"], 0.85)  # high fuzzy score is still not proof
        self.assertFalse(self.lite.approve_edge(cid, edge["id"], actor="hermes", receipt_type=None, receipt={})["accepted"])
        self.assertFalse(self.lite.propose_cluster(cid, [edge["unit_a"], edge["unit_b"]], actor="hermes")["accepted"])
        # false candidate is rejected explicitly and audibly
        rej = self.lite.reject_edge(cid, edge["id"], actor="hermes", receipt_type="lineage_review",
                                    receipt={"evidence_refs": ["only function-hash overlap"], "summary": "insufficient"})
        self.assertTrue(rej["accepted"])
        self.assertEqual(self.lite.list_similarity_edges(cid)[0]["status"], "rejected")

    def test_two_fuzzy_signals_without_exact_anchor_or_model_sourced_signals_do_not_pass(self):
        cid = self.campaign(lineage={"auto_approve": True})
        p, q, r, s = sha("p"), sha("q"), sha("r"), sha("s")
        self.lite.ingest_image(cid, family="f", name="i", image_sha256=sha("i"), actor="hermes",
                               members=[{"path": f"/{n}", "sha256": h} for n, h in zip("pqrs", (p, q, r, s))])
        two_fuzzy = [obs("function_hashes", FUNCS), obs("strings_constants", ["a", "b", "c", "d", "e"])]
        self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=p, observations=two_fuzzy)
        self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=q, observations=two_fuzzy)
        # strong-looking evidence, but produced by a model worker: candidate generation only
        self.lite.ingest_fingerprints(cid, actor="qwen", content_sha256=r, observations=strong_obs("r"))
        self.lite.ingest_fingerprints(cid, actor="qwen", content_sha256=s, observations=strong_obs("s"))
        self.lite.run_lineage_pass(cid, actor="hermes")
        self.assertEqual(self.lite.list_families(cid), [])
        for e in self.lite.list_similarity_edges(cid):
            self.assertFalse(e["policy_passed"], e["evidence"])

    def test_human_can_override_below_threshold_only_with_receipt(self):
        cid = self.campaign()
        p, q = sha("p"), sha("q")
        self.lite.ingest_image(cid, family="f", name="i", image_sha256=sha("i"), actor="hermes",
                               members=[{"path": "/p", "sha256": p}, {"path": "/q", "sha256": q}])
        for c in (p, q):
            self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=c, observations=[obs("function_hashes", FUNCS)])
        self.lite.run_lineage_pass(cid, actor="hermes")
        edge = self.lite.list_similarity_edges(cid)[0]
        self.assertFalse(self.lite.approve_edge(cid, edge["id"], actor="analyst", receipt_type=None, receipt={})["accepted"])
        ok = self.lite.approve_edge(cid, edge["id"], actor="analyst", receipt_type="human_lineage_review",
                                    receipt={"evidence_refs": ["manual diff of sources"], "summary": "same code, rebuilt"})
        self.assertTrue(ok["accepted"])
        self.assertTrue(ok["edge"]["override"])

    def test_late_variant_extends_family_and_new_image_exact_copy_inherits(self):
        cid = self.lineage_campaign(lineage={"auto_approve": True})
        self.fingerprint_all(cid)
        first = self.lite.run_lineage_pass(cid, actor="hermes")
        fam = first["families_auto_approved"][0]
        D = sha("httpd-buildD")
        self.lite.ingest_image(cid, family="nas", name="n-1", image_sha256=sha("n-1"), actor="hermes",
                               members=[{"path": "/sbin/httpd", "sha256": D}, {"path": "/opt/httpd", "sha256": self.A}])
        self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=D, observations=strong_obs("D", func_drop=1))
        second = self.lite.run_lineage_pass(cid, actor="hermes")
        self.assertEqual(second["families_extended"], [fam])
        self.assertIn(self.unit(cid, D), {m["code_unit_id"] for m in self.lite.get_family(fam)["members"]})
        self.assertIn("nas", self.lite.get_family(fam)["product_families"])


class StalenessTests(LineageCase):
    def test_algorithm_version_change_stales_reuse_and_cannot_skip_work(self):
        cid = self.lineage_campaign()
        fam_id, _ = self.to_deep_with_family(cid)
        deltas = self.lite.plan_lineage_work(cid, actor="hermes")["delta_jobs"]
        self.assertEqual(len(deltas), 2)
        res = self.lite.set_fingerprint_algorithm(cid, "lite-fp-v2", actor="hermes", reason="new function hasher")
        self.assertEqual(res["stale_families"], [fam_id])
        self.assertEqual(res["stale_edges"], 3)
        self.assertEqual(sorted(res["cancelled_delta_jobs"]), sorted(deltas))
        self.assertEqual(self.lite.get_family(fam_id)["status"], "stale")
        self.assertTrue(all(e["status"] == "stale" for e in self.lite.list_similarity_edges(cid)))
        self.assertEqual(self.lite.plan_lineage_work(cid, actor="hermes")["delta_jobs"], [])
        rep = self.lite.get_family(fam_id)["representative_unit_id"]
        variant = next(c for c in (self.A, self.B, self.C) if self.unit(cid, c) != rep)
        full = self.lite.select_for_deep(cid, variant, actor="hermes", reason="lineage stale; full analysis")
        self.assertTrue(full["accepted"], full)
        with self.assertRaises(ValueError):
            self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=self.A,
                                          observations=[obs("build_id", "abc", algorithm_version=ALG)])
        self.assertEqual(self.lite.get_campaign(cid)["config"]["lineage"]["algorithm_version"], "lite-fp-v2")
        with self.assertRaises(PermissionError):
            self.lite.set_fingerprint_algorithm(cid, "lite-fp-v3", actor="qwen", reason="x")

    def test_deep_requires_current_lineage_pass_once_fingerprints_exist(self):
        cid = self.lineage_campaign()
        self.to_middle(cid)
        self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        self.drain(cid, "middle")
        self.fingerprint_all(cid)
        gate = self.lite.advance_stage(cid, actor="hermes")
        self.assertFalse(gate["advanced"])
        self.assertIn("lineage pass", " ".join(gate["reasons"]))
        self.lite.run_lineage_pass(cid, actor="hermes")
        self.assertFalse(self.lite.advance_stage(cid, actor="hermes")["advanced"])  # proposed family awaits review
        fam = self.lite.list_families(cid)[0]["id"]
        self.assertTrue(self.lite.reject_cluster(cid, fam, actor="hermes", receipt_type="lineage_review",
                                                 receipt={"evidence_refs": ["operator disagrees"]})["accepted"])
        self.assertTrue(self.lite.advance_stage(cid, actor="hermes")["advanced"])


class ApplicabilityTests(LineageCase):
    def _validated_finding_on_rep(self, cid, fam_id):
        rep = self.lite.get_family(fam_id)["representative_unit_id"]
        rep_sha = self.lite.get_code_unit(rep)["content_sha256"]
        fid = self.lite.record_finding(cid, actor="claude", candidate=model_finding(rep_sha, title="Auth bypass in parse_auth"))["finding"]["id"]
        self.lite.transition_finding(cid, fid, actor="checker", to="independently_checked", receipt_type="independent_check", receipt=check_receipt())
        self.lite.transition_finding(cid, fid, actor="replayer", to="validated", receipt_type="deterministic_replay", receipt=replay_receipt())
        return fid, rep_sha

    def test_finding_is_candidate_on_variants_until_gates_pass(self):
        cid = self.lineage_campaign()
        fam_id, _ = self.to_deep_with_family(cid)
        fid, rep_sha = self._validated_finding_on_rep(cid, fam_id)
        prop = self.lite.propagate_finding(cid, fid, actor="hermes")
        rows = self.lite.list_applicability(cid, finding_id=fid)
        self.assertEqual(len(rows), 3)  # one occurrence each for A, B, C
        self.assertTrue(all(r["state"] == "candidate_applicable" for r in rows))
        self.assertTrue(all(not r["validated_on_target"] for r in rows))
        self.assertEqual(prop["created"], 3)
        self.assertEqual(self.lite.propagate_finding(cid, fid, actor="hermes")["created"], 0)
        origin = next(r for r in rows if r["content_sha256"] == rep_sha)
        self.assertEqual(origin["derived_via"], "exact")
        self.assertEqual(origin["checks"]["code_path"]["status"], "passed")  # invariant under exact bytes
        variants = [r for r in rows if r["content_sha256"] != rep_sha]
        self.assertTrue(all(r["derived_via"] == "lineage" for r in variants))
        self.assertTrue(all(r["checks"]["code_path"]["status"] == "pending" for r in variants))
        self.assertEqual(len(self.lite.list_findings(cid)), 1)  # never duplicate the finding record
        self.lite.draft_report(cid, actor="hermes")
        gate = self.lite.closeout_gate(cid)
        self.assertIn("applicability-unresolved", gate["blockers"])
        b, c = variants
        # model actors cannot pass gates
        self.assertFalse(self.lite.record_applicability_check(cid, b["id"], gate="code_path", status="passed", actor="qwen",
                                                              receipt={"evidence_refs": ["trust me"]})["accepted"])
        for g in ("code_path", "version_constraints", "configuration", "exposure"):
            res = self.lite.record_applicability_check(cid, b["id"], gate=g, status="passed", actor="checker",
                                                       receipt={"commands": [f"synthetic check {g}"], "evidence_refs": ["delta-receipt"]})
            self.assertTrue(res["accepted"], res)
            self.assertEqual(res["row"]["state"], "candidate_applicable")
        done = self.lite.record_applicability_check(cid, b["id"], gate="preconditions", status="passed", actor="checker",
                                                    receipt={"commands": ["synthetic precondition check"]})
        self.assertEqual(done["row"]["state"], "applicable")
        self.assertTrue(done["row"]["validated_on_target"])
        # C: code path absent -> explicit negative state; does not generalise to B
        self.lite.record_applicability_check(cid, c["id"], gate="code_path", status="failed", actor="checker",
                                             receipt={"commands": ["synthetic delta: parse_auth rewritten"]})
        bad = self.lite.decide_applicability(cid, c["id"], state="unreachable", actor="checker", receipt_type="applicability_check",
                                             receipt={"evidence_refs": ["x"]})
        self.assertFalse(bad["accepted"])  # unreachable needs an exposure/precondition failure
        neg = self.lite.decide_applicability(cid, c["id"], state="not_present", actor="checker", receipt_type="applicability_check",
                                             receipt={"evidence_refs": ["delta shows rewrite"]})
        self.assertTrue(neg["accepted"], neg)
        self.assertEqual(self.lite.list_applicability(cid, finding_id=fid, state="applicable")[0]["id"], b["id"])
        for g in ("configuration", "exposure", "preconditions"):
            self.lite.record_applicability_check(cid, origin["id"], gate=g, status="passed", actor="checker", receipt={"commands": ["c"]})
        self.lite.draft_report(cid, actor="hermes")
        self.assertNotIn("applicability-unresolved", self.lite.closeout_gate(cid)["blockers"])

    def test_variant_finding_from_worker_attaches_to_canonical_finding(self):
        cid = self.lineage_campaign()
        fam_id, _ = self.to_deep_with_family(cid)
        fid, rep_sha = self._validated_finding_on_rep(cid, fam_id)
        other = next(c for c in (self.A, self.B, self.C) if c != rep_sha)
        res = self.lite.record_finding(cid, actor="qwen", candidate=model_finding(other, title="Auth bypass in parse_auth"))
        self.assertEqual(res["finding"]["id"], fid)
        self.assertTrue(res["merged"])
        self.assertEqual(len(self.lite.list_findings(cid)), 1)
        row = next(r for r in self.lite.list_applicability(cid, finding_id=fid) if r["content_sha256"] == other)
        self.assertEqual(row["state"], "candidate_applicable")
        self.assertEqual(self.lite.get_finding(fid)["tier"], "validated")

    def test_negative_result_reuse_requires_code_and_config_equivalence(self):
        cid = self.lineage_campaign()
        neg = good_result(summary="upload handler: no injection", checked_scope=["fn:upload_handler", "config:httpd.conf"],
                          checked_digests={"code:upload_handler": sha("uh-v1"), "config:httpd.conf": sha("conf-v1")})
        fam_id, _ = self.to_deep_with_family(cid, rep_result=neg)
        rep = self.lite.get_family(fam_id)["representative_unit_id"]
        receipt = [r for r in self.lite.list_analysis_receipts(cid, unit_id=rep) if r["outcome"] == "negative" and r["analysis_kind"] == "full"][0]
        b, c = [self.unit(cid, x) for x in (self.A, self.B, self.C) if self.unit(cid, x) != rep]
        bsha, csha = self.lite.get_code_unit(b)["content_sha256"], self.lite.get_code_unit(c)["content_sha256"]
        # no equivalence evidence at all: refused even though B is in the same approved family
        none = self.lite.reuse_negative_result(cid, receipt["id"], b, actor="hermes")
        self.assertFalse(none["accepted"])
        self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=bsha, observations=[
            obs("scoped_digest", {"scope": "code:upload_handler", "digest": sha("uh-v1")}),
            obs("scoped_digest", {"scope": "config:httpd.conf", "digest": sha("conf-v2")})])
        partial = self.lite.reuse_negative_result(cid, receipt["id"], b, actor="hermes")
        self.assertFalse(partial["accepted"])
        self.assertIn("config:httpd.conf", " ".join(partial["reasons"]))
        self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=csha, observations=[
            obs("scoped_digest", {"scope": "code:upload_handler", "digest": sha("uh-v1")}),
            obs("scoped_digest", {"scope": "config:httpd.conf", "digest": sha("conf-v1")})])
        ok = self.lite.reuse_negative_result(cid, receipt["id"], c, actor="hermes")
        self.assertTrue(ok["accepted"], ok)
        self.assertEqual(ok["reuse"]["kind"], "negative_result")
        self.assertEqual(ok["reuse"]["basis"]["matched_scopes"], ["code:upload_handler", "config:httpd.conf"])
        with self.assertRaises(PermissionError):
            self.lite.reuse_negative_result(cid, receipt["id"], c, actor="qwen")


class AttackChainTests(LineageCase):
    def test_shared_node_reused_while_reachability_stays_product_specific(self):
        cid = self.lineage_campaign()
        fam_id, _ = self.to_deep_with_family(cid)
        shared = self.lite.add_chain_node(cid, actor="hermes", kind="component_weakness", label="parse_auth bypass",
                                          scope="shared", family_id=fam_id, evidence={"refs": ["finding"]})
        again = self.lite.add_chain_node(cid, actor="hermes", kind="component_weakness", label="parse_auth bypass",
                                         scope="shared", family_id=fam_id)
        self.assertEqual(shared["id"], again["id"])  # linked once
        router = self.lite.add_chain_node(cid, actor="hermes", kind="entry_point", label="WAN http", scope="product", product_family="router")
        edge = self.lite.add_chain_edge(cid, router["id"], shared["id"], actor="hermes", relation="reaches",
                                        preconditions=["httpd bound to WAN interface", "auth endpoint enabled"])
        self.assertEqual(edge["status"], "candidate")
        pre = edge["preconditions"]
        self.assertFalse(self.lite.check_precondition(cid, pre[0]["id"], state="satisfied", actor="qwen", receipt={"evidence_refs": ["x"]})["accepted"])
        self.lite.check_precondition(cid, pre[0]["id"], state="satisfied", actor="checker", receipt={"commands": ["synthetic netstat"]})
        res = self.lite.check_precondition(cid, pre[1]["id"], state="satisfied", actor="checker", receipt={"commands": ["synthetic cfg"]})
        self.assertEqual(res["edge"]["status"], "confirmed")
        reuse = self.lite.reuse_chain_node(cid, shared["id"], product_family="cam", actor="hermes", entry_label="LAN http",
                                           template_edge_id=edge["id"])
        self.assertTrue(reuse["accepted"], reuse)
        cam_edge = reuse["edge"]
        self.assertEqual(cam_edge["status"], "candidate")
        self.assertEqual([p["state"] for p in cam_edge["preconditions"]], ["unknown", "unknown"])
        self.assertEqual(cam_edge["dst_node_id"], shared["id"])
        self.lite.check_precondition(cid, cam_edge["preconditions"][0]["id"], state="unsatisfied", actor="checker", receipt={"commands": ["lan only"]})
        cam = self.lite.attack_chain(cid, product_family="cam")
        self.assertEqual(next(e for e in cam["edges"] if e["id"] == cam_edge["id"])["status"], "refuted")
        router_view = self.lite.attack_chain(cid, product_family="router")
        self.assertEqual(next(e for e in router_view["edges"] if e["id"] == edge["id"])["status"], "confirmed")
        self.assertEqual(len([n for n in self.lite.attack_chain(cid)["nodes"] if n["scope"] == "shared"]), 1)
        nope = self.lite.reuse_chain_node(cid, shared["id"], product_family="toaster", actor="hermes", entry_label="x")
        self.assertFalse(nope["accepted"])


class DurabilityTests(LineageCase):
    def test_reopen_preserves_clusters_mappings_receipts_applicability_and_invalidation(self):
        cid = self.lineage_campaign()
        fam_id, _ = self.to_deep_with_family(cid)
        deltas = self.lite.plan_lineage_work(cid, actor="hermes")["delta_jobs"]
        rep = self.lite.get_family(fam_id)["representative_unit_id"]
        rep_sha = self.lite.get_code_unit(rep)["content_sha256"]
        fid = self.lite.record_finding(cid, actor="claude", candidate=model_finding(rep_sha))["finding"]["id"]
        self.lite.propagate_finding(cid, fid, actor="hermes")
        row = self.lite.list_applicability(cid, finding_id=fid)[0]
        self.lite.record_applicability_check(cid, row["id"], gate="exposure", status="passed", actor="checker", receipt={"commands": ["c"]})
        before = (self.lite.get_family(fam_id), self.lite.list_similarity_edges(cid), self.lite.list_analysis_receipts(cid),
                  self.lite.list_applicability(cid))
        self.reopen()
        after = (self.lite.get_family(fam_id), self.lite.list_similarity_edges(cid), self.lite.list_analysis_receipts(cid),
                 self.lite.list_applicability(cid))
        self.assertEqual(before, after)
        self.assertEqual(sorted(j["id"] for j in self.lite.list_delta_jobs(cid)), sorted(deltas))
        self.lite.set_fingerprint_algorithm(cid, "lite-fp-v2", actor="hermes", reason="upgrade")
        self.reopen()
        self.assertEqual(self.lite.get_family(fam_id)["status"], "stale")
        self.assertTrue(all(r["stale"] for r in self.lite.list_applicability(cid) if r["derived_via"] == "lineage"))
        self.assertTrue(self.lite.verify_ledger(cid)["ok"])

    def test_concurrent_idempotent_ingestion_no_duplicate_edges_clusters_or_deltas(self):
        cid = self.lineage_campaign(lineage={"auto_approve": True})
        self.to_middle(cid)
        self.lite.enqueue_member_jobs(cid, stage="middle", kind="triage", actor="hermes")
        self.drain(cid, "middle")
        other = RefallLite(self.db, clock=self.clock)
        try:
            for inst in (self.lite, other, self.lite):
                for content, o in ((self.A, strong_obs("A")), (self.B, strong_obs("B", func_drop=1))):
                    inst.ingest_fingerprints(cid, actor="fp-tool", content_sha256=content, observations=o)
            self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=self.C, observations=strong_obs("C", func_drop=1, extra_funcs=("fnC1",)))
            for inst in (self.lite, other):
                inst.run_lineage_pass(cid, actor="hermes")
            self.assertTrue(self.lite.advance_stage(cid, actor="hermes")["advanced"])
            for inst in (self.lite, other):
                inst.plan_lineage_work(cid, actor="hermes")
            job = self.lite.claim_job(cid, worker="claude", stage="deep")["job"]
            self.lite.submit_result(cid, job["id"], job["claim_token"], good_result())
            for inst in (other, self.lite, other):
                inst.plan_lineage_work(cid, actor="hermes")
            n_obs = other.store.scalar("SELECT COUNT(*) FROM fingerprint_observations WHERE campaign_id=?", (cid,))
        finally:
            other.close()
        self.assertEqual(n_obs, 3 * len(strong_obs("A")))
        self.assertEqual(len(self.lite.list_similarity_edges(cid)), 3)
        self.assertEqual(len(self.lite.list_families(cid)), 1)
        self.assertEqual(len(self.lite.list_delta_jobs(cid)), 2)
        self.assertEqual(len(self.lite.list_jobs(cid, stage="deep")), 3)

    def test_budgets_retry_and_closeout_still_control_lineage_jobs(self):
        cid = self.lineage_campaign(budgets={"stage:deep": {"max_claims": 2, "max_cost": 100}}, max_attempts=1)
        fam_id, _ = self.to_deep_with_family(cid)  # rep claim uses 1 of 2 deep claims
        deltas = self.lite.plan_lineage_work(cid, actor="hermes")["delta_jobs"]
        job = self.lite.claim_job(cid, worker="qwen", stage="deep")["job"]
        self.assertIn(job["id"], deltas)
        out = self.lite.fail_job(cid, job["id"], job["claim_token"], status="provider_timeout", error="x")
        self.assertEqual(out["outcome"]["state"], "dead")  # retry ceiling applies to delta jobs
        res = self.lite.claim_job(cid, worker="qwen", stage="deep")
        self.assertFalse(res["claimed"])  # stage:deep budget exhausted
        self.assertEqual(self.lite.status(cid)["jobs"].get("budget_blocked"), 1)
        self.lite.draft_report(cid, actor="hermes")
        blockers = self.lite.closeout_gate(cid)["blockers"]
        self.assertIn("jobs-unresolved", blockers)
        self.assertIn("pending-actions-open", blockers)

    def test_max_jobs_ceiling_bounds_delta_enqueue(self):
        cid = self.lineage_campaign(max_jobs=10)  # 3 inventory + 5 middle + 1 rep + 1 delta (of 2)
        self.to_deep_with_family(cid)
        plan = self.lite.plan_lineage_work(cid, actor="hermes")
        self.assertEqual(len(plan["delta_jobs"]), 1)
        self.assertEqual(len(plan["refused"]), 1)


class RoleLabelTests(LineageCase):
    def test_behavioral_role_label_plus_one_lineage_signal_does_not_cluster(self):
        cid = self.campaign(lineage={"auto_approve": True})
        p, q = sha("p"), sha("q")
        self.lite.ingest_image(cid, family="f", name="i", image_sha256=sha("i"), actor="hermes",
                               members=[{"path": "/p", "sha256": p}, {"path": "/q", "sha256": q}])
        for c in (p, q):
            self.lite.ingest_fingerprints(cid, actor="fp-tool", content_sha256=c, observations=[
                obs("behavioral_role", "web_handler"), obs("package_version", "acme-httpd@3.2"),
                obs("source_paths", ["src/a.c", "src/b.c"])])
        self.lite.run_lineage_pass(cid, actor="hermes")
        self.assertEqual(self.lite.list_families(cid), [])
        edge = self.lite.list_similarity_edges(cid)[0]
        self.assertFalse(edge["policy_passed"])
        self.assertIn("behavioral_role", {s["kind"] for s in edge["evidence"]["metadata_only"]})
