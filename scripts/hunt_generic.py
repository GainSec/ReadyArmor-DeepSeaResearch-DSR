#!/usr/bin/env python3
"""Generic single-target DSR hunt: one file, one fresh campaign DB, one OpenCode+REA hunt.

Target-agnostic; everything about the subject comes from the environment:

  DSR_ROOT             directory the hunter works in (also the OpenCode workdir)
  DSR_MEMBER           path of the target file, relative to DSR_ROOT
  DSR_FAMILY           label for the campaign (``hunt-<family>``)
  DSR_DB               campaign database path; REMOVED and recreated on every run
  DSR_PRIORITIES_FILE  text file whose content replaces the default hunt priorities
  DSR_TIMEOUT_S        hunt budget in seconds (default 10800)
  DSR_SPARK_BASE_URL   OpenAI-compatible endpoint (default http://127.0.0.1:8000/v1)
  DSR_SPARK_MODEL      model name (default "local-model")
  DSR_SPARK_API_KEY    API key for the endpoint, if it needs one
  DSR_REA_COMMAND      REA MCP command (default "rea mcp", which must be on PATH)
  GHIDRA_INSTALL_DIR, JAVA_HOME   passed through to REA when set

Never starts the model endpoint; it only probes it and exits 4 (DSR_RESULT=BRAIN_DOWN)
if it is not answering. The last line printed is always ``DSR_RESULT=<COMPLETE|TIMEOUT|
ERROR|BRAIN_DOWN> ...`` so a queue script can grep the outcome. Findings stay at the
tier the hunt gives them; nothing is verified or promoted here.

Run from the refall-lite directory (or with it on PYTHONPATH).
"""
import hashlib, json, os, sys, time, traceback
from refall_lite import RefallLite
from refall_lite.corpus_hunt import advance_to_middle, enqueue_hunt, run_hunt_once
from refall_lite.corpus_hunt_runner import brain_available
from refall_lite.opencode_worker import OpenCodeWorker

ROOT   = os.environ["DSR_ROOT"]; MEMBER = os.environ["DSR_MEMBER"]
FAMILY = os.environ["DSR_FAMILY"]; DB = os.environ["DSR_DB"]
PRIORITIES = open(os.environ["DSR_PRIORITIES_FILE"]).read().strip()
TIMEOUT_S = int(os.environ.get("DSR_TIMEOUT_S", "10800"))
BASE_URL = os.environ.get("DSR_SPARK_BASE_URL", "http://127.0.0.1:8000/v1")
MODEL = os.environ.get("DSR_SPARK_MODEL", "local-model")
REA_CMD = os.environ.get("DSR_REA_COMMAND", "rea mcp").split()
REA_ENV = {k: os.environ[k] for k in ("GHIDRA_INSTALL_DIR", "JAVA_HOME") if k in os.environ}
def log(*a): print(*a, flush=True)
def sha256(p):
    h=hashlib.sha256()
    with open(p,"rb") as f:
        for c in iter(lambda: f.read(1<<20), b""): h.update(c)
    return h.hexdigest()
try:
    full=os.path.join(ROOT, MEMBER)
    if not os.path.isfile(full): log(f"MISSING {full}"); sys.exit(2)
    member={"path": MEMBER, "sha256": sha256(full), "size_bytes": os.path.getsize(full)}
    if os.path.exists(DB): os.remove(DB)
    lite=RefallLite(DB)
    for aid,kind in [("supervisor","supervisor"),("qwen","model"),("spark-hunt","model")]:
        lite.register_actor(aid, kind)
    cfg={"budgets":{"run":{"max_claims":60,"max_cost":100000000}},"max_attempts":1,"lease_s":TIMEOUT_S+600,
         "methodology_bundle":{"methods":[]}}
    cid=lite.create_campaign(f"hunt-{FAMILY}", config=cfg, actor="supervisor")["id"]
    log(f"campaign={cid} db={DB} target={full} size={member['size_bytes']} timeout_s={TIMEOUT_S}")
    img=lite.ingest_image(cid, family=FAMILY, name=MEMBER, image_sha256=sha256(full),
                          members=[member], actor="supervisor")
    advance_to_middle(lite, cid, img["image_id"], actor="supervisor")
    enqueue_hunt(lite, cid, member["sha256"], actor="supervisor")
    if not brain_available(BASE_URL): log("DSR_RESULT=BRAIN_DOWN"); sys.exit(4)
    hunt=OpenCodeWorker("spark-hunt", model=MODEL, base_url=BASE_URL, api_key=os.environ.get("DSR_SPARK_API_KEY", "not-needed"),
                        rea_command=REA_CMD, rea_env=REA_ENV, workdir_for=lambda p: ROOT,
                        timeout_s=TIMEOUT_S, priorities=PRIORITIES)
    log(f"=== HUNT START {FAMILY} ({MEMBER}) timeout_s={TIMEOUT_S} ===")
    t0=time.time(); res=run_hunt_once(lite, cid, hunt, stage="middle"); el=int(time.time()-t0)
    nf=len(lite.list_findings(cid))
    log(f"[hunt] elapsed={el}s claimed={res.get('claimed')} accepted={res.get('accepted')} "
        f"finding_ids={res.get('finding_ids')} errors={res.get('errors')}")
    for fid in (res.get("finding_ids") or []):
        f=lite.get_finding(fid)
        log(f"FINDING {fid} sev={f.get('severity')} class={f.get('vuln_class')!r} title={f.get('title')!r}")
        log(f"   claim_keys={list((f.get('claim') or {}).keys())} anchors={(f.get('source_anchors') or [])[:4]}")
    result = "TIMEOUT" if el >= int(TIMEOUT_S*0.97) else "COMPLETE"
    log(f"DSR_RESULT={result} elapsed={el} findings={nf} campaign={cid}")
except Exception:
    log("EXC:\n"+traceback.format_exc()); log("DSR_RESULT=ERROR"); sys.exit(1)
