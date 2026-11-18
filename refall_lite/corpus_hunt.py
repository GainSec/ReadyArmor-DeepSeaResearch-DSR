"""Corpus-hunt slice: ingest a firmware image, advance to middle, enqueue and run one hunt lead."""
from __future__ import annotations

import hashlib
import os

from .stage0 import expand_image
from .worker import CallableWorker, result_payload, run_one


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def ingest_firmware(lite, cid: str, image_path: str, out_dir: str, *, actor: str, family: str = "corpus") -> dict:
    """Unpack an image (Stage-0) and register it plus its members with the engine.

    A failed unpack registers the image with zero members and flags escalation.
    """
    outcome = expand_image(image_path, out_dir)
    failed = outcome.status == "failed"
    members = [] if failed else outcome.members
    res = lite.ingest_image(cid, family=family, name=os.path.basename(image_path),
                            image_sha256=_file_sha256(image_path), members=members, actor=actor)
    return {"image_id": res["image_id"], "members": members, "escalation": failed}


def _inventory_result() -> dict:
    return result_payload(
        summary="inventory enumerated",
        evidence=[{"kind": "metadata", "ref": "stage0:members", "claim": "members enumerated"}],
        confidence="medium", artifact_refs=["stage0:members"], limitations=["stage0 metadata only"])


def advance_to_middle(lite, cid: str, image_id: str, *, actor: str, worker_id: str = "qwen") -> dict:
    """Run one trivial inventory job on the image and advance the campaign to the middle stage.

    worker_id must be a registered actor."""
    lite.enqueue_job(cid, stage="inventory", kind="inventory", target_type="image", target_ref=image_id, actor=actor)
    worker = CallableWorker(worker_id,lambda packet: _inventory_result())
    res = run_one(lite, cid, worker, stage="inventory")
    if not res.get("accepted"):
        raise RuntimeError(f"inventory job not accepted: {res}")
    adv = lite.advance_stage(cid, actor=actor)
    if not adv.get("advanced"):
        raise RuntimeError(f"stage did not advance: {adv}")
    return adv


def enqueue_hunt(lite, cid: str, member_sha256: str, *, technique_id: str | None = None, actor: str) -> str:
    res = lite.enqueue_job(cid, stage="middle", kind="hunt", target_type="member", target_ref=member_sha256,
                           actor=actor, payload={"technique_id": technique_id} if technique_id else {})
    return res["job"]["id"]


def run_hunt_once(lite, cid: str, worker, *, stage: str = "middle") -> dict:
    return run_one(lite, cid, worker, stage=stage)
