"""Firmware fleet model: images, product families, member SHA-256 dedup, occurrences.

Identical members (same SHA-256) are stored once per campaign; every place a
member appears (image, path, family) is an occurrence row. Jobs and findings
anchor to the member SHA-256, so occurrence propagation is a join, not a copy:
images ingested later automatically inherit existing analysis and findings.
"""
from __future__ import annotations

from typing import Any

from ._base import Base
from .arcticbase.contracts import normalize_sha256, stable_id
from .arcticbase.store import dumps, loads


class FleetMixin(Base):
    def ingest_image(self, cid: str, *, family: str, name: str, image_sha256: str,
                     members: list[dict], actor: str, metadata: dict | None = None) -> dict:
        self._require_operator(actor, "ingest images")
        camp = self.get_campaign(cid)
        if camp["status"] != "active":
            raise ValueError(f"campaign {cid} is {camp['status']}")
        img_sha = normalize_sha256(image_sha256)
        if not img_sha or not family.strip() or not name.strip():
            raise ValueError("image requires family, name, and a sha256 digest")
        clean: list[dict[str, Any]] = []
        for item in members:
            msha = normalize_sha256(item.get("sha256"))
            path = str(item.get("path") or "").strip()
            if not msha or not path:
                raise ValueError(f"member requires path and sha256 digest: {item!r}")
            offset = item.get("offset")
            if offset is not None and (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0):
                raise ValueError(f"member offset must be a non-negative integer: {item!r}")
            clean.append({"sha256": msha, "path": path, "size_bytes": item.get("size_bytes"), "kind": item.get("kind"),
                          "container": item.get("container"), "offset": offset, "package": item.get("package")})
        image_id = stable_id("img", {"campaign_id": cid, "image_sha256": img_sha})
        now = self.store.now()
        new_members = duplicate_members = occurrences_added = 0
        with self.store.tx():
            if not self.store.one("SELECT 1 FROM images WHERE id=?", (image_id,)):
                seq = int(self.store.scalar("SELECT COALESCE(MAX(ingest_seq),0)+1 FROM images WHERE campaign_id=?", (cid,)))
                self.store.conn.execute(
                    "INSERT INTO images(id,campaign_id,family,name,image_sha256,metadata,ingest_seq,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (image_id, cid, family, name, img_sha, dumps(metadata or {}), seq, now))
            else:
                family = self.store.scalar("SELECT family FROM images WHERE id=?", (image_id,))
            for m in clean:
                exists = self.store.one("SELECT 1 FROM members WHERE campaign_id=? AND sha256=?", (cid, m["sha256"]))
                if exists:
                    duplicate_members += 1
                else:
                    new_members += 1
                    self.store.conn.execute(
                        "INSERT INTO members(campaign_id,sha256,size_bytes,kind,primary_family,first_image_id,created_at) "
                        "VALUES(?,?,?,?,?,?,?)", (cid, m["sha256"], m["size_bytes"], m["kind"], family, image_id, now))
                cur = self.store.conn.execute(
                    "INSERT OR IGNORE INTO occurrences(campaign_id,member_sha256,image_id,path,family,created_at,container,offset,package) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (cid, m["sha256"], image_id, m["path"], family, now, m["container"], m["offset"], m["package"]))
                occurrences_added += cur.rowcount
            self._ledger(cid, "image", "ingest", actor, image_id=image_id, family=family, name=name, image_sha256=img_sha,
                         new_members=new_members, duplicate_members=duplicate_members, occurrences_added=occurrences_added)
        return {"image_id": image_id, "new_members": new_members, "duplicate_members": duplicate_members,
                "occurrences_added": occurrences_added}

    def get_image(self, image_id: str) -> dict:
        row = self.store.one("SELECT * FROM images WHERE id=?", (image_id,))
        if not row:
            raise KeyError(f"unknown image {image_id}")
        data = dict(row)
        data["metadata"] = loads(data["metadata"], {})
        return data

    def list_images(self, cid: str) -> list[dict]:
        return [self.get_image(r["id"]) for r in self.store.all("SELECT id FROM images WHERE campaign_id=? ORDER BY ingest_seq", (cid,))]

    def get_member(self, cid: str, sha256: str) -> dict:
        row = self.store.one("SELECT * FROM members WHERE campaign_id=? AND sha256=?", (cid, normalize_sha256(sha256)))
        if not row:
            raise KeyError(f"unknown member {sha256}")
        data = dict(row)
        data["occurrence_count"] = self.store.scalar(
            "SELECT COUNT(*) FROM occurrences WHERE campaign_id=? AND member_sha256=?", (cid, data["sha256"]))
        data["families"] = [r["family"] for r in self.store.all(
            "SELECT DISTINCT family FROM occurrences WHERE campaign_id=? AND member_sha256=? ORDER BY family", (cid, data["sha256"]))]
        return data

    def member_occurrences(self, cid: str, sha256: str) -> list[dict]:
        return [dict(r) for r in self.store.all(
            "SELECT o.member_sha256, o.image_id, i.name AS image_name, i.image_sha256, o.family, o.path, "
            "o.container, o.offset, o.package "
            "FROM occurrences o JOIN images i ON i.id=o.image_id WHERE o.campaign_id=? AND o.member_sha256=? "
            "ORDER BY i.ingest_seq, o.path", (cid, normalize_sha256(sha256)))]
