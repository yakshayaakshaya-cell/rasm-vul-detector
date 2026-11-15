"""ENHANCEMENT 6: analyst feedback. Confirmed cases are queued for review and only reach the knowledge base after a
reviewer approves them (so one wrong click can never poison retrieval)."""
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

MAX_PENDING = 500
MAX_TOTAL = 3000


class FeedbackError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FeedbackStore:
    def __init__(self, directory, kb):
        self.dir, self.kb = Path(directory), kb
        self.lock = threading.Lock()
        self.path = self.dir / "queue.json"

    # -- storage
    def _load(self) -> list:
        try:
            return json.loads(self.path.read_text(encoding="utf-8")) if self.path.is_file() else []
        except (OSError, json.JSONDecodeError):
            return []

    def _save(self, items: list):
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)

    # -- API
    def submit(self, d: dict) -> dict:
        kind = d["kind"]
        item = {"id": uuid.uuid4().hex[:10], "created_at": _now(), "status": "pending", "kind": kind, "language": d.get("language", "c"),
                "cwe": (d.get("cwe") or "").strip()[:40], "note": (d.get("note") or "").strip()[:1000],
                "model_verdict": d.get("model_verdict"), "risk_score": d.get("risk_score")}
        if kind == "pair":
            item.update(old_code=d["old_code"], new_code=d["new_code"])
        else:
            item.update(code=d["code"], label=d["label"])
        with self.lock:
            items = self._load()
            if sum(i["status"] == "pending" for i in items) >= MAX_PENDING or len(items) >= MAX_TOTAL:
                raise FeedbackError(429, "The review queue is full. A reviewer needs to clear it before more feedback can be added.")
            items.append(item)
            self._save(items)
        return {"id": item["id"], "status": "pending"}

    def list(self, status: str | None = "pending") -> list:
        items = self._load()
        items = [i for i in items if status in (None, "all", i["status"])]
        return list(reversed(items))

    def counts(self) -> dict:
        c = {}
        for i in self._load():
            c[i["status"]] = c.get(i["status"], 0) + 1
        return c

    def reject(self, fid: str) -> dict:
        return self._finish(fid, "rejected")

    def approve(self, fid: str, counterpart: str | None = None, cwe: str | None = None, description: str | None = None) -> dict:
        with self.lock:
            items = self._load()
            item = next((i for i in items if i["id"] == fid), None)
            if not item:
                raise FeedbackError(404, "Feedback item not found.")
            if item["status"] != "pending":
                raise FeedbackError(409, f"Item was already {item['status']}.")
            vul = fix = None
            if item["kind"] == "pair":
                vul, fix = item["old_code"], item["new_code"]
            elif counterpart and counterpart.strip():
                vul, fix = (item["code"], counterpart) if item["label"] == "vulnerable" else (counterpart, item["code"])
            if vul and fix:
                pid = f"feedback-{item['id']}"
                self.kb.add_pairs([{"id": pid, "language": item["language"], "cwe": (cwe or item["cwe"]),
                                    "description": (description or item["note"] or "Analyst-confirmed case"), "vulnerable_code": vul, "fixed_code": fix}])
                item.update(status="approved", kb_pair_id=pid)
            else:  # a lone function cannot form a vulnerable/fixed pair: keep it as a labelled example only
                item["status"] = "approved_labelled"
                self.dir.mkdir(parents=True, exist_ok=True)
                with open(self.dir / "labelled_singles.jsonl", "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"id": item["id"], "language": item["language"], "label": item["label"], "cwe": item["cwe"], "code": item["code"]}) + "\n")
            item["reviewed_at"] = _now()
            self._save(items)
            return item

    def _finish(self, fid: str, status: str) -> dict:
        with self.lock:
            items = self._load()
            item = next((i for i in items if i["id"] == fid), None)
            if not item:
                raise FeedbackError(404, "Feedback item not found.")
            if item["status"] != "pending":
                raise FeedbackError(409, f"Item was already {item['status']}.")
            item.update(status=status, reviewed_at=_now())
            self._save(items)
            return item
