"""Append-only, hash-chained audit log. Editing or deleting any past entry breaks every later hash."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any, Callable, Optional

GENESIS = "0" * 64


def _digest(body: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str = "", clock: Callable[[], float] = time.time):
        self.entries: list[dict[str, Any]] = []
        self._path = path
        self._clock = clock
        self._lock = threading.Lock()
        if path:
            try:
                with open(path, encoding="utf-8") as fh:
                    self.entries = [json.loads(line) for line in fh if line.strip()]
            except FileNotFoundError:
                pass

    def append(self, event: str, request_id: str, data: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        with self._lock:
            prev = self.entries[-1]["hash"] if self.entries else GENESIS
            body = {"seq": len(self.entries), "ts": round(self._clock(), 3), "event": event,
                    "request_id": request_id, "data": data or {}, "prev": prev}
            entry = {**body, "hash": _digest(body)}
            self.entries.append(entry)
            if self._path:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry, default=str) + "\n")
            return entry

    def verify(self) -> dict[str, Any]:
        prev = GENESIS
        for i, entry in enumerate(self.entries):
            body = {k: v for k, v in entry.items() if k != "hash"}
            if entry.get("prev") != prev or entry.get("seq") != i or _digest(body) != entry.get("hash"):
                return {"ok": False, "entries": len(self.entries), "broken_at": i}
            prev = entry["hash"]
        return {"ok": True, "entries": len(self.entries), "broken_at": None}

    def tail(self, limit: int = 100, request_id: Optional[str] = None) -> list[dict[str, Any]]:
        items = [e for e in self.entries if request_id is None or e["request_id"] == request_id]
        return items[-limit:]
