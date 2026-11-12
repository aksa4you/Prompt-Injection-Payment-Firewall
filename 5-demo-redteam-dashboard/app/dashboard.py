"""Dashboard backend. It holds the admin key so the browser never sees it, and proxies the gateway's admin API."""
from __future__ import annotations

import os
from decimal import Decimal
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import pages
from .runner import Runner, load_config

STATIC = Path(__file__).parent / "static"


class RunBody(BaseModel):
    scenario: str
    mode: str = "protected"  # protected | unprotected
    approve: bool = False


def create_app(runner: Optional[Runner] = None, admin: Optional[httpx.Client] = None) -> FastAPI:
    cfg = load_config()
    runner = runner or Runner(cfg)
    admin = admin or httpx.Client(base_url=cfg.gateway_url, headers={"X-Admin-Key": cfg.admin_key}, timeout=20)
    runs: list[dict[str, Any]] = []
    app = FastAPI(title="Firewall dashboard", version="1.0.0")

    def upstream(method: str, path: str, **kw: Any) -> Any:
        try:
            resp = admin.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise HTTPException(502, f"gateway unreachable ({exc.__class__.__name__})") from exc
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text[:300])
        return resp.json()

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/scenarios")
    def scenarios() -> list[dict[str, Any]]:
        return [{"id": s.id, "title": s.title, "attack": s.attack, "description": s.description,
                 "expected": s.expected, "is_attack": s.is_attack, "caught_by": s.caught_by} for s in pages.SCENARIOS]

    @app.post("/api/run")
    def run(body: RunBody) -> dict[str, Any]:
        if body.mode not in ("protected", "unprotected"):
            raise HTTPException(422, "mode must be protected or unprotected")
        if pages.get(body.scenario) is None:
            raise HTTPException(404, "unknown scenario")
        try:
            result = runner.run(body.scenario, body.mode, body.approve)
        except httpx.HTTPError as exc:
            raise HTTPException(502, f"a backing service failed ({exc.__class__.__name__}): is everything running?") from exc
        runs.insert(0, result)
        del runs[200:]
        return result

    @app.get("/api/runs")
    def run_log() -> dict[str, Any]:
        lost = sum((Decimal(r["amount"]) for r in runs if r["mode"] == "unprotected" and r["money_lost"]), Decimal("0"))
        saved = sum((Decimal(r["amount"]) for r in runs if r["mode"] == "protected" and r["is_attack"]
                     and r["status"] in ("BLOCKED", "REJECTED", "EXPIRED")), Decimal("0"))
        return {"runs": runs, "lost_unprotected": f"{lost:.2f}", "blocked_by_firewall": f"{saved:.2f}"}

    @app.get("/api/requests")
    def requests() -> Any:
        return upstream("GET", "/v1/admin/requests")

    @app.get("/api/requests/{request_id}")
    def request_detail(request_id: str) -> Any:
        return upstream("GET", f"/v1/admin/requests/{request_id}")

    @app.get("/api/audit")
    def audit(request_id: Optional[str] = None) -> Any:
        return upstream("GET", "/v1/admin/audit", params={"request_id": request_id} if request_id else None)

    @app.get("/api/audit/verify")
    def audit_verify() -> Any:
        return upstream("GET", "/v1/admin/audit/verify")

    @app.post("/api/requests/{request_id}/approve")
    def approve(request_id: str) -> Any:
        return upstream("POST", f"/v1/admin/requests/{request_id}/approve", json={"reviewer": "dashboard-human"})

    @app.post("/api/requests/{request_id}/reject")
    def reject(request_id: str) -> Any:
        return upstream("POST", f"/v1/admin/requests/{request_id}/reject", json={"reviewer": "dashboard-human"})

    return app


app = create_app()
