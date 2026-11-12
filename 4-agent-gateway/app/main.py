from __future__ import annotations

import hmac
import threading
import time
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from .clients import DetectorClient, PayPalClient, PolicyClient
from .config import Settings, load_settings
from .models import AgentPaymentRequest, ReviewDecision
from .orchestrator import Gateway, GatewayError


def create_app(settings: Optional[Settings] = None, gateway: Optional[Gateway] = None,
               sweep_interval: Optional[float] = None) -> FastAPI:
    settings = settings or load_settings()
    gateway = gateway or Gateway(settings, PayPalClient(settings), DetectorClient(settings), PolicyClient(settings))
    app = FastAPI(title="Agent gateway", version="1.0.0")
    app.state.gateway = gateway

    def _same(provided: Optional[str], expected: str) -> bool:
        return bool(provided) and hmac.compare_digest(provided, expected)

    def agent_auth(x_agent_key: Optional[str] = Header(default=None)) -> None:
        if not _same(x_agent_key, settings.agent_key):
            raise GatewayError(401, "unauthorized", "missing or invalid agent key")

    def admin_auth(x_admin_key: Optional[str] = Header(default=None)) -> None:
        if not _same(x_admin_key, settings.admin_key):  # an agent key is NOT accepted here
            raise GatewayError(401, "unauthorized", "missing or invalid admin key")

    @app.exception_handler(GatewayError)
    async def _err(_: Request, exc: GatewayError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": exc.message}})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # ---------------------------------------------- agent-facing: REQUEST a payment, nothing else
    @app.post("/v1/payment-requests", dependencies=[Depends(agent_auth)])
    def submit(body: AgentPaymentRequest) -> dict[str, Any]:
        return gateway.agent_view(gateway.submit(body))

    @app.get("/v1/payment-requests/{request_id}", dependencies=[Depends(agent_auth)])
    def status(request_id: str) -> dict[str, Any]:
        return gateway.agent_view(gateway.get(request_id))

    # ---------------------------------------------- human / dashboard-facing
    @app.get("/v1/admin/requests", dependencies=[Depends(admin_auth)])
    def admin_list(status: Optional[str] = None) -> list[dict[str, Any]]:
        return gateway.list(status)

    @app.get("/v1/admin/requests/{request_id}", dependencies=[Depends(admin_auth)])
    def admin_get(request_id: str) -> dict[str, Any]:
        return gateway.get(request_id)

    @app.post("/v1/admin/requests/{request_id}/approve", dependencies=[Depends(admin_auth)])
    def approve(request_id: str, body: ReviewDecision = ReviewDecision()) -> dict[str, Any]:
        return gateway.approve(request_id, body.reviewer, body.note)

    @app.post("/v1/admin/requests/{request_id}/reject", dependencies=[Depends(admin_auth)])
    def reject(request_id: str, body: ReviewDecision = ReviewDecision()) -> dict[str, Any]:
        return gateway.reject(request_id, body.reviewer, body.note)

    @app.get("/v1/admin/audit", dependencies=[Depends(admin_auth)])
    def audit(limit: int = 200, request_id: Optional[str] = None) -> list[dict[str, Any]]:
        return gateway.audit.tail(limit, request_id)

    @app.get("/v1/admin/audit/verify", dependencies=[Depends(admin_auth)])
    def audit_verify() -> dict[str, Any]:
        return gateway.audit.verify()

    @app.post("/v1/admin/sweep", dependencies=[Depends(admin_auth)])
    def sweep() -> dict[str, int]:
        return {"expired": gateway.sweep()}

    if sweep_interval:
        def _loop() -> None:
            while True:
                time.sleep(sweep_interval)
                try:
                    gateway.sweep()
                except Exception:  # noqa: BLE001
                    pass
        threading.Thread(target=_loop, daemon=True).start()

    return app


def _default_app() -> FastAPI:
    return create_app(sweep_interval=15)


app = _default_app()
