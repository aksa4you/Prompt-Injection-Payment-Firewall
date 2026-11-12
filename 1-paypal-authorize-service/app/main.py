from __future__ import annotations

import hmac
import threading
import time
from decimal import Decimal
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .config import Settings, load_settings
from .providers import MockProvider, PayPalLiveProvider
from .service import AuthService, ServiceError


class CreateAuthorization(BaseModel):
    amount: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    currency: str = Field(min_length=3, max_length=3)
    payee: str = Field(min_length=1, max_length=200)
    reference: str = Field(min_length=1, max_length=127)
    idempotency_key: str = Field(min_length=8, max_length=128)
    payee_email: Optional[str] = None


class VoidBody(BaseModel):
    reason: str = Field(default="voided by gateway", max_length=300)


def build_provider(settings: Settings) -> Any:
    if settings.mode == "live":
        if not (settings.paypal_client_id and settings.paypal_client_secret):
            raise RuntimeError("PAYPAL_MODE=live needs PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET")
        return PayPalLiveProvider(settings.paypal_client_id, settings.paypal_client_secret,
                                  settings.paypal_base_url, settings.return_url, settings.cancel_url)
    return MockProvider()


def create_app(settings: Optional[Settings] = None, provider: Any = None, clock=time.time,
               sweep_interval: Optional[float] = None) -> FastAPI:
    settings = settings or load_settings()
    service = AuthService(provider or build_provider(settings), settings, clock=clock)
    app = FastAPI(title="PayPal authorize service", version="1.0.0")
    app.state.service = service

    def require_service_token(x_service_token: Optional[str] = Header(default=None)) -> None:
        if not x_service_token or not hmac.compare_digest(x_service_token, settings.service_token):
            raise ServiceError(401, "unauthorized", "missing or invalid service token")

    @app.exception_handler(ServiceError)
    async def _service_error(_: Request, exc: ServiceError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code,
                            content={"error": {"code": exc.code, "message": exc.message}})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "mode": settings.mode}

    @app.post("/v1/authorizations", status_code=201, dependencies=[Depends(require_service_token)])
    def create(body: CreateAuthorization) -> dict[str, Any]:
        item = service.create(body.amount, body.currency, body.payee, body.reference,
                              body.idempotency_key, body.payee_email)
        return item.public()

    @app.post("/v1/authorizations/{auth_id}/confirm", dependencies=[Depends(require_service_token)])
    def confirm(auth_id: str) -> dict[str, Any]:
        return service.confirm(auth_id).public()

    @app.get("/v1/authorizations/{auth_id}", dependencies=[Depends(require_service_token)])
    def read(auth_id: str) -> dict[str, Any]:
        return service.get(auth_id).public()

    @app.post("/v1/authorizations/{auth_id}/capture", dependencies=[Depends(require_service_token)])
    def capture(auth_id: str, x_capture_ticket: Optional[str] = Header(default=None)) -> dict[str, Any]:
        return service.capture(auth_id, x_capture_ticket).public()

    @app.post("/v1/authorizations/{auth_id}/void", dependencies=[Depends(require_service_token)])
    def void(auth_id: str, body: VoidBody = VoidBody()) -> dict[str, Any]:
        return service.void(auth_id, body.reason).public()

    @app.post("/v1/sweep", dependencies=[Depends(require_service_token)])
    def sweep() -> dict[str, int]:
        return {"expired": service.sweep()}

    if sweep_interval:
        def _loop() -> None:
            while True:
                time.sleep(sweep_interval)
                try:
                    service.sweep()
                except Exception:  # noqa: BLE001
                    pass
        threading.Thread(target=_loop, daemon=True).start()

    return app


app = create_app(sweep_interval=30)
