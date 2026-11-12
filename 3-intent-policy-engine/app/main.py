from __future__ import annotations

import hmac
import os
import time
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException

from .engine import PolicyEngine
from .models import ConsumeIn, EvaluateIn, IntentIn, PolicyConfig


def create_app(user_key: Optional[str] = None, service_token: Optional[str] = None,
               engine: Optional[PolicyEngine] = None) -> FastAPI:
    user_key = user_key or os.getenv("USER_KEY", "dev-user-key")
    service_token = service_token or os.getenv("SERVICE_TOKEN", "dev-service-token")
    engine = engine or PolicyEngine(
        signing_secret=os.getenv("INTENT_SECRET", "dev-intent-secret"),
        config=PolicyConfig(
            daily_cap=os.getenv("DAILY_CAP", "500.00"),
            review_over=os.getenv("REVIEW_OVER", "250.00"),
        ),
    )
    app = FastAPI(title="Intent & policy engine", version="1.0.0")
    app.state.engine = engine

    def _check(provided: Optional[str], expected: str) -> None:
        if not provided or not hmac.compare_digest(provided, expected):
            raise HTTPException(401, "missing or invalid credentials")

    def user_auth(x_user_key: Optional[str] = Header(default=None)) -> None:
        _check(x_user_key, user_key)  # the user's own trusted app. The agent never has this.

    def service_auth(x_service_token: Optional[str] = Header(default=None)) -> None:
        _check(x_service_token, service_token)  # the gateway only

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/intents", status_code=201, dependencies=[Depends(user_auth)])
    def create_intent(body: IntentIn) -> dict[str, Any]:
        return engine.create_intent(body)

    @app.get("/v1/intents/{intent_id}", dependencies=[Depends(service_auth)])
    def get_intent(intent_id: str) -> dict[str, Any]:
        intent = engine.get_intent(intent_id)
        if intent is None:
            raise HTTPException(404, "intent not found")
        return intent

    @app.post("/v1/evaluate", dependencies=[Depends(service_auth)])
    def evaluate(body: EvaluateIn) -> dict[str, Any]:
        return engine.evaluate(body)

    @app.post("/v1/intents/{intent_id}/consume", dependencies=[Depends(service_auth)])
    def consume(intent_id: str, body: ConsumeIn) -> dict[str, Any]:
        return engine.consume(intent_id, body)

    return app


app = create_app()
