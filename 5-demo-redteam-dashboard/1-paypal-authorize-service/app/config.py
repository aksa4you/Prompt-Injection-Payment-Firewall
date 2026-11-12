from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    mode: str = "mock"  # "mock" or "live" (live = PayPal sandbox/production via REST)
    service_token: str = "dev-service-token"  # shared with the gateway only
    capture_secret: str = "dev-capture-secret"  # shared with the gateway only
    hold_ttl_seconds: int = 900  # how long an authorization may stay held before auto-void
    paypal_client_id: str = ""
    paypal_client_secret: str = ""
    paypal_base_url: str = "https://api-m.sandbox.paypal.com"
    return_url: str = "http://localhost:8004/paypal/return"
    cancel_url: str = "http://localhost:8004/paypal/cancel"


def load_settings() -> Settings:
    return Settings(
        mode=os.getenv("PAYPAL_MODE", "mock"),
        service_token=os.getenv("SERVICE_TOKEN", "dev-service-token"),
        capture_secret=os.getenv("CAPTURE_SECRET", "dev-capture-secret"),
        hold_ttl_seconds=int(os.getenv("HOLD_TTL_SECONDS", "900")),
        paypal_client_id=os.getenv("PAYPAL_CLIENT_ID", ""),
        paypal_client_secret=os.getenv("PAYPAL_CLIENT_SECRET", ""),
        paypal_base_url=os.getenv("PAYPAL_BASE_URL", "https://api-m.sandbox.paypal.com"),
        return_url=os.getenv("PAYPAL_RETURN_URL", "http://localhost:8004/paypal/return"),
        cancel_url=os.getenv("PAYPAL_CANCEL_URL", "http://localhost:8004/paypal/cancel"),
    )
