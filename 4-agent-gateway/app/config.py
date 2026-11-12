from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    paypal_url: str = "http://localhost:8001"
    detector_url: str = "http://localhost:8002"
    policy_url: str = "http://localhost:8003"
    service_token: str = "dev-service-token"  # presented to repo 1 and repo 3
    detector_token: str = ""  # presented to repo 2 if it requires one
    capture_secret: str = "dev-capture-secret"  # signs capture tickets; ONLY the gateway and repo 1 know it
    receipt_secret: str = "dev-receipt-secret"
    agent_key: str = "dev-agent-key"  # what the shopping agent presents
    admin_key: str = "dev-admin-key"  # what the human reviewer / dashboard presents
    audit_file: str = ""  # JSONL path; empty = memory only
    review_ttl_seconds: int = 600  # how long a borderline payment waits for a human
    http_timeout: float = 10.0


def load_settings() -> Settings:
    e = os.getenv
    return Settings(
        paypal_url=e("PAYPAL_URL", "http://localhost:8001"),
        detector_url=e("DETECTOR_URL", "http://localhost:8002"),
        policy_url=e("POLICY_URL", "http://localhost:8003"),
        service_token=e("SERVICE_TOKEN", "dev-service-token"),
        detector_token=e("DETECTOR_TOKEN", ""),
        capture_secret=e("CAPTURE_SECRET", "dev-capture-secret"),
        receipt_secret=e("RECEIPT_SECRET", "dev-receipt-secret"),
        agent_key=e("AGENT_KEY", "dev-agent-key"),
        admin_key=e("ADMIN_KEY", "dev-admin-key"),
        audit_file=e("AUDIT_FILE", ""),
        review_ttl_seconds=int(e("REVIEW_TTL_SECONDS", "600")),
        http_timeout=float(e("HTTP_TIMEOUT", "10")),
    )
