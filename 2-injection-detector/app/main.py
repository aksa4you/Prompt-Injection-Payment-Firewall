from __future__ import annotations

import hmac
import os
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .classifier import BLOCK_AT, REVIEW_AT, classify

SERVICE_TOKEN = os.getenv("DETECTOR_TOKEN", "")  # empty = no auth (local dev)


class ScanRequest(BaseModel):
    html: str = Field(default="", max_length=2_000_000)
    text: str = Field(default="", max_length=500_000)
    context: str = Field(default="", max_length=100_000, description="agent reasoning / tool output to scan too")
    url: str = Field(default="", max_length=2048)


def require_token(x_service_token: Optional[str] = Header(default=None)) -> None:
    if SERVICE_TOKEN and not (x_service_token and hmac.compare_digest(x_service_token, SERVICE_TOKEN)):
        raise HTTPException(401, "missing or invalid service token")


app = FastAPI(title="Injection detector", version="1.0.0")


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"status": "ok", "block_at": BLOCK_AT, "review_at": REVIEW_AT}


@app.post("/v1/scan", dependencies=[Depends(require_token)])
def scan(req: ScanRequest) -> dict[str, Any]:
    if not (req.html or req.text or req.context):
        raise HTTPException(422, "provide html, text or context")
    return classify(html=req.html, text=req.text, context=req.context, url=req.url)
