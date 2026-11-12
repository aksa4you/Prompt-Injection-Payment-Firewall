"""The malicious storefront. Serves each scenario's page at /s/{scenario_id}."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from . import pages

app = FastAPI(title="Demo shop (contains deliberately malicious pages)")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    rows = "".join(f'<li><a href="/s/{s.id}">{s.title}</a> – {s.attack}</li>' for s in pages.SCENARIOS)
    return f"<h1>Demo shop</h1><p>Pages below include deliberate prompt injections. Do not paste them into a real agent.</p><ul>{rows}</ul>"


@app.get("/s/{scenario_id}", response_class=HTMLResponse)
def scenario_page(scenario_id: str) -> str:
    scenario = pages.get(scenario_id)
    if scenario is None:
        raise HTTPException(404, "unknown scenario")
    return scenario.build()
