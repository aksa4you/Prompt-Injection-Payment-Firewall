# 4 · Agent Gateway (Agent Gateway & Backend Architect)

Part of the **Prompt-Injection Payment Firewall**. The only door between an AI shopping agent and PayPal.
The agent can **request** a payment. It has no capture call, no PayPal credentials and no capture secret.

```
agent ──X-Agent-Key──▶ POST /v1/payment-requests
                         1. AUTHORIZE at PayPal (funds held)                      repo 1
                         2. scan page + agent context                              repo 2   ┐ either unreachable
                         3. compare with the user's intent                         repo 3   ┘ = block (fail closed)
                         4a. block  → VOID        4b. review → hold, wait for a human (auto-void on timeout)
                         4c. allow  → sign capture ticket → CAPTURE → record spend + signed receipt
```

## Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --port 8004      # needs repos 1-3 running on 8001-8003 (see env below)
pytest -q                              # 18 tests, all backing services faked
```

Env (defaults match the other repos): `PAYPAL_URL`, `DETECTOR_URL`, `POLICY_URL`, `SERVICE_TOKEN`, `CAPTURE_SECRET`,
`RECEIPT_SECRET`, `AGENT_KEY`, `ADMIN_KEY`, `AUDIT_FILE` (JSONL path), `REVIEW_TTL_SECONDS` (default 600).

## API

Agent (`X-Agent-Key`): `POST /v1/payment-requests`, `GET /v1/payment-requests/{id}`
Human / dashboard (`X-Admin-Key`; an agent key is rejected): `GET /v1/admin/requests[?status=]`, `GET /v1/admin/requests/{id}`,
`POST /v1/admin/requests/{id}/approve|reject`, `GET /v1/admin/audit`, `GET /v1/admin/audit/verify`, `POST /v1/admin/sweep`

Request body: `request_id` (idempotency key), `intent_id`, `amount`, `currency`, `payee{id,name,domain}`,
`cart{items[{name,price,qty}],total,currency}`, `page_url`, `page_html`, `agent_context`.

Agent-facing response: `{request_id, status, decision, reason_codes, message, receipt}`. Status is one of
`CAPTURED`, `BLOCKED`, `PENDING_REVIEW`, `REJECTED`, `EXPIRED`, `FAILED`.

## Design rules (each has a test)

- **Hold before check, check before capture.** The call order is asserted: `authorize → … → capture`.
- **Fail closed.** Detector/policy down, or returning malformed output → `BLOCKED`, funds voided.
- **Capture needs a gateway-signed ticket** (`app/tickets.py`, bound to auth id + amount + currency, 60 s).
  The test PayPal double verifies real tickets, so the integration with repo 1 is proven, not assumed.
- **No echo.** The agent only gets fixed messages and reason codes, never page excerpts or payee strings, because
  attacker-controlled text returned to the agent would re-inject it. Humans see everything via the admin API.
- **Idempotent.** Same `request_id` returns the same record; same id with a different payment → 409.
- **Tamper-evident audit.** Hash-chained log (`app/audit.py`); `/audit/verify` pinpoints the first altered entry. Page HTML is
  stored as a hash only.

## Your checklist

- [ ] Persist `_records` (SQLite/Postgres); in-memory today
- [ ] Keep `app/tickets.py` identical to repo 1's copy
- [ ] Notify humans on `PENDING_REVIEW` (Slack/email/push) instead of polling
- [ ] Rate-limit per agent key; rotate keys

## Honest limits

`AGENT_KEY` is a shared secret; per-agent keys with scopes would be the next step. The audit log is tamper-*evident*, not
tamper-*proof*: anchor the latest hash somewhere the gateway cannot write for real assurance.
