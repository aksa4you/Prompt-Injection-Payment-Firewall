# 1 · PayPal Authorize Service (Payment Integration Lead)

Part of the **Prompt-Injection Payment Firewall**. This is the *only* component that holds PayPal
credentials and the only one that can move money. It wraps PayPal Orders v2 `AUTHORIZE`:

```
create order (intent=AUTHORIZE) → buyer approves → authorize (funds HELD) → capture  |  void
```

The agent never talks to this service. The gateway (repo 4) does, and **capture is refused unless
the call carries a ticket signed by the gateway** after the firewall said `allow`.

## Run

```bash
pip install -r requirements.txt
cp .env.example .env            # optional; defaults work for mock mode
uvicorn app.main:app --port 8001
pytest -q
```

Mock mode (default) needs no credentials. For live sandbox set `PAYPAL_MODE=live` plus
`PAYPAL_CLIENT_ID` / `PAYPAL_CLIENT_SECRET` and keep `PAYPAL_BASE_URL` on the sandbox.

## API (all calls need `X-Service-Token`)

| Method | Path | Purpose |
|---|---|---|
| POST | `/v1/authorizations` | Create order + hold funds. Idempotent on `idempotency_key`. |
| POST | `/v1/authorizations/{id}/confirm` | Live mode: after the buyer approved at `approval_url`, authorize the order. |
| GET | `/v1/authorizations/{id}` | Status: `PENDING_APPROVAL`, `HELD`, `CAPTURED`, `VOIDED`, `EXPIRED`. |
| POST | `/v1/authorizations/{id}/capture` | Needs `X-Capture-Ticket`. |
| POST | `/v1/authorizations/{id}/void` | Idempotent; cannot undo a capture. |
| POST | `/v1/sweep` | Void holds past `HOLD_TTL_SECONDS` (also runs every 30 s in the background). |

Create body: `{"amount": "30.00", "currency": "USD", "payee": "bookshop", "reference": "order-1", "idempotency_key": "…", "payee_email": null}`

## Capture tickets (`app/tickets.py`)

`ticket = base64url({auth_id, amount, currency, exp}) + "." + HMAC-SHA256(CAPTURE_SECRET)`.
Bound to one authorization, one amount, one currency; expires in ~60 s. The gateway issues it with the
same `issue_ticket` function (copied into repo 4).

## Your checklist

- [x] Authorize → hold → capture/void, idempotency, hold expiry sweeper, capture tickets, tests
- [ ] Run once against the PayPal sandbox (`PAYPAL_MODE=live`) and confirm the buyer-approval redirect
- [ ] Swap the in-memory store in `app/service.py` for Postgres/SQLite before any real use
- [ ] Add PayPal webhook handling (`PAYMENT.AUTHORIZATION.VOIDED`, `PAYMENT.CAPTURE.COMPLETED`)

## Honest limits

The live provider is tested against a mocked HTTP transport (request shapes), not against PayPal itself.
State is in memory, so a restart loses holds. PayPal-side authorizations still lapse by themselves.
