# 3 · Intent & Policy Engine (Intent & Policy Engine Lead)

Part of the **Prompt-Injection Payment Firewall**. Records what the **user** actually asked for *before* the
agent browses, then compares every payment request against it with deterministic rules. There is no LLM here.

```
user app ──(X-User-Key)──▶ POST /v1/intents        "buy the Python Cookbook, max $30, shop = bookshop.example"
gateway  ──(X-Service-Token)──▶ POST /v1/evaluate  { intent_id, request }  ──▶ allow | review | block + reasons + intent_diff
gateway  ──(X-Service-Token)──▶ POST /v1/intents/{id}/consume   after capture: burn intent, count spend, remember payee
```

Two separate credentials on purpose: the agent has neither, and the gateway can evaluate but **cannot mint
intents**. An attacker who owns the agent cannot widen what the user authorised.

## Run

```bash
pip install -r requirements.txt
uvicorn app.main:app --port 8003
pytest -q          # 21 tests
```

Env: `USER_KEY`, `SERVICE_TOKEN`, `INTENT_SECRET`, `DAILY_CAP` (default 500.00), `REVIEW_OVER` (default 250.00).

## Checks (`app/engine.py`)

| Check | block when | review when |
|---|---|---|
| `intent_exists` / `intent_integrity` / `intent_active` | no intent, signature mismatch, expired, single-use already used | – |
| `currency` | differs from the user's currency | – |
| `budget` | amount > budget × (1+tolerance) | amount slightly over budget (tax/shipping) |
| `cart_total` | charge ≠ cart total | line items exceed cart total |
| `quantity` | more units than the intent allows | – |
| `item_match` | – | nothing in the cart matches the request, or big unrelated items |
| `payee` | not on the user's payee/domain allowlist | no allowlist and a never-seen payee |
| `merchant_domain` | page outside approved merchants | page domain ≠ payee domain |
| `daily_cap` | captured spend today + amount > cap | – |
| `velocity` | > 10 attempts in 10 min | > 5 attempts |
| `high_value` | – | amount ≥ `REVIEW_OVER` (human approval) |

Verdict = worst check. Every response includes `intent_diff` (`user_asked` vs `agent_wants`) for the dashboard.

## Example

User asked for a $30 book at bookshop.example. The hijacked checkout requests $4,999 to `evil-llc`:
`verdict: block`: `budget` (166.6× the budget), `payee`, `merchant_domain`, `item_match`.

## Your checklist

- [ ] Add policy knobs per user (own caps, own allowlists) instead of the global `PolicyConfig`
- [ ] Persist intents/spend (SQLite or Postgres); state is in memory today
- [ ] Smarter `item_match` (SKU/ISBN match instead of keyword tokens)
- [ ] Add merchant reputation / category rules if time allows

## Honest limits

`item_match` is keyword overlap, so it is a review signal rather than proof. Policy is only as good as the intent the user
set: a user who approves "any merchant, $5,000" has approved it. Velocity/spend state is per process and in memory.
