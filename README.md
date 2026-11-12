# Prompt-Injection Payment Firewall

A deterministic, non-LLM firewall between an AI shopping agent and PayPal capture. The agent can only *request*
a payment. PayPal Orders v2 `AUTHORIZE` holds the funds, an injection detector and an intent/policy engine check
the request, and the payment is captured only if everything agrees, otherwise it is voided.

| Role | Folder | Port |
|---|---|---|
| 1 Payment Integration Lead | `1-paypal-authorize-service` | 8001 |
| 2 Injection Detection Engineer | `2-injection-detector` | 8002 |
| 3 Intent & Policy Engine Lead | `3-intent-policy-engine` | 8003 |
| 4 Agent Gateway & Backend Architect | `4-agent-gateway` | 8004 |
| 5 Demo, Red-Team & Frontend Lead | `5-demo-redteam-dashboard` | 8005 dashboard, 8006 shop |

Each folder is a standalone repo (own README, tests, CI, LICENSE). Push each to its own GitHub repo, or keep this
folder as a monorepo.

## Try it (Python 3.10+)

```bash
pip install -r 5-demo-redteam-dashboard/requirements.txt
python 5-demo-redteam-dashboard/scripts/run_all.py            # dashboard at http://127.0.0.1:8005
python 5-demo-redteam-dashboard/scripts/run_all.py --attack-run   # headless: all attacks, with and without the firewall
```

Run each repo's tests: `cd <folder> && pip install -r requirements.txt && pytest -q`

PayPal runs in **mock mode** by default (no credentials). For the real sandbox, see repo 1's README (`PAYPAL_MODE=live`).
All keys in the repos are `dev-*` defaults for local use: change them before deploying anywhere.
