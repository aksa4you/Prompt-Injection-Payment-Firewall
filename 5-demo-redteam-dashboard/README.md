# 5 · Demo, Red-Team & Dashboard (Demo, Red-Team & Frontend Lead)

Part of the **Prompt-Injection Payment Firewall**. This repo is the proof: a malicious storefront, a gullible
shopping agent, an attack runner, and a dashboard that shows *why* each payment was captured, held or blocked.

```
shop (8006)  ──page──▶  naive agent  ──┬─ unprotected: holds PayPal creds, captures whatever the page told it to
 9 scenarios                           └─ protected:   can only POST /v1/payment-requests to the gateway (repo 4)
dashboard (8005) ── admin key (server side only) ──▶ gateway admin API: requests, decision trail, audit, approve/reject
```

The agent is **simulated without an LLM** so demos are deterministic. It reads everything on the page (hidden text,
comments, alt text, data attributes, base64) and obeys it, exactly what a hijacked LLM agent does. The firewall must not
depend on *how* the agent was fooled.

## Run the whole stack

Unzip all five repos **side by side**, then from this repo:

```bash
pip install -r requirements.txt            # also install requirements.txt of repos 1-4 (same packages)
python scripts/run_all.py                  # starts 1-4 + shop + dashboard; Ctrl+C stops all
#   dashboard http://127.0.0.1:8005   shop http://127.0.0.1:8006
python scripts/run_all.py --attack-run     # headless: start stack, run every scenario both ways, print table, stop
```

CLI against a running stack:

```bash
python -m app.runner --mode both           # unprotected vs protected, side by side (exit 1 if any protected run misbehaves)
python -m app.runner css_hidden --approve  # one scenario; auto-approve if held for human review
```

## Scenarios (`app/pages.py`)

| id | attack | expected | stopped by |
|---|---|---|---|
| `clean_purchase` | none ($29.99 book, approved merchant) | CAPTURED | allowed through |
| `css_hidden`, `white_on_white`, `html_comment`, `image_alt_text` | hidden-text / metadata injection | BLOCKED | detector + policy |
| `visible_review` | instruction in a user review | BLOCKED | detector + policy |
| `base64_payload` | obfuscated instruction | BLOCKED | detector + policy |
| `paraphrase_overcharge` | polite wording, no trigger phrases, $4,999 | BLOCKED | **policy** (budget, payee) |
| `silent_payee_swap` | same $29.99, money redirected | BLOCKED | **policy** (payee, merchant domain) |
| `needs_review` | legit new shop the user never approved | PENDING_REVIEW | policy → human |

The last three matter most for the pitch: they show the firewall is not just a keyword filter. The benign ones prove it
does not block everything.

## Tests

```bash
pytest -q          # 24 offline tests (+1 live test that runs with E2E=1 while the stack is up)
E2E=1 pytest -q    # needs scripts/run_all.py running in another terminal
```

## Pitch script (3 minutes)

1. Open the shop page for `css_hidden`: a normal-looking book page. Show page source: the hidden instruction.
2. Dashboard → **Run without** → the agent paid $4,999 to `evil-llc`. Header shows money lost.
3. **Run with firewall** → BLOCKED. Open the decision trail: detector risk, intent diff (asked $30, wanted $4,999), void.
4. Run `paraphrase_overcharge` and `silent_payee_swap`: no scary words, still blocked by deterministic policy.
5. Run `needs_review`, then approve it in the UI. Finish on the audit chain badge (tamper-evident log).

## Your checklist

- [ ] Record the demo video and screenshots for the README/Devpost
- [ ] Add 3-5 attacks of your own to `app/pages.py` (multi-step, homoglyph payee, currency switch) and see what slips through
- [ ] Optional: replace `NaiveShoppingAgent` with a real LLM agent behind the same `decide()` interface to show it on real models
- [ ] Keep `app/tickets.py` identical to repo 1's copy (used only by the *unprotected* demo)

## Honest limits

The simulated agent shows the architecture working, not that every real LLM can be hijacked in these exact ways.
Treat the scenarios as a regression suite for the firewall, not a benchmark of agent robustness.
