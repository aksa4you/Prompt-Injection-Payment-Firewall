"""Pattern rules. Every rule is a plain regex with a weight; nothing here calls an LLM."""
from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass

# (id, weight, description, regex)
RULES: list[tuple[str, float, str, re.Pattern[str]]] = [
    ("override_instructions", 0.9, "tells the agent to ignore/forget its instructions",
     re.compile(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|any|your|the)\b"
                r"[^.\n]{0,30}\b(instruction|instructions|rules|prompt|guidelines|directives|constraints|policy|policies)\b", re.I)),
    ("new_instructions", 0.7, "announces replacement instructions",
     re.compile(r"\b(new|updated|revised|real|actual)\s+(instructions?|task|objective|directive|system prompt)\b", re.I)),
    ("role_hijack", 0.7, "tries to reassign the agent's role",
     re.compile(r"\b(you are now|from now on you|act as (?:an? )?(?:admin|system|developer|payment)|"
                r"your (?:new )?(?:role|task|goal) is)\b", re.I)),
    ("fake_role_marker", 0.8, "fake system/assistant chat markers",
     re.compile(r"(<\|im_start\|>|<\|im_end\|>|\[/?INST\]|<<SYS>>|^\s*(?:system|assistant)\s*:|###\s*(?:system|instruction))",
                re.I | re.M)),
    # Strong: a money verb aimed at a destination (account, wallet, address, e-mail...).
    ("payment_command", 0.85, "orders the agent to pay/transfer/send money to a destination",
     re.compile(r"\b(pay|transfer|send|wire|remit|charge|authori[sz]e|redirect|forward)\b[^.\n]{0,60}"
                r"(\bto\s+(?:the\s+|this\s+|that\s+|my\s+|a\s+)?(?:new\s+)?(?:account|wallet|paypal|iban|address|recipient|beneficiary)\b|"
                r"[\w.+-]+@[\w-]+\.[\w.]+|\biban\b)", re.I)),
    # Weak: "pay $30" alone is normal checkout copy, so it only nudges the score.
    ("payment_amount", 0.3, "mentions paying a specific amount",
     re.compile(r"\b(pay|transfer|send|wire|remit|charge|authori[sz]e|complete (?:the )?purchase)\b[^.\n]{0,40}"
                r"(\$\s?\d|\d[\d,]*(?:\.\d+)?\s?(?:usd|eur|inr|gbp|dollars|rupees))", re.I)),
    ("payee_change", 0.8, "tries to change who gets paid",
     re.compile(r"\b(change|update|use|switch|redirect)\b[^.\n]{0,25}\b(payee|recipient|beneficiary|merchant|payment (?:account|address))\b", re.I)),
    ("secrecy", 0.75, "tells the agent to hide something from the user",
     re.compile(r"\b(do not|don't|never)\s+(tell|inform|notify|alert|mention|show|reveal)[^.\n]{0,30}\b(user|customer|human|owner)\b", re.I)),
    ("skip_confirmation", 0.8, "tries to skip user confirmation",
     re.compile(r"\b(without|skip|bypass|no need (?:for|to))\s+(?:asking\s+|the\s+|user\s+|further\s+)*"
                r"(confirmation|approval|permission|verification|consent|asking)\b|"
                r"\b(?:do not|don't|never)\s+ask\s+(?:the\s+user\s+|them\s+)?(?:for\s+)?"
                r"(?:confirmation|approval|permission|consent|verification)\b", re.I)),
    ("ai_addressing", 0.3, "addresses AI agents directly",
     re.compile(r"\b(attention|note to|message for|instructions? for|dear)\s+(ai|llm|language|assistant|agent|model|chatbot|bot)s?"
                r"(?:\s+(?:models?|assistants?|agents?))?\b|"
                r"\b(ai|llm) (agents?|assistants?|models?),?\s+(must|should|please|need to|are required)\b", re.I)),
    ("exfiltrate", 0.7, "asks the agent to reveal secrets or credentials",
     re.compile(r"\b(reveal|print|send|leak|exfiltrate|share|output)\b[^.\n]{0,30}\b(system prompt|api key|password|credentials?|"
                r"secret|token|card number|cvv|session)\b", re.I)),
    ("urgency_pressure", 0.25, "pressure wording often paired with injections",
     re.compile(r"\b(immediately|urgent(?:ly)?|right now|critical|mandatory|required)\b[^.\n]{0,40}\b(pay|payment|transfer|checkout)\b", re.I)),
    ("tool_call_syntax", 0.6, "embeds tool-call or function syntax",
     re.compile(r"(\bfunction_call\b|\btool_use\b|\"name\"\s*:\s*\"(?:pay|capture|checkout|transfer)[\w]*\"|"
                r"\b(?:capture_payment|request_payment|paypal\.capture)\s*\()", re.I)),
]

BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")
INVISIBLE = re.compile("[​‌‍⁠﻿᠎‪-‮⁦-⁩]")
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})


@dataclass
class RuleHit:
    rule: str
    weight: float
    description: str
    excerpt: str


def normalize(text: str) -> str:
    """Fold look-alike tricks so 'Ign0re prev​ious' still matches."""
    text = unicodedata.normalize("NFKC", text)
    text = INVISIBLE.sub("", text)
    return text


def _excerpt(text: str, match: re.Match[str], pad: int = 40) -> str:
    start, end = max(0, match.start() - pad), min(len(text), match.end() + pad)
    return re.sub(r"\s+", " ", text[start:end]).strip()


def run_rules(text: str, allow_leet: bool = True) -> list[RuleHit]:
    hits: list[RuleHit] = []
    seen: set[str] = set()
    variants = [normalize(text)]
    if allow_leet:
        variants.append(variants[0].translate(LEET))
    for variant in variants:
        for rid, weight, desc, pattern in RULES:
            if rid in seen:
                continue
            m = pattern.search(variant)
            if m:
                seen.add(rid)
                hits.append(RuleHit(rid, weight, desc, _excerpt(variant, m)))
    return hits


def decode_base64_blobs(text: str, limit: int = 5) -> list[str]:
    out: list[str] = []
    for m in BASE64_BLOB.finditer(text):
        blob = m.group(1)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except Exception:  # noqa: BLE001
            continue
        if decoded.isprintable() or "\n" in decoded:
            out.append(decoded)
        if len(out) >= limit:
            break
    return out
