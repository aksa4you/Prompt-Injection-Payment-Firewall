"""Combine structural signals, regex rules and the Naive Bayes opinion into one risk score.

risk = noisy-OR over every finding, so one strong finding is enough and many weak ones add up.
Thresholds: >= BLOCK_AT -> block, >= REVIEW_AT -> review, otherwise allow.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Optional

from . import nb
from .htmlscan import Fragment, PageText, scan_html
from .rules import RuleHit, decode_base64_blobs, run_rules

BLOCK_AT = 0.70
REVIEW_AT = 0.35

# a rule hit counts for more when it sits where a shopper cannot see it
LOCATION_MULTIPLIER = {"hidden": 1.0, "comment": 1.0, "attribute": 0.95, "script": 0.7,
                       "decoded": 1.0, "context": 0.9, "visible": 0.8}


@dataclass
class Finding:
    kind: str  # rule | hidden_text | invisible_chars | encoded_payload | ml_signal
    rule: str
    severity: float
    where: str
    description: str
    excerpt: str


def _clip(text: str, n: int = 160) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= n else text[: n - 1] + "…"


def _scan_group(frags: list[Fragment], location: str, findings: list[Finding]) -> None:
    found: set[str] = set()
    for frag in frags:
        for hit in run_rules(frag.text):
            found.add(hit.rule)
            sev = min(hit.weight * LOCATION_MULTIPLIER[location], 0.99)
            where = f"{location}: {frag.where}" + (f" ({frag.reason})" if frag.reason else "")
            findings.append(Finding("rule", hit.rule, round(sev, 3), where, hit.description,
                                    _clip(hit.excerpt)))
    # A phrase can be split across tags, or by a stray "<" that the HTML parser treats as a tag
    # boundary ("<|im_start|>" becomes two fragments). Re-run the rules on the group's joined text.
    if len(frags) > 1:
        texts = [f.text for f in frags]
        for joined in (" ".join(texts), "".join(texts)):
            for hit in run_rules(joined):
                if hit.rule in found:
                    continue
                found.add(hit.rule)
                sev = min(hit.weight * LOCATION_MULTIPLIER[location], 0.99)
                findings.append(Finding("rule", hit.rule, round(sev, 3), f"{location}: across elements",
                                        hit.description, _clip(hit.excerpt)))


def classify(html: str = "", text: str = "", context: str = "", url: str = "") -> dict:
    page: PageText = scan_html(html)
    findings: list[Finding] = []

    # 1. rules, run per fragment so we know *where* the text lives
    _scan_group(page.visible, "visible", findings)
    _scan_group(page.hidden, "hidden", findings)
    _scan_group(page.comments, "comment", findings)
    _scan_group(page.attributes, "attribute", findings)
    _scan_group(page.scripts, "script", findings)
    if text:
        _scan_group([Fragment(text, "plain text")], "visible", findings)
    if context:
        _scan_group([Fragment(context, "agent context")], "context", findings)
    # 2. structure: hidden text is suspicious by itself, more so if it reads like an instruction
    for frag in page.hidden:
        if len(frag.text) >= 25:
            findings.append(Finding("hidden_text", "hidden_text", 0.2, f"hidden: {frag.where} ({frag.reason})",
                                    "substantial text hidden from human readers", _clip(frag.text)))
    if page.zero_width_count >= 3:
        findings.append(Finding("invisible_chars", "zero_width", 0.35, "text",
                                f"{page.zero_width_count} zero-width characters", ""))
    if page.bidi_count >= 1:
        findings.append(Finding("invisible_chars", "bidi_override", 0.4, "text",
                                f"{page.bidi_count} bidirectional override characters", ""))

    # 3. encoded payloads
    searchable = " ".join([page.all_text, text, context])
    for decoded in decode_base64_blobs(searchable):
        for hit in run_rules(decoded):
            findings.append(Finding("encoded_payload", hit.rule, round(min(hit.weight, 0.99), 3), "decoded base64",
                                    "base64 blob decodes to: " + hit.description, _clip(decoded)))

    # 4. soft ML signal, scored only on text a shopper would not read
    unseen = " ".join(f.text for g in (page.hidden, page.comments, page.attributes, page.scripts) for f in g)
    ml = nb.score_text(unseen) if unseen.strip() else 0.0
    if ml >= 0.9:
        findings.append(Finding("ml_signal", "naive_bayes", round(0.3 * (ml - 0.85) / 0.15, 3), "unseen text",
                                f"hidden/meta text reads like known injections (p={ml:.2f})", _clip(unseen)))

    # noisy-OR
    keep = 1.0
    for f in findings:
        keep *= 1.0 - f.severity
    risk = round(1.0 - keep, 4)
    if risk >= BLOCK_AT:
        recommendation, level = "block", "high"
    elif risk >= REVIEW_AT:
        recommendation, level = "review", "medium"
    else:
        recommendation, level = "allow", "low"

    findings.sort(key=lambda f: f.severity, reverse=True)
    return {
        "risk": risk,
        "level": level,
        "recommendation": recommendation,
        "findings": [asdict(f) for f in findings[:25]],
        "stats": {
            "visible_fragments": len(page.visible),
            "hidden_fragments": len(page.hidden),
            "comments": len(page.comments),
            "zero_width_chars": page.zero_width_count,
            "ml_probability": round(ml, 3),
        },
        "page_hash": hashlib.sha256((html or text or "").encode()).hexdigest(),
        "url": url,
    }
