"""A tiny multinomial Naive Bayes in pure Python: a soft second opinion for phrasing the regexes miss.

Trained at import time from app/corpus.py (a few dozen examples), so there is no model file to ship.
It only *adds* a little to the score; the deterministic rules stay in charge.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .corpus import BENIGN, MALICIOUS

TOKEN = re.compile(r"[a-z]{2,}|\$|\d+")
STOP = {"the", "a", "an", "is", "are", "to", "of", "and", "in", "on", "for", "with", "it", "this", "that"}


def tokens(text: str) -> list[str]:
    return [t for t in TOKEN.findall(text.lower()) if t not in STOP]


class NaiveBayes:
    def __init__(self, benign: list[str], malicious: list[str]) -> None:
        self.counts = {0: Counter(), 1: Counter()}
        for label, docs in ((0, benign), (1, malicious)):
            for d in docs:
                self.counts[label].update(tokens(d))
        self.vocab = set(self.counts[0]) | set(self.counts[1])
        self.totals = {k: sum(v.values()) for k, v in self.counts.items()}
        self.priors = {0: len(benign) / (len(benign) + len(malicious)),
                       1: len(malicious) / (len(benign) + len(malicious))}

    def prob_malicious(self, text: str) -> float:
        toks = [t for t in tokens(text) if t in self.vocab]
        if not toks:
            return 0.0
        logp = {}
        for label in (0, 1):
            lp = math.log(self.priors[label])
            for t in toks:
                lp += math.log((self.counts[label][t] + 1) / (self.totals[label] + len(self.vocab)))
            logp[label] = lp
        m = max(logp.values())
        e0, e1 = math.exp(logp[0] - m), math.exp(logp[1] - m)
        return e1 / (e0 + e1)


MODEL = NaiveBayes(BENIGN, MALICIOUS)


def score_text(text: str, window: int = 60) -> float:
    """Highest malicious probability across sliding windows of the text."""
    toks = text.split()
    if not toks:
        return 0.0
    best = 0.0
    step = max(window // 2, 1)
    for i in range(0, max(len(toks) - window, 0) + 1, step):
        best = max(best, MODEL.prob_malicious(" ".join(toks[i:i + window])))
    return best
