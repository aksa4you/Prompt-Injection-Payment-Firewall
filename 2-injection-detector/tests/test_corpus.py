"""Regression tests over the shipped corpus. Add every new attack you find to app/corpus.py."""
import pytest

from app.classifier import classify
from app.corpus import BENIGN, MALICIOUS


@pytest.mark.parametrize("sample", MALICIOUS)
def test_every_known_attack_is_flagged(sample):
    res = classify(html=f'<div style="display:none">{sample}</div>')
    assert res["recommendation"] in ("review", "block"), (sample, res["risk"])


@pytest.mark.parametrize("sample", MALICIOUS)
def test_known_attacks_flagged_even_when_plain_visible_text(sample):
    res = classify(text=sample)
    assert res["risk"] >= 0.35, (sample, res["risk"])


@pytest.mark.parametrize("sample", BENIGN)
def test_benign_copy_is_not_flagged(sample):
    res = classify(html=f"<p>{sample}</p>")
    assert res["recommendation"] == "allow", (sample, res["findings"])
