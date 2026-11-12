"""Split a page into text a human sees and text a human does not see.

Attackers hide instructions where an LLM reads them but a shopper never does. This module walks the
HTML with the standard-library parser and sorts every text node, comment, attribute and meta tag into
*visible* or *hidden*, recording why it counted as hidden.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
        "source", "track", "wbr"}
SKIP_TEXT = {"script", "style", "noscript", "template"}  # not rendered as page text
HIDING_STYLES = [
    (re.compile(r"display\s*:\s*none", re.I), "display:none"),
    (re.compile(r"visibility\s*:\s*hidden", re.I), "visibility:hidden"),
    (re.compile(r"font-size\s*:\s*0(?:\.0+)?(?:px|pt|em|rem|%)?\s*(?:;|$)", re.I), "font-size:0"),
    (re.compile(r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)", re.I), "opacity:0"),
    (re.compile(r"(?:left|top|right|bottom|text-indent)\s*:\s*-\d{3,}", re.I), "off-screen position"),
    (re.compile(r"(?:width|height)\s*:\s*0(?:px)?\s*(?:;|$).*overflow\s*:\s*hidden", re.I | re.S), "zero-size box"),
    (re.compile(r"clip\s*:\s*rect\(\s*0", re.I), "clipped"),
    (re.compile(r"color\s*:\s*(?:#fff(?:fff)?|white)\b.*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white)\b",
                re.I | re.S), "white on white"),
]
TEXT_ATTRS = ("alt", "title", "aria-label", "placeholder", "content", "value")
ZERO_WIDTH = re.compile("[​‌‍⁠﻿᠎]")
BIDI = re.compile("[‪-‮⁦-⁩]")


@dataclass
class Fragment:
    text: str
    where: str  # e.g. "div.style", "comment", "alt attribute"
    reason: str = ""


@dataclass
class PageText:
    visible: list[Fragment] = field(default_factory=list)
    hidden: list[Fragment] = field(default_factory=list)
    comments: list[Fragment] = field(default_factory=list)
    attributes: list[Fragment] = field(default_factory=list)
    scripts: list[Fragment] = field(default_factory=list)
    zero_width_count: int = 0
    bidi_count: int = 0

    @property
    def visible_text(self) -> str:
        return " ".join(f.text for f in self.visible)

    @property
    def all_text(self) -> str:
        parts = [self.visible_text]
        for group in (self.hidden, self.comments, self.attributes, self.scripts):
            parts.extend(f.text for f in group)
        return " ".join(parts)


class _Scanner(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.result = PageText()
        self._stack: list[tuple[str, str]] = []  # (tag, hidden_reason or "")

    def _hidden_reason(self) -> str:
        for _, reason in reversed(self._stack):
            if reason:
                return reason
        return ""

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        reason = ""
        if "hidden" in a and tag != "input":
            reason = "hidden attribute"
        elif a.get("aria-hidden", "").lower() == "true":
            reason = "aria-hidden"
        elif tag == "input" and a.get("type", "").lower() == "hidden":
            reason = "hidden input"
        else:
            style = a.get("style", "")
            for pattern, label in HIDING_STYLES:
                if pattern.search(style):
                    reason = label
                    break
        # attribute text that machines read but people rarely see
        for name in TEXT_ATTRS:
            if name in a and a[name].strip():
                if tag == "meta" and name == "content" or name != "content":
                    self.result.attributes.append(Fragment(a[name], f"<{tag}> {name}"))
        for name, value in a.items():
            if name.startswith("data-") and len(value) > 15:
                self.result.attributes.append(Fragment(value, f"<{tag}> {name}"))
        if tag in SKIP_TEXT:
            self._stack.append((tag, reason))
            return
        if tag not in VOID:
            self._stack.append((tag, reason))
        elif reason and tag == "input" and a.get("value"):
            self.result.hidden.append(Fragment(a["value"], f"<{tag}>", reason))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in VOID and self._stack and self._stack[-1][0] == tag:
            self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break

    def handle_data(self, data: str) -> None:
        text = data.strip()
        if not text:
            return
        self.result.zero_width_count += len(ZERO_WIDTH.findall(data))
        self.result.bidi_count += len(BIDI.findall(data))
        current = self._stack[-1][0] if self._stack else ""
        if any(t in SKIP_TEXT for t, _ in self._stack):
            if current in ("script", "style", "noscript", "template") and current != "style":
                self.result.scripts.append(Fragment(text, f"<{current}>"))
            return
        reason = self._hidden_reason()
        frag = Fragment(text, f"<{current or 'text'}>", reason)
        (self.result.hidden if reason else self.result.visible).append(frag)

    def handle_comment(self, data: str) -> None:
        if data.strip():
            self.result.comments.append(Fragment(data.strip(), "html comment"))


def scan_html(html: str) -> PageText:
    scanner = _Scanner()
    try:
        scanner.feed(html or "")
        scanner.close()
    except Exception:  # noqa: BLE001  malformed HTML must never crash the firewall
        pass
    return scanner.result
