"""Pure detectors over OCR text and decoded codes. No I/O, fully unit-testable.

Three families, matching the product story:
- leaks   : secrets and PII that must not leave the screen (outbound)
- quishing: QR codes aimed at viewers (inbound, humans)
- injection: instructions aimed at agents that watch the feed (inbound, agents)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

Severity = str  # "critical" | "high" | "medium" | "low"


@dataclass(frozen=True)
class Finding:
    kind: str  # leak | quishing | injection
    rule: str
    severity: Severity
    match: str
    reason: str
    box: tuple[float, float, float, float] | None = None  # x, y, w, h in pixels
    meta: dict = field(default_factory=dict)


# --- leaks -----------------------------------------------------------------

# AI-NOTE: patterns kept short on purpose; Semgrep secrets rules are run on the same text
# by `semgrep_bridge.py`, these are the fast path for the live loop.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical"),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b"), "critical"),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "critical"),
    ("openai-key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{20,}\b"), "critical"),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), "critical"),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high"),
    ("private-key-block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "critical"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "high"),
    ("password-assignment", re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*\S{6,}"), "high"),
    ("db-connection-string", re.compile(r"\b(postgres|mysql|mongodb(\+srv)?|redis)://[^\s]+:[^\s]+@[^\s]+"), "critical"),
    ("env-secret", re.compile(r"\b[A-Z][A-Z0-9_]*(SECRET|TOKEN|API_KEY|PASSWORD)[A-Z0-9_]*\s*=\s*\S{8,}"), "high"),
]

PII_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "low"),
    ("us-ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), "high"),
    ("phone", re.compile(r"\b(\+?1[ -.]?)?\(?\d{3}\)?[ -.]?\d{3}[ -.]?\d{4}\b"), "low"),
    ("credit-card", re.compile(r"\b(?:\d[ -]?){13,16}\b"), "high"),
]


def _luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) < 13:
        return False
    total, parity = 0, len(d) % 2
    for i, n in enumerate(d):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def detect_leaks(text: str, box=None) -> list[Finding]:
    out: list[Finding] = []
    for rule, pat, sev in SECRET_PATTERNS:
        for m in pat.finditer(text):
            out.append(Finding("leak", rule, sev, m.group(0), "secret format on screen", box))
    for rule, pat, sev in PII_PATTERNS:
        for m in pat.finditer(text):
            s = m.group(0)
            if rule == "credit-card" and not _luhn_ok(s):
                continue
            out.append(Finding("leak", rule, sev, s, "PII on screen", box))
    return out


# --- quishing --------------------------------------------------------------

SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "icu", "click", "cam", "rest", "gq", "tk", "ml"}
SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "qrco.de"}
BRAND_WORDS = ("microsoft", "office365", "okta", "zoom", "google", "apple", "paypal", "duo", "canvas")


def assess_url(url: str, allowed_domains: set[str] | None = None) -> tuple[Severity, str]:
    """Static checks only; a live reputation lookup can upgrade the verdict later."""
    try:
        u = urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        return "medium", "unparseable url"
    host = (u.hostname or "").lower()
    if not host:
        return "medium", "no host"
    if allowed_domains and any(host == d or host.endswith("." + d) for d in allowed_domains):
        return "low", "allowed domain"
    if host in SHORTENERS:
        return "high", "url shortener hides destination"
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
        return "high", "raw ip address"
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        return "high", f"suspicious tld .{tld}"
    label = host.replace("-", "").replace(".", "")
    for b in BRAND_WORDS:
        if b in label and not host.endswith((f"{b}.com", f"{b}.net")):
            return "high", f"brand lookalike ({b})"
    if u.scheme == "http":
        return "medium", "plain http"
    return "medium", "unknown destination shown to viewers"


def detect_quishing(codes: list[dict], allowed_domains: set[str] | None = None) -> list[Finding]:
    out: list[Finding] = []
    for c in codes:
        payload = c.get("payload", "")
        if not payload:
            continue
        box = c.get("box")
        b = (box["x"], box["y"], box["w"], box["h"]) if box else None
        if re.match(r"(?i)^(https?://|www\.)", payload) or re.match(r"^[a-z0-9.-]+\.[a-z]{2,}(/|$)", payload, re.IGNORECASE):
            sev, why = assess_url(payload, allowed_domains)
            out.append(Finding("quishing", "qr-url", sev, payload, why, b, {"symbology": c.get("symbology")}))
        elif payload.lower().startswith(("wifi:", "otpauth:", "sms:", "tel:")):
            out.append(Finding("quishing", "qr-action", "high", payload, "action qr shown to viewers", b))
        else:
            out.append(Finding("quishing", "qr-opaque", "low", payload[:80], "non-url qr payload", b))
    return out


# --- injection -------------------------------------------------------------

INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("override-instructions", re.compile(r"(?i)\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|all|your|the)\s+(system\s+)?(instructions?|rules?|prompts?|guidelines?|policy)\b"), "critical"),
    ("agent-address", re.compile(r"(?i)\b(ai|assistant|agent|copilot|claude|gpt|llm)\b\s*[:,]?\s*(you must|please|now)\b"), "high"),
    ("system-prompt-marker", re.compile(r"(?i)(\[?system\]?\s*:|<\|?system\|?>|###\s*instruction)"), "high"),
    ("tool-call-request", re.compile(r"(?i)\b(call|invoke|run|execute|use)\b.{0,20}\b(tool|function|mcp)\b"), "high"),
    ("device-control-verbs", re.compile(r"(?i)\b(set|change|switch|redirect|point)\b.{0,30}\b(rtmp|srt|stream (destination|url|key|output)|destination|output url|admin (password|user)|root password)\b"), "critical"),
    ("exfil-verbs", re.compile(r"(?i)\b(send|post|upload|forward)\b.{0,30}\b(to|at)\b.{0,10}(https?://|rtmp://|srt://)"), "critical"),
]


def detect_injection(text: str, box=None) -> list[Finding]:
    out: list[Finding] = []
    for rule, pat, sev in INJECTION_PATTERNS:
        m = pat.search(text)
        if m:
            out.append(Finding("injection", rule, sev, m.group(0), "instruction-like text in the frame", box))
    return out


# --- all together ------------------------------------------------------------

def detect_all(texts: list[dict], codes: list[dict], allowed_domains: set[str] | None = None) -> list[Finding]:
    """texts: [{text, conf, box}] from OCR; codes: [{payload, symbology, box}]."""
    findings: list[Finding] = []
    joined = " ".join(t["text"] for t in texts)  # instructions span OCR lines
    for t in texts:
        box = t.get("box")
        b = (box["x"], box["y"], box["w"], box["h"]) if box else None
        findings += detect_leaks(t["text"], b)
    # injection reads the whole frame: instructions often span lines
    findings += detect_injection(joined)
    findings += detect_quishing(codes, allowed_domains)
    return findings
