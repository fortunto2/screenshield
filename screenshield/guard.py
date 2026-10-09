"""Agent guard: video is an untrusted channel. Two deterministic gates outside the model.

1. Taint gate   : any tool argument that contains a token first seen in frame text (external content)
                  is tainted; a tainted write call is blocked.
2. Approved-destination gate : write tools that point a device somewhere (stream destination, upload
                  target, admin URL) only accept allowlisted destinations. The allowlist cannot be
                  extended from the frame, only from policy (Senso / config).

Vocabulary borrowed from Chaowei Xiao's "safeguards" slide: isolate external content, approve recipients.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

READ_TOOLS = {"get_stream_status", "list_devices", "get_device", "get_recording_status"}
WRITE_TOOLS = {"set_stream_destination", "start_stream", "stop_stream", "reboot", "set_admin_password",
               "upload_recording", "factory_reset"}
DESTINATION_ARGS = {"url", "destination", "rtmp_url", "srt_url", "target", "upload_to"}


@dataclass
class Verdict:
    allowed: bool
    verdict: str  # allowed | blocked | needs_human
    reason: str
    tainted: bool = False
    evidence: dict = field(default_factory=dict)


@dataclass
class Guard:
    approved_destinations: set[str] = field(default_factory=set)  # hostnames
    window_s: float = 120.0
    _seen: list[tuple[float, str]] = field(default_factory=list)  # (ts, token) from frames

    # --- external content ----------------------------------------------------
    def observe_frame_text(self, ts: float, text: str) -> None:
        """Register tokens that appeared in a frame. Short tokens are ignored (too common)."""
        for tok in _tokens(text):
            self._seen.append((ts, tok))
        cutoff = ts - self.window_s
        self._seen = [(t, k) for t, k in self._seen if t >= cutoff]

    def _tainted_tokens(self, args: dict) -> list[str]:
        blob = json.dumps(args, ensure_ascii=False)
        arg_tokens = set(_tokens(blob))
        seen = {k for _, k in self._seen}
        return sorted(arg_tokens & seen)

    # --- gates -----------------------------------------------------------------
    def check(self, ts: float, tool: str, args: dict) -> Verdict:
        if tool in READ_TOOLS:
            return Verdict(True, "allowed", "read-only tool")
        tainted = self._tainted_tokens(args)
        if tainted:
            return Verdict(False, "blocked", "argument value appeared in frame text (external content)",
                           True, {"tokens": tainted})
        for k, v in args.items():
            if k in DESTINATION_ARGS and isinstance(v, str):
                host = (urlparse(v if "://" in v else "//" + v).hostname or "").lower()
                if not any(host == d or host.endswith("." + d) for d in self.approved_destinations):
                    return Verdict(False, "needs_human", f"destination {host or v!r} is not approved",
                                   False, {"host": host})
        if tool in {"factory_reset", "set_admin_password"}:
            return Verdict(False, "needs_human", "destructive tool requires a human")
        if tool in WRITE_TOOLS:
            return Verdict(True, "allowed", "write tool, clean args, approved destination")
        return Verdict(False, "needs_human", f"unknown tool {tool}")


_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{5,}")


def _tokens(text: str) -> list[str]:
    """Tokens worth tracking: urls, hosts, keys, words >= 6 chars. Lowercased."""
    out = []
    for m in _TOKEN.finditer(text):
        t = m.group(0).strip(".:/").lower()
        if len(t) >= 6:
            out.append(t)
    return out


# --- injection isolator (DRIFT, Li & Xiao et al., NeurIPS 2025) ------------------------

def isolate(texts: list[dict]) -> tuple[str, list[str]]:
    """Return frame text safe to show an agent, with instruction-like lines removed and listed.

    The agent still learns *that* there was text (and where), never *what it ordered*.
    """
    from .detectors import detect_injection

    clean: list[str] = []
    stripped: list[str] = []
    for t in texts:
        line = t["text"]
        if detect_injection(line):
            stripped.append(line)
            clean.append("[external content removed: instruction-like text]")
        else:
            clean.append(line)
    return "\n".join(clean), stripped
