"""Policy: what the agent must know BEFORE it acts. Read from Senso (verified org context) when a key
is present, else from policy.json next to the repo. The frame can never change it.

Policy fields:
  allowed_qr_domains     : QR codes pointing here are fine for viewers
  approved_destinations  : hosts a device may stream/upload to
  sensitive_classes      : what counts as sensitive for this org (used by the vision step and the eval)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

SENSO = "https://apiv2.senso.ai/api/v1"
DEFAULT = Path(__file__).resolve().parent.parent / "policy.json"


@dataclass
class Policy:
    org: str = "demo"
    allowed_qr_domains: set[str] = field(default_factory=set)
    approved_destinations: set[str] = field(default_factory=set)
    sensitive_classes: list[str] = field(default_factory=list)
    source: str = "default"

    @classmethod
    def load(cls, path: Path | None = None) -> Policy:
        key = os.environ.get("SENSO_API_KEY")
        if key:
            try:
                return cls.from_senso(key)
            except Exception as e:  # fall back loudly, never silently
                print(f"# senso policy unavailable ({e}); using local policy.json")
        p = path or DEFAULT
        if p.exists():
            d = json.loads(p.read_text())
            return cls(d.get("org", "demo"), set(d.get("allowed_qr_domains", [])),
                       set(d.get("approved_destinations", [])), d.get("sensitive_classes", []), f"file:{p.name}")
        return cls()

    @classmethod
    def from_senso(cls, key: str) -> Policy:
        """The org's policy document lives in Senso's knowledge base; we ask for the passages and parse the
        JSON block inside. Writing the policy there is a one-time `shield policy push`."""
        import httpx

        r = httpx.post(f"{SENSO}/org/search/context", headers={"X-API-Key": key},
                       json={"query": "ScreenShield policy: allowed QR domains, approved stream destinations, sensitive classes"},
                       timeout=20)
        r.raise_for_status()
        for res in r.json().get("results", []):
            txt = res.get("chunk_text", "")
            if "{" in txt and "approved_destinations" in txt:
                d = json.loads(txt[txt.index("{"): txt.rindex("}") + 1])
                return cls(d.get("org", "demo"), set(d.get("allowed_qr_domains", [])),
                           set(d.get("approved_destinations", [])), d.get("sensitive_classes", []), "senso")
        raise RuntimeError("no policy document in Senso")

    def push_to_senso(self, key: str) -> dict:
        import httpx

        body = {"org": self.org, "allowed_qr_domains": sorted(self.allowed_qr_domains),
                "approved_destinations": sorted(self.approved_destinations), "sensitive_classes": self.sensitive_classes}
        text = "ScreenShield policy (allowed QR domains, approved stream destinations, sensitive classes):\n" + json.dumps(body)
        r = httpx.post(f"{SENSO}/org/kb/raw", headers={"X-API-Key": key},
                       json={"title": "ScreenShield policy", "text": text}, timeout=20)
        if r.status_code == 409:
            return {"status": "already present"}
        r.raise_for_status()
        return r.json()
