from pathlib import Path

from screenshield.policy import Policy


def test_local_policy_loads(monkeypatch):
    monkeypatch.delenv("SENSO_API_KEY", raising=False)
    p = Policy.load(Path(__file__).resolve().parent.parent / "policy.json")
    assert "live.campus-cloud.example" in p.approved_destinations and p.source.startswith("file:")
