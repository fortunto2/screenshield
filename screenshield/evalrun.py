"""shield eval: run the real OCR + detector path over fixtures/ and report what was caught.

Each fixture image may have a sidecar `<name>.expect.json` listing rules that must fire
and rules that must NOT fire. Fixtures are hand-made test data, added one at a time.
"""

from __future__ import annotations

import json
from pathlib import Path

from .detectors import detect_all
from .ocr import scan_images


def run_eval(fixtures: Path, allowed: set[str] | None = None) -> dict:
    images = sorted(p for p in fixtures.iterdir() if p.suffix.lower() in {".png", ".jpg", ".jpeg"})
    results = scan_images(images)
    report = {"fixtures": [], "expected_hits": 0, "caught": 0, "false_positives": 0}
    for img, res in zip(images, results, strict=True):
        got = {f.rule for f in detect_all(res["texts"], res["codes"], allowed)}
        side = img.with_suffix(".expect.json")
        exp = json.loads(side.read_text()) if side.exists() else {"must": [], "must_not": []}
        must, must_not = set(exp.get("must", [])), set(exp.get("must_not", []))
        missed = sorted(must - got)
        fp = sorted(got & must_not)
        report["expected_hits"] += len(must)
        report["caught"] += len(must & got)
        report["false_positives"] += len(fp)
        report["fixtures"].append({"image": img.name, "got": sorted(got), "missed": missed, "false_positives": fp,
                                   "ocr_lines": len(res["texts"]), "codes": len(res["codes"])})
    report["catch_rate"] = round(report["caught"] / report["expected_hits"], 3) if report["expected_hits"] else None
    return report
