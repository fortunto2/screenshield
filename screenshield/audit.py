"""shield audit: the slow loop. Walk an archive of recordings, run the fast path on each, hand findings to the
responder, and write the dataset the fast loop learns from (labelled keyframes + expectations) plus a report."""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import asdict
from pathlib import Path

from .detectors import detect_all
from .frames import iter_frames
from .ocr import scan_images
from .policy import Policy
from .respond import Responder, fleet_facts
from .store import Store
from .vision_llm import review_frame

VIDEO = {".mp4", ".mov", ".mkv", ".webm", ".m4v"}


def audit(archive: Path, work: Path, dataset: Path, fps: float = 1.0, min_change: int = 8,
          vision: bool = True, dry_run: bool = True) -> dict:
    policy = Policy.load()
    store = Store(work)
    responder = Responder(policy, store, dry_run=dry_run)
    dataset.mkdir(parents=True, exist_ok=True)
    report = {"recordings": 0, "keyframes": 0, "findings": 0, "vision_calls": 0, "vision_hits": 0, "actions": 0,
              "dataset_items": 0, "seconds": 0.0, "policy": policy.source, "store": store.backend}
    t0 = time.time()
    files = sorted(p for p in archive.rglob("*") if p.suffix.lower() in VIDEO)
    for rec in files:
        report["recordings"] += 1
        stream_id = rec.stem
        for frame in iter_frames(str(rec), work / "frames" / stream_id, fps=fps, min_change=min_change):
            report["keyframes"] += 1
            res = scan_images([frame.path])[0]
            findings = detect_all(res["texts"], res["codes"], policy.allowed_qr_domains)
            labels = [f.rule for f in findings]
            # vision review only where the fast path is blind: text-heavy frame with no deterministic hit
            if vision and not findings and len(res["texts"]) >= 5:
                v = review_frame(frame.path, policy.sensitive_classes)
                if v is not None:
                    report["vision_calls"] += 1
                    if v.get("sensitive"):
                        report["vision_hits"] += 1
                        labels.append(f"vision:{v.get('class', 'unknown')}")
                        findings.append(_vision_finding(v))
            for f in findings:
                rec_row = {"ts": frame.ts, "stream_id": stream_id, "room_id": stream_id.split("-")[0],
                           "frame_path": str(frame.path), **asdict(f)}
                report["findings"] += 1
                report["actions"] += len(responder.respond(rec_row, fleet_facts(store, rec_row)))
            if labels:
                item = dataset / f"{stream_id}_{frame.index:06d}.png"
                shutil.copy(frame.path, item)
                item.with_suffix(".expect.json").write_text(json.dumps(
                    {"must": sorted({x for x in labels if not x.startswith('vision:')}), "must_not": [],
                     "vision": [x for x in labels if x.startswith("vision:")], "source": rec.name, "t": frame.ts}, indent=1))
                report["dataset_items"] += 1
    report["seconds"] = round(time.time() - t0, 1)
    (dataset / "report.json").write_text(json.dumps(report, indent=1))
    return report


def _vision_finding(v: dict):
    from .detectors import Finding

    return Finding("leak", f"vision-{v.get('class', 'unknown').replace(' ', '-')[:30]}",
                   "high" if float(v.get("confidence", 0)) >= 0.7 else "medium",
                   v.get("region", ""), v.get("why", "vision review"), None, {"vision": v})
