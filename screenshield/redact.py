"""Redaction: blur boxes in a recording for given time ranges, one ffmpeg pass.

Each Region is (t_from, t_to, x, y, w, h) in seconds and pixels of the source video.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Region:
    t_from: float
    t_to: float
    x: float
    y: float
    w: float
    h: float
    pad: float = 8.0


def _even(v: float) -> int:
    n = max(2, int(round(v)))
    return n if n % 2 == 0 else n + 1


def build_filter(regions: list[Region]) -> str:
    """Chain of crop→boxblur→overlay, each overlay enabled only inside its time window."""
    parts: list[str] = []
    prev = "0:v"
    for i, r in enumerate(regions):
        x, y = max(0, int(r.x - r.pad)), max(0, int(r.y - r.pad))
        w, h = _even(r.w + 2 * r.pad), _even(r.h + 2 * r.pad)
        parts.append(f"[{prev}]split[s{i}][p{i}]")
        parts.append(f"[p{i}]crop={w}:{h}:{x}:{y},boxblur=luma_radius=12:luma_power=2:chroma_radius=5:chroma_power=2[b{i}]")
        parts.append(f"[s{i}][b{i}]overlay={x}:{y}:enable='between(t,{r.t_from:.3f},{r.t_to:.3f})'[v{i}]")
        prev = f"v{i}"
    return ";".join(parts), prev


def redact(src: Path, dst: Path, regions: list[Region]) -> Path:
    if not regions:
        raise ValueError("no regions")
    graph, last = build_filter(regions)
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", str(src),
           "-filter_complex", graph, "-map", f"[{last}]", "-map", "0:a?",
           "-c:v", "libx264", "-preset", "veryfast", "-crf", "20", "-c:a", "copy", str(dst)]
    subprocess.run(cmd, check=True)
    return dst


def regions_from_findings(findings: list[dict], hold: float = 1.0) -> list[Region]:
    """Turn finding records (ts, box) into regions; each finding blurs from its keyframe for `hold`
    seconds or until the next keyframe, whichever is later (caller may merge)."""
    out: list[Region] = []
    for f in findings:
        box = f.get("box")
        if not box:
            continue
        x, y, w, h = box
        out.append(Region(f["ts"], f["ts"] + max(hold, f.get("dur", 0.0)), x, y, w, h))
    return out
