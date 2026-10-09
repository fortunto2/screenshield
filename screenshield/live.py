"""shield live: watch a source, write findings to the store, keep a rolling recording,
and hand frame text to the guard so a watching agent cannot be steered by it."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

from .detectors import detect_all
from .frames import ffmpeg_input_args, iter_frames
from .guard import Guard
from .ocr import scan_images
from .store import Store, now_iso


def h64(s: str) -> int:
    return int.from_bytes(hashlib.blake2b(s.encode(), digest_size=8).digest(), "big")


def start_recording(source: str, out: Path) -> subprocess.Popen:
    """Record the same source to a file in parallel (the 'recording' we later redact)."""
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *ffmpeg_input_args(source),
           "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p", "-g", "25", str(out)]
    return subprocess.Popen(cmd, stdin=subprocess.PIPE)


def run_live(source: str, work: Path, room: str, org: str, allowed: set[str], approved: set[str],
             fps: float, min_change: int, limit: int | None, record: bool, verbose: bool) -> int:
    store = Store(work)
    guard = Guard(approved_destinations=approved)
    rec = start_recording(source, work / "recording.mp4") if record else None
    t_start = time.time()
    n = 0
    print(f"# live source={source} store={store.backend} record={bool(rec)}", file=sys.stderr)
    try:
        for frame in iter_frames(source, work / "frames", fps=fps, min_change=min_change, limit=limit):
            t_frame = time.time()
            res = scan_images([frame.path])[0]
            texts, codes = res["texts"], res["codes"]
            joined = "\n".join(t["text"] for t in texts)
            guard.observe_frame_text(frame.ts, joined)
            findings = detect_all(texts, codes, allowed)
            mpx = max(1, res["width"] * res["height"]) / 1e6
            store.insert("frame_events", [{
                "ts": now_iso(), "org_id": org, "site_id": "local", "room_id": room, "device_id": "mac",
                "stream_id": f"{room}-{int(t_start)}", "source_kind": "screen" if source == "screen" else "camera",
                "phash": frame.dhash, "text_density": round(len(joined) / mpx, 1), "n_texts": len(texts),
                "n_codes": len(codes), "app_class": "unknown",
                "token_hashes": [h64(w) for w in set(joined.split()) if len(w) >= 6][:64],
                "qr_payload": codes[0]["payload"] if codes else "", "viewers": 1, "embedding": [],
            }])
            rows = []
            for f in findings:
                rows.append({"ts": now_iso(), "org_id": org, "room_id": room, "stream_id": f"{room}-{int(t_start)}",
                             "kind": f.kind, "rule": f.rule, "severity": f.severity, "match_hash": h64(f.match),
                             "match": _mask(f.match) if f.kind == "leak" else f.match, "reason": f.reason,
                             "box": list(f.box) if f.box else [], "action": "blurred" if f.box and f.kind == "leak" else "logged",
                             "frame_path": str(frame.path)})
                print(json.dumps({"ts": frame.ts, "lat_ms": int((time.time() - t_frame) * 1000), **asdict(f)},
                                 ensure_ascii=False, default=str), flush=True)
            store.insert("findings", rows)
            n += 1
            if verbose:
                print(f"# kf {frame.index} t={frame.ts:.1f}s texts={len(texts)} codes={len(codes)} "
                      f"findings={len(findings)} lat={int((time.time() - t_frame) * 1000)}ms", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        if rec:
            try:
                rec.stdin.write(b"q")
                rec.stdin.flush()
                rec.wait(timeout=5)
            except Exception:
                rec.kill()
    print(f"# live done keyframes={n} elapsed={time.time() - t_start:.1f}s", file=sys.stderr)
    return 0


def _mask(s: str) -> str:
    return s[:4] + "*" * max(4, len(s) - 4) if len(s) > 8 else "*" * len(s)
