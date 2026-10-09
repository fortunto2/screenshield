"""shield: CLI mirroring the core pipeline (CLI-first)."""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

from .dashboard import serve
from .detectors import detect_all
from .evalrun import run_eval
from .frames import iter_frames
from .ingest import ingest_synth
from .live import run_live
from .ocr import scan_images
from .respond import respond_file
from .store import Store


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan a file, screen, camera or stream URL; print one JSON line per finding."""
    work = Path(args.work)
    allowed = set(args.allow or [])
    n_frames = n_findings = 0
    t0 = time.time()
    for frame in iter_frames(args.source, work / "frames", fps=args.fps, min_change=args.min_change, limit=args.limit):
        n_frames += 1
        res = scan_images([frame.path])[0]
        findings = detect_all(res["texts"], res["codes"], allowed)
        for f in findings:
            n_findings += 1
            rec = {"ts": frame.ts, "frame": str(frame.path), "lat_ms": int((time.time() - t0) * 1000), **asdict(f)}
            print(json.dumps(rec, ensure_ascii=False), flush=True)
        if args.verbose:
            print(f"# frame {frame.index} t={frame.ts:.1f}s texts={len(res['texts'])} codes={len(res['codes'])} findings={len(findings)}", file=sys.stderr)
    print(f"# done frames={n_frames} findings={n_findings} in {time.time() - t0:.1f}s", file=sys.stderr)
    return 0


def load_env(path: Path = Path(".env")) -> None:
    """Minimal .env loader: KEY=VALUE lines, no quotes handling beyond stripping."""
    if not path.exists():
        return
    import os

    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def main(argv: list[str] | None = None) -> int:
    load_env()
    p = argparse.ArgumentParser(prog="shield", description="DLP for video: leaks out, attacks in.")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a video file, 'screen', 'camera:<idx>' or a stream url")
    s.add_argument("source")
    s.add_argument("--work", default=".shield")
    s.add_argument("--fps", type=float, default=2.0)
    s.add_argument("--min-change", type=int, default=6, help="dHash bits that count as a new keyframe")
    s.add_argument("--limit", type=int, default=None, help="stop after N keyframes")
    s.add_argument("--allow", nargs="*", help="allowed QR domains")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(fn=cmd_scan)
    lv = sub.add_parser("live", help="watch screen/camera/stream, store events, record, guard")
    lv.add_argument("source", nargs="?", default="screen")
    lv.add_argument("--work", default=".shield")
    lv.add_argument("--room", default="room-local")
    lv.add_argument("--org", default="demo")
    lv.add_argument("--fps", type=float, default=2.0)
    lv.add_argument("--min-change", type=int, default=6)
    lv.add_argument("--limit", type=int, default=None)
    lv.add_argument("--allow", nargs="*", help="allowed QR domains")
    lv.add_argument("--approved", nargs="*", default=["live.campus-cloud.example"], help="approved stream destinations")
    lv.add_argument("--no-record", action="store_true")
    lv.add_argument("-v", "--verbose", action="store_true")
    lv.set_defaults(fn=lambda a: run_live(a.source, Path(a.work), a.room, a.org, set(a.allow or []),
                                          set(a.approved), a.fps, a.min_change, a.limit, not a.no_record, a.verbose))
    ev = sub.add_parser("eval", help="run OCR+detectors over fixtures/ and report catch rate")
    ev.add_argument("--fixtures", default="fixtures")
    ev.add_argument("--allow", nargs="*")
    ev.set_defaults(fn=lambda a: print(json.dumps(run_eval(Path(a.fixtures), set(a.allow or [])), indent=1)) or 0)
    db = sub.add_parser("dashboard", help="serve the local dashboard")
    db.add_argument("--work", default=".shield")
    db.add_argument("--port", type=int, default=8787)
    db.set_defaults(fn=lambda a: serve(Path(a.work), a.port))
    ig = sub.add_parser("ingest-synth", help="load synthetic fleet telemetry (10k rooms) into the store")
    ig.add_argument("--work", default=".shield")
    ig.add_argument("--rooms", type=int, default=10_000)
    ig.add_argument("--days", type=int, default=1)
    ig.add_argument("--max-rows", type=int, default=None)
    ig.set_defaults(fn=lambda a: ingest_synth(Store(Path(a.work)), a.rooms, a.days, max_rows=a.max_rows) and 0)
    rs = sub.add_parser("respond", help="run the responder agent over a findings.jsonl (dry-run by default)")
    rs.add_argument("findings")
    rs.add_argument("--work", default=".shield")
    rs.add_argument("--execute", action="store_true", help="perform actions instead of dry-run")
    rs.set_defaults(fn=lambda a: respond_file(Path(a.findings), Path(a.work), dry_run=not a.execute))
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
