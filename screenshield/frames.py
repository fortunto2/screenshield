"""Frame sources and keyframe selection.

ffmpeg does the decoding (screen, camera, file, RTMP/SRT all look the same to it);
we keep a frame only when its dHash moved far enough from the last kept one.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from PIL import Image

W, H = 640, 360  # analysis resolution for hashing; OCR runs on the full frame


@dataclass
class Frame:
    index: int
    ts: float
    path: Path
    dhash: int


def dhash(img: Image.Image, size: int = 8) -> int:
    g = img.convert("L").resize((size + 1, size), Image.Resampling.BILINEAR)
    px = list(g.getdata())
    bits = 0
    for row in range(size):
        for col in range(size):
            left = px[row * (size + 1) + col]
            right = px[row * (size + 1) + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return bits


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def avf_index(needle: str) -> int | None:
    """Index of the first avfoundation video device whose name contains `needle` (indices shift when a
    phone or camera is plugged in, so never hardcode)."""
    out = subprocess.run(["ffmpeg", "-hide_banner", "-f", "avfoundation", "-list_devices", "true", "-i", ""],
                         capture_output=True, text=True)
    in_video = False
    for line in out.stderr.splitlines():
        if "video devices" in line:
            in_video = True
            continue
        if "audio devices" in line:
            break
        if in_video and needle in line:
            return int(line[line.rfind("[") + 1:line.rfind("]")])
    return None


def ffmpeg_input_args(source: str) -> list[str]:
    """Map a friendly source name to ffmpeg input args."""
    if source == "screen":
        idx = avf_index("Capture screen") or 5
        return ["-f", "avfoundation", "-framerate", "5", "-pixel_format", "uyvy422", "-capture_cursor", "1", "-i", f"{idx}:none"]
    if source.startswith("cam:"):
        idx = avf_index(source[4:]) or 0
        return ["-f", "avfoundation", "-framerate", "30", "-pixel_format", "uyvy422", "-i", f"{idx}:none"]
    if source.startswith("camera:"):
        return ["-f", "avfoundation", "-framerate", "30", "-pixel_format", "uyvy422", "-i", f"{source.split(':', 1)[1]}:none"]
    if source.startswith(("rtmp://", "srt://", "rtsp://", "http://", "https://")):
        return ["-i", source]
    return ["-i", source]  # file


def iter_frames(source: str, out_dir: Path, fps: float = 2.0, min_change: int = 6,
                limit: int | None = None) -> Iterator[Frame]:
    """Decode `source` at `fps`, yield frames whose dHash changed by >= min_change bits."""
    out_dir.mkdir(parents=True, exist_ok=True)
    is_image = source.lower().endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp"))
    vf = [] if is_image else ["-vf", f"fps={fps}"]
    cmd = ["ffmpeg", "-hide_banner", "-loglevel", "error", *ffmpeg_input_args(source),
           *vf, "-f", "image2pipe", "-vcodec", "png", "-"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=sys.stderr)
    assert proc.stdout is not None
    last_hash: int | None = None
    index = 0
    kept = 0
    try:
        for png in _split_pngs(proc.stdout):
            ts = index / fps
            index += 1
            img = Image.open(png)
            img.load()
            h = dhash(img.resize((W, H)))
            if last_hash is not None and hamming(h, last_hash) < min_change:
                continue
            last_hash = h
            path = out_dir / f"f{index:06d}_{ts:08.2f}.png"
            path.write_bytes(png.getvalue())
            kept += 1
            yield Frame(index, ts, path, h)
            if limit and kept >= limit:
                break
    finally:
        proc.kill()


def _split_pngs(stream) -> Iterator[io.BytesIO]:
    """Split a concatenated PNG byte stream on the IEND chunk."""
    import io

    buf = bytearray()
    end = b"IEND\xaeB`\x82"
    while chunk := stream.read(1 << 16):
        buf += chunk
        while (i := buf.find(end)) != -1:
            yield io.BytesIO(bytes(buf[: i + len(end)]))
            del buf[: i + len(end)]
