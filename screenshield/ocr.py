"""OCR + barcode via the Swift `visionscan` helper (Apple Vision, on-device)."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin" / "visionscan"


def scan_images(paths: list[Path]) -> list[dict]:
    if not paths:
        return []
    if not BIN.exists():
        raise FileNotFoundError(f"{BIN} missing: run `make vision`")
    out = subprocess.run([str(BIN), *map(str, paths)], capture_output=True, text=True, check=True)
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


def scan_image(path: Path) -> dict:
    return scan_images([path])[0]
