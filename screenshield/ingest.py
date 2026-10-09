"""shield ingest-synth: load the synthetic fleet into the store in batches (ClickHouse or JSONL)."""

from __future__ import annotations

import sys
import time
from itertools import islice

from .store import Store
from .synth import gen_frame_events, planted_incidents


def ingest_synth(store: Store, rooms: int, days: int, batch: int = 50_000, max_rows: int | None = None) -> int:
    t0 = time.time()
    n = 0
    gen = gen_frame_events(rooms=rooms, days=days)
    while True:
        chunk = list(islice(gen, batch))
        if not chunk:
            break
        if max_rows and n + len(chunk) > max_rows:
            chunk = chunk[: max_rows - n]
        store.insert("frame_events", chunk)
        n += len(chunk)
        print(f"# frame_events {n:,} rows  {n / max(1e-9, time.time() - t0):,.0f} rows/s", file=sys.stderr)
        if max_rows and n >= max_rows:
            break
    fe, fi, tc = planted_incidents()
    store.insert("frame_events", fe)
    store.insert("findings", fi)
    store.insert("tool_calls", tc)
    print(f"# planted {len(fe)} events, {len(fi)} findings, {len(tc)} tool calls; total {time.time() - t0:.1f}s", file=sys.stderr)
    return n
