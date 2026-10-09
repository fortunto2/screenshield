"""Storage: ClickHouse when configured, JSONL files otherwise. Same schema either way.

Tables (ClickHouse):
  frame_events : one row per keyframe across the fleet (the volume table)
  findings     : one row per detection (joins to frame_events on stream_id, ts)
  tool_calls   : agent MCP tool-call log (joins to findings to prove an injection)
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

DDL = {
    "frame_events": """
CREATE TABLE IF NOT EXISTS frame_events (
  ts            DateTime64(3),
  org_id        LowCardinality(String),
  site_id       LowCardinality(String),
  room_id       String,
  device_id     String,
  stream_id     String,
  source_kind   LowCardinality(String),   -- screen | camera | stream
  phash         UInt64,
  text_density  Float32,                  -- OCR chars per megapixel
  n_texts       UInt16,
  n_codes       UInt8,
  app_class     LowCardinality(String),   -- slides | terminal | browser | ide | spreadsheet | video | unknown
  token_hashes  Array(UInt64),            -- hashed OCR tokens (privacy: no raw text at fleet scale)
  qr_payload    String,
  viewers       UInt32,
  embedding     Array(Float32)            -- only for flagged frames, else []
) ENGINE = MergeTree ORDER BY (org_id, room_id, ts)""",
    "findings": """
CREATE TABLE IF NOT EXISTS findings (
  ts        DateTime64(3),
  org_id    LowCardinality(String),
  room_id   String,
  stream_id String,
  kind      LowCardinality(String),   -- leak | quishing | injection | anomaly
  rule      LowCardinality(String),
  severity  LowCardinality(String),
  match_hash UInt64,
  match     String,                   -- redacted/truncated for display
  reason    String,
  box       Array(Float32),
  action    LowCardinality(String),   -- none | blurred | blocked | revoked | escalated
  frame_path String
) ENGINE = MergeTree ORDER BY (org_id, kind, ts)""",
    "tool_calls": """
CREATE TABLE IF NOT EXISTS tool_calls (
  ts        DateTime64(3),
  org_id    LowCardinality(String),
  agent_id  String,
  stream_id String,
  tool      LowCardinality(String),
  args      String,
  args_hash UInt64,
  tainted   UInt8,                    -- 1 if any arg came from untrusted frame text
  verdict   LowCardinality(String),   -- allowed | blocked | needs_human
  reason    String
) ENGINE = MergeTree ORDER BY (org_id, agent_id, ts)""",
}


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


class Store:
    def __init__(self, work: Path | None = None):
        self.work = work or Path(os.environ.get("SHIELD_WORK", ".shield"))
        self.work.mkdir(parents=True, exist_ok=True)
        self.ch = None
        host = os.environ.get("CLICKHOUSE_HOST")
        if host:
            import clickhouse_connect

            self.ch = clickhouse_connect.get_client(
                host=host,
                port=int(os.environ.get("CLICKHOUSE_PORT", "8443")),
                username=os.environ.get("CLICKHOUSE_USER", "default"),
                password=os.environ.get("CLICKHOUSE_PASSWORD", ""),
                secure=os.environ.get("CLICKHOUSE_SECURE", "1") == "1",
            )
            for ddl in DDL.values():
                self.ch.command(ddl)

    @property
    def backend(self) -> str:
        return "clickhouse" if self.ch else "jsonl"

    def insert(self, table: str, rows: list[dict]) -> None:
        if not rows:
            return
        if self.ch:
            cols = list(rows[0].keys())
            self.ch.insert(table, [[r[c] for c in cols] for r in rows], column_names=cols)
        else:
            with (self.work / f"{table}.jsonl").open("a") as f:
                for r in rows:
                    f.write(json.dumps(r, ensure_ascii=False, default=str) + "\n")

    def query(self, sql: str):
        if not self.ch:
            raise RuntimeError("query needs ClickHouse (set CLICKHOUSE_HOST)")
        res = self.ch.query(sql)
        return res.column_names, res.result_rows
