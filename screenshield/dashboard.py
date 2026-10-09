"""Tiny dashboard server (stdlib only). Serves web/index.html and JSON from the store.

/api/findings      last N findings (JSONL or ClickHouse)
/api/stats         counts for the fleet (frame_events, findings by kind, tool_calls blocked)
/api/stories       the three incident queries used in the demo (ClickHouse only; JSONL returns [])
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .store import Store

WEB = Path(__file__).resolve().parent.parent / "web"

STORIES = {
    "leak_on_screen": """
        SELECT room_id, min(ts) AS first_seen, max(ts) AS last_seen,
               dateDiff('second', min(ts), max(ts)) AS seconds_on_screen, count() AS keyframes,
               anyLast(action) AS last_action
        FROM findings WHERE kind='leak' AND severity='critical' GROUP BY room_id, match_hash
        ORDER BY seconds_on_screen DESC LIMIT 5""",
    "qr_campaign": """
        SELECT match AS url, uniq(room_id) AS rooms, min(ts) AS first_seen, max(ts) AS last_seen
        FROM findings WHERE kind='quishing' GROUP BY match HAVING rooms >= 3 ORDER BY rooms DESC LIMIT 5""",
    "injection_to_toolcall": """
        SELECT f.room_id, f.ts AS seen_in_frame, t.ts AS tool_call, t.tool, t.verdict, t.reason,
               dateDiff('second', f.ts, t.ts) AS gap_s
        FROM findings f INNER JOIN tool_calls t ON t.stream_id = f.stream_id
        WHERE f.kind='injection' AND t.ts BETWEEN f.ts AND f.ts + INTERVAL 120 SECOND
        ORDER BY f.ts DESC LIMIT 5""",
}


def _jsonl(path: Path, n: int) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text().splitlines()[-n:]
    return [json.loads(line) for line in lines]


class Handler(BaseHTTPRequestHandler):
    store: Store

    def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):  # quiet
        pass

    def do_GET(self):
        s = self.store
        if self.path.startswith("/api/findings"):
            if s.ch:
                cols, rows = s.query("SELECT ts, room_id, kind, rule, severity, match, reason, action FROM findings ORDER BY ts DESC LIMIT 50")
                data = [dict(zip(cols, r, strict=True)) for r in rows]
            else:
                data = list(reversed(_jsonl(s.work / "findings.jsonl", 50)))
            return self._send(200, json.dumps(data, default=str).encode())
        if self.path.startswith("/api/stats"):
            if s.ch:
                stats = {}
                for name, sql in {"frame_events": "SELECT count() FROM frame_events",
                                  "rooms": "SELECT uniq(room_id) FROM frame_events",
                                  "findings": "SELECT count() FROM findings",
                                  "blocked_tool_calls": "SELECT count() FROM tool_calls WHERE verdict='blocked'"}.items():
                    _, rows = s.query(sql)
                    stats[name] = rows[0][0]
                _, rows = s.query("SELECT kind, count() FROM findings GROUP BY kind")
                stats["by_kind"] = {k: c for k, c in rows}
            else:
                fe = _jsonl(s.work / "frame_events.jsonl", 10**7)
                fi = _jsonl(s.work / "findings.jsonl", 10**7)
                by = {}
                for f in fi:
                    by[f["kind"]] = by.get(f["kind"], 0) + 1
                stats = {"frame_events": len(fe), "rooms": len({e["room_id"] for e in fe}), "findings": len(fi),
                         "blocked_tool_calls": 0, "by_kind": by}
            stats["backend"] = s.backend
            return self._send(200, json.dumps(stats, default=str).encode())
        if self.path.startswith("/api/stories"):
            out = {}
            if s.ch:
                import time

                for name, sql in STORIES.items():
                    t0 = time.time()
                    cols, rows = s.query(sql)
                    out[name] = {"ms": int((time.time() - t0) * 1000), "rows": [dict(zip(cols, r, strict=True)) for r in rows]}
            return self._send(200, json.dumps(out, default=str).encode())
        if self.path in ("/", "/index.html"):
            return self._send(200, (WEB / "index.html").read_bytes(), "text/html; charset=utf-8")
        if self.path.startswith("/frames/"):
            p = (s.work / "frames" / Path(self.path).name)
            if p.exists():
                return self._send(200, p.read_bytes(), "image/png")
        return self._send(404, b"{}")


def serve(work: Path, port: int = 8787) -> None:
    Handler.store = Store(work)
    print(f"# dashboard http://127.0.0.1:{port}  store={Handler.store.backend}")
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
