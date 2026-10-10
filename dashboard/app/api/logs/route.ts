// Tail of the ClickHouse tables for the live page: what the fast loop and the agent just wrote.
const URL_ = process.env.CLICKHOUSE_URL ?? "http://127.0.0.1:8123";
const AUTH = { "X-ClickHouse-User": process.env.CLICKHOUSE_USER ?? "default", "X-ClickHouse-Key": process.env.CLICKHOUSE_PASSWORD ?? "" };

async function q<T>(sql: string): Promise<{ rows: T[]; ms: number }> {
  const t0 = Date.now();
  const r = await fetch(`${URL_}/?query=${encodeURIComponent(sql + " FORMAT JSONEachRow")}`, { headers: AUTH, cache: "no-store" });
  const text = await r.text();
  if (!r.ok) throw new Error(text.slice(0, 200));
  return { rows: text.split("\n").filter(Boolean).map((l) => JSON.parse(l) as T), ms: Date.now() - t0 };
}

export async function GET() {
  try {
    const [frames, findings, calls, totals] = await Promise.all([
      q<Record<string, unknown>>("SELECT ts, room_id, source_kind, n_texts, n_codes, round(text_density, 2) AS text_density, length(ocr_text) AS ocr_len FROM frame_events WHERE room_id IN ('room-cam','room-live') ORDER BY ts DESC LIMIT 10"),
      q<Record<string, unknown>>("SELECT ts, room_id, kind, rule, severity, match FROM findings WHERE room_id IN ('room-cam','room-live') ORDER BY ts DESC LIMIT 10"),
      q<Record<string, unknown>>("SELECT ts, tool, verdict, tainted, substring(args, 1, 90) AS args FROM tool_calls ORDER BY ts DESC LIMIT 8"),
      q<{ t: string; n: string }>("SELECT 'frame_events' AS t, count() AS n FROM frame_events UNION ALL SELECT 'findings', count() FROM findings UNION ALL SELECT 'tool_calls', count() FROM tool_calls UNION ALL SELECT 'reviews', count() FROM reviews"),
    ]);
    return Response.json({ frames: frames.rows, findings: findings.rows, calls: calls.rows, totals: totals.rows, ms: Math.max(frames.ms, findings.ms, calls.ms, totals.ms) });
  } catch (e) {
    return Response.json({ error: String(e) }, { status: 502 });
  }
}
