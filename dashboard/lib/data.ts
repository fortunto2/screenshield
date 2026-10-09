// Data access for the dashboard. Same three tables as the store: frame_events, findings, tool_calls.
// JSONL from SHIELD_WORK (default ../.shield-archive) or ClickHouse when CLICKHOUSE_HOST is set.
import fs from "node:fs";
import path from "node:path";

export type FrameEvent = {
  ts: string; org_id: string; room_id: string; stream_id: string; source_kind: string;
  phash: number; text_density: number; n_texts: number; n_codes: number; app_class: string;
  qr_payload: string; viewers: number;
};
export type Finding = {
  ts: string; org_id: string; room_id: string; stream_id: string; kind: string; rule: string;
  severity: string; match: string; reason: string; box: number[]; action: string; frame_path: string;
  evidence_jpeg?: string; // base64 JPEG of the flagged keyframe (ClickHouse carries the evidence)
};
export type ToolCall = {
  ts: string; org_id: string; agent_id: string; stream_id: string; tool: string; args: string;
  tainted: number; verdict: string; reason: string;
};

export type Review = {
  ts: string; stream_id: string; rule: string; kind: string; frame_path: string;
  vision_confirmed: boolean | null; vision_why: string; redaction_ok: boolean | null; reviewer: string;
};

export const WORK = path.resolve(process.cwd(), process.env.SHIELD_WORK ?? "../.shield-archive");

function readJsonl<T>(name: string): T[] {
  const p = path.join(WORK, `${name}.jsonl`);
  if (!fs.existsSync(p)) return [];
  return fs.readFileSync(p, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l) as T);
}

async function ch<T>(sql: string): Promise<T[]> {
  const { createClient } = await import("@clickhouse/client");
  const client = createClient({
    url: process.env.CLICKHOUSE_URL ?? `https://${process.env.CLICKHOUSE_HOST}:8443`,
    username: process.env.CLICKHOUSE_USER ?? "default",
    password: process.env.CLICKHOUSE_PASSWORD ?? "",
  });
  const r = await client.query({ query: sql, format: "JSONEachRow" });
  return (await r.json()) as T[];
}

export const backend = () => (process.env.CLICKHOUSE_HOST || process.env.CLICKHOUSE_URL ? "clickhouse" : "jsonl");

export async function frameEvents(stream?: string): Promise<FrameEvent[]> {
  if (backend() === "clickhouse")
    return ch(`SELECT * FROM frame_events ${stream ? `WHERE stream_id = '${esc(stream)}'` : "WHERE source_kind != 'screen' OR org_id != 'univ-demo'"} ORDER BY ts LIMIT 5000`);
  const rows = readJsonl<FrameEvent>("frame_events");
  return stream ? rows.filter((r) => r.stream_id === stream) : rows;
}

export async function findings(stream?: string): Promise<Finding[]> {
  if (backend() === "clickhouse")
    return ch(`SELECT * EXCEPT (evidence_jpeg), if(evidence_jpeg != '', evidence_jpeg, '') AS evidence_jpeg FROM findings ${stream ? `WHERE stream_id = '${esc(stream)}'` : ""} ORDER BY ts LIMIT 5000`);
  const rows = readJsonl<Finding>("findings");
  return stream ? rows.filter((r) => r.stream_id === stream) : rows;
}

export async function toolCalls(stream?: string): Promise<ToolCall[]> {
  if (backend() === "clickhouse")
    return ch(`SELECT * FROM tool_calls ${stream ? `WHERE stream_id = '${esc(stream)}'` : ""} ORDER BY ts LIMIT 5000`);
  const rows = readJsonl<ToolCall>("tool_calls");
  return stream ? rows.filter((r) => r.stream_id === stream) : rows;
}

export async function reviews(stream?: string): Promise<Review[]> {
  if (backend() === "clickhouse")
    return ch(`SELECT * FROM reviews ${stream ? `WHERE stream_id = '${esc(stream)}'` : ""} ORDER BY ts LIMIT 5000`);
  const rows = readJsonl<Review>("reviews");
  return stream ? rows.filter((r) => r.stream_id === stream) : rows;
}

const SEV = ["low", "medium", "high", "critical"];
export const sevRank = (s: string) => SEV.indexOf(s);

export type Recording = {
  stream_id: string; room_id: string; source_kind: string; keyframes: number; findings: number;
  byKind: Record<string, number>; worst: string; actions: number; blocked: number; firstFrame?: string; evidence?: string;
};

export async function recordings(): Promise<Recording[]> {
  const [fe, fi, tc] = await Promise.all([frameEvents(), findings(), toolCalls()]);
  const map = new Map<string, Recording>();
  for (const e of fe) {
    const r = map.get(e.stream_id) ?? { stream_id: e.stream_id, room_id: e.room_id, source_kind: e.source_kind, keyframes: 0, findings: 0, byKind: {}, worst: "none", actions: 0, blocked: 0 };
    r.keyframes++;
    map.set(e.stream_id, r);
  }
  for (const f of fi) {
    const r = map.get(f.stream_id) ?? { stream_id: f.stream_id, room_id: f.room_id, source_kind: "?", keyframes: 0, findings: 0, byKind: {}, worst: "none", actions: 0, blocked: 0 };
    r.findings++;
    r.byKind[f.kind] = (r.byKind[f.kind] ?? 0) + 1;
    if (sevRank(f.severity) > sevRank(r.worst)) r.worst = f.severity;
    if (!r.firstFrame && f.frame_path) r.firstFrame = f.frame_path;
    if (!r.evidence && f.evidence_jpeg) r.evidence = f.evidence_jpeg;
    map.set(f.stream_id, r);
  }
  for (const t of tc) {
    const r = map.get(t.stream_id);
    if (!r) continue;
    r.actions++;
    if (t.verdict === "blocked") r.blocked++;
  }
  return [...map.values()].sort((a, b) => sevRank(b.worst) - sevRank(a.worst) || b.findings - a.findings);
}

export async function stats() {
  if (backend() === "clickhouse") {
    const [[a], kinds, [t]] = await Promise.all([
      ch<{ n: string; recs: string; rooms: string }>(`SELECT count() AS n, uniq(stream_id) AS recs, uniq(room_id) AS rooms FROM frame_events`),
      ch<{ kind: string; n: string }>(`SELECT kind, count() AS n FROM findings GROUP BY kind`),
      ch<{ n: string; blocked: string; human: string }>(`SELECT count() AS n, countIf(verdict = 'blocked') AS blocked, countIf(verdict = 'needs_human' OR tool = 'notify_human') AS human FROM tool_calls`),
    ]);
    const byKind: Record<string, number> = {};
    let findingsN = 0;
    for (const k of kinds) { byKind[k.kind] = Number(k.n); findingsN += Number(k.n); }
    return { backend: "clickhouse", frame_events: Number(a.n), recordings: Number(a.recs), rooms: Number(a.rooms), findings: findingsN, byKind, actions: Number(t.n), blocked: Number(t.blocked), needs_human: Number(t.human) };
  }
  const [fe, fi, tc] = await Promise.all([frameEvents(), findings(), toolCalls()]);
  const byKind: Record<string, number> = {};
  for (const f of fi) byKind[f.kind] = (byKind[f.kind] ?? 0) + 1;
  return {
    backend: backend(), frame_events: fe.length, recordings: new Set(fe.map((e) => e.stream_id)).size,
    rooms: new Set(fe.map((e) => e.room_id)).size, findings: fi.length, byKind,
    actions: tc.length, blocked: tc.filter((t) => t.verdict === "blocked").length,
    needs_human: tc.filter((t) => t.verdict === "needs_human" || t.tool === "notify_human").length,
  };
}

/** grep the archive: ClickHouse ILIKE over ocr_text (the whole fleet), JSONL filter otherwise. Returns rows + ms. */
export async function searchFrames(q: string): Promise<{ rows: (FrameEvent & { ocr_text?: string; frame_path?: string })[]; ms: number; total: number }> {
  const t0 = Date.now();
  if (backend() === "clickhouse") {
    const rows = await ch<FrameEvent & { ocr_text?: string; frame_path?: string }>(`SELECT * FROM frame_events WHERE ocr_text ILIKE '%${esc(q).replace(/%/g, "")}%' ORDER BY ts LIMIT 200`);
    const [{ n }] = await ch<{ n: string }>(`SELECT count() AS n FROM frame_events WHERE ocr_text ILIKE '%${esc(q).replace(/%/g, "")}%'`);
    return { rows, ms: Date.now() - t0, total: Number(n) };
  }
  const all = readJsonl<FrameEvent & { ocr_text?: string }>("frame_events").filter((e) => (e.ocr_text ?? "").toLowerCase().includes(q.toLowerCase()));
  return { rows: all.slice(0, 200), ms: Date.now() - t0, total: all.length };
}

/** Fleet stories for the overview, each with its latency (ClickHouse only). */
export async function stories() {
  if (backend() !== "clickhouse") return [];
  const defs: [string, string][] = [
    ["Secret held on screen (seconds, rooms)", `SELECT room_id, min(ts) AS first_seen, dateDiff('second', min(ts), max(ts)) AS seconds_on_screen, count() AS keyframes, anyLast(action) AS last_action FROM findings WHERE kind='leak' AND severity IN ('critical','high') GROUP BY room_id, match_hash ORDER BY seconds_on_screen DESC LIMIT 5`],
    ["Same QR across rooms = campaign", `SELECT match AS url, uniq(room_id) AS rooms, min(ts) AS first_seen, max(ts) AS last_seen FROM findings WHERE kind='quishing' GROUP BY match HAVING rooms >= 3 ORDER BY rooms DESC LIMIT 5`],
    ["Frame text → blocked tool call", `SELECT f.room_id, f.ts AS seen_in_frame, t.ts AS tool_call, t.tool, t.verdict, dateDiff('second', f.ts, t.ts) AS gap_s FROM findings f INNER JOIN tool_calls t ON t.stream_id = f.stream_id WHERE f.kind='injection' AND t.ts BETWEEN f.ts AND f.ts + INTERVAL 120 SECOND ORDER BY f.ts DESC LIMIT 5`],
  ];
  const out = [];
  for (const [title, sql] of defs) { const t0 = Date.now(); const rows = await ch<Record<string, unknown>>(sql); out.push({ title, ms: Date.now() - t0, rows }); }
  return out;
}

/** Seconds into the recording, parsed from the keyframe file name f000007_00003.00.png */
export function secondsOf(framePath: string): number {
  const m = /_(\d+\.\d+)\.png$/.exec(framePath);
  return m ? parseFloat(m[1]) : 0;
}

function esc(s: string) { return s.replace(/'/g, "\\'"); }
