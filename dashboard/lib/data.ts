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
};
export type ToolCall = {
  ts: string; org_id: string; agent_id: string; stream_id: string; tool: string; args: string;
  tainted: number; verdict: string; reason: string;
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
    return ch(`SELECT * FROM frame_events ${stream ? `WHERE stream_id = '${esc(stream)}'` : ""} ORDER BY ts LIMIT 5000`);
  const rows = readJsonl<FrameEvent>("frame_events");
  return stream ? rows.filter((r) => r.stream_id === stream) : rows;
}

export async function findings(stream?: string): Promise<Finding[]> {
  if (backend() === "clickhouse")
    return ch(`SELECT * FROM findings ${stream ? `WHERE stream_id = '${esc(stream)}'` : ""} ORDER BY ts LIMIT 5000`);
  const rows = readJsonl<Finding>("findings");
  return stream ? rows.filter((r) => r.stream_id === stream) : rows;
}

export async function toolCalls(stream?: string): Promise<ToolCall[]> {
  if (backend() === "clickhouse")
    return ch(`SELECT * FROM tool_calls ${stream ? `WHERE stream_id = '${esc(stream)}'` : ""} ORDER BY ts LIMIT 5000`);
  const rows = readJsonl<ToolCall>("tool_calls");
  return stream ? rows.filter((r) => r.stream_id === stream) : rows;
}

const SEV = ["low", "medium", "high", "critical"];
export const sevRank = (s: string) => SEV.indexOf(s);

export type Recording = {
  stream_id: string; room_id: string; source_kind: string; keyframes: number; findings: number;
  byKind: Record<string, number>; worst: string; actions: number; blocked: number; firstFrame?: string;
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

/** Seconds into the recording, parsed from the keyframe file name f000007_00003.00.png */
export function secondsOf(framePath: string): number {
  const m = /_(\d+\.\d+)\.png$/.exec(framePath);
  return m ? parseFloat(m[1]) : 0;
}

function esc(s: string) { return s.replace(/'/g, "\\'"); }
