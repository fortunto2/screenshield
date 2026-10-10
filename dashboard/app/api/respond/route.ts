import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Run the responder agent (shield respond: sgr-agent tool calling on AkashML, rule-based offline) on the findings
// the browser just saw, and return the tool calls with verdicts so the page can show the agent at work.
const BIN = process.env.SHIELD_BIN ?? path.join(os.homedir(), ".cargo-target", "release", "shield");
const APP = path.resolve(process.cwd(), "..");
const TMP = path.join(os.tmpdir(), "shield-cam");

type Finding = { kind: string; rule: string; severity: string; match: string; box: { x: number; y: number; w: number; h: number } | null };

export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as { findings?: Finding[] };
  const findings = (body.findings ?? []).slice(0, 6);
  if (!findings.length) return Response.json({ error: "no findings" }, { status: 400 });
  fs.mkdirSync(TMP, { recursive: true });
  const id = `${process.pid}-${Date.now()}`;
  const work = path.join(TMP, `r-${id}`);
  fs.mkdirSync(work, { recursive: true });
  const file = path.join(work, "findings.jsonl");
  fs.writeFileSync(file, findings.map((f) => JSON.stringify({ ts: 0.0, stream_id: "live-demo", room_id: "room-live", kind: f.kind, rule: f.rule, severity: f.severity, match: f.match, reason: "live frame", box: f.box ? [f.box.x, f.box.y, f.box.w, f.box.h] : null, match_hash: 0 })).join("\n") + "\n");
  const t0 = Date.now();
  const { stdout, stderr } = await new Promise<{ stdout: string; stderr: string }>((resolve) => {
    // --execute: the agent really acts (rotate_in_repo commits on a branch). Scope is the demo folder only.
    const env = { ...process.env, SHIELD_REPO: process.env.SHIELD_REPO ?? path.join(APP, "demo", "fake-secrets") };
    execFile(BIN, ["respond", file, "--work", work, "--execute"], { cwd: APP, env, timeout: 120000, maxBuffer: 4 << 20 }, (_e, out, err) => resolve({ stdout: out ?? "", stderr: err ?? "" }));
  });
  const planner = /planner=(\w+)/.exec(stderr)?.[1] ?? "?";
  let calls: Record<string, unknown>[] = [];
  try { calls = fs.readFileSync(path.join(work, "tool_calls.jsonl"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)); } catch {}
  const decisions = stdout.split("\n").filter((l) => l.startsWith("{")).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  try { fs.rmSync(work, { recursive: true, force: true }); } catch {}
  return Response.json({ planner, ms: Date.now() - t0, decisions, calls: calls.map((c) => { let a: Record<string, unknown> = {}; try { a = JSON.parse(String(c.args)); } catch {} const result = a.result as Record<string, unknown> | undefined; delete a.result; return { tool: c.tool, verdict: c.verdict, args: JSON.stringify(a).slice(0, 160), reason: c.reason, result: result ?? (a.error ? { error: a.error } : undefined) }; }), tokens: /💰 ([^\n]+)/.exec(stderr)?.[1] ?? null });
}
