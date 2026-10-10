import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Detect on one frame sent by the browser (JPEG/PNG body). Runs the Rust fast loop on the image and returns
// the findings with boxes in frame pixels. The browser does the pixelation itself.
const BIN = process.env.SHIELD_BIN ?? path.join(os.homedir(), ".cargo-target", "release", "shield");
const APP = path.resolve(process.cwd(), "..");
const TMP = path.join(os.tmpdir(), "shield-cam");

export async function POST(req: Request) {
  fs.mkdirSync(TMP, { recursive: true });
  const buf = Buffer.from(await req.arrayBuffer());
  if (buf.length < 100) return Response.json({ error: "empty frame" }, { status: 400 });
  const id = `${process.pid}-${Date.now()}`;
  const img = path.join(TMP, `${id}.jpg`);
  const work = path.join(TMP, `w-${id}`);
  fs.writeFileSync(img, buf);
  const t0 = Date.now();
  const out = await new Promise<string>((resolve) => {
    execFile(BIN, ["scan", img, "--work", work, "--room", "room-cam"], { cwd: APP, timeout: 8000, maxBuffer: 8 << 20 }, (_e, stdout) => resolve(stdout ?? ""));
  });
  try { fs.rmSync(img); fs.rmSync(work, { recursive: true, force: true }); } catch {}
  const findings = out.split("\n").filter((l) => l.startsWith("{")).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean)
    .map((f) => ({ kind: f.kind, rule: f.rule, severity: f.severity, match: f.kind === "leak" ? String(f.match).slice(0, 4) + "****" : String(f.match).slice(0, 60), box: f.box, frame_w: f.frame_w, frame_h: f.frame_h }));
  return Response.json({ findings, ms: Date.now() - t0 });
}
