import { spawn, execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Start / stop the live scan from the page (the dashboard runs on the same Mac as the camera).
// POST {action: "start"|"stop", source?: "cam:iPhone Camera"}
const APP = path.resolve(process.cwd(), "..");
const WORK = path.resolve(process.cwd(), process.env.SHIELD_LIVE ?? "../.shield-live");
const BIN = process.env.SHIELD_BIN ?? path.join(os.homedir(), ".cargo-target", "release", "shield");

type G = typeof globalThis & { __shieldScan?: ReturnType<typeof spawn> | null };
const g = globalThis as G;

function stopAll() {
  try { g.__shieldScan?.kill("SIGINT"); } catch {}
  g.__shieldScan = null;
  try { execSync("pkill -f 'release/shield scan' ; pkill -f 'ffmpeg -hide_banner -loglevel error -y -f avfoundation'", { stdio: "ignore" }); } catch {}
}

export async function POST(req: Request) {
  const body = (await req.json().catch(() => ({}))) as { action?: string; source?: string };
  if (body.action === "stop") { stopAll(); return Response.json({ ok: true, running: false }); }
  stopAll();
  await new Promise((r) => setTimeout(r, 800)); // let the camera device free up
  fs.mkdirSync(WORK, { recursive: true });
  for (const f of ["live.jpg", "live.json"]) { try { fs.unlinkSync(path.join(WORK, f)); } catch {} }
  const source = body.source && /^(cam:[\w ’' .-]+|screen)$/.test(body.source) ? body.source : "cam:iPhone Camera";
  // the Osmo only streams at 1280x720 nv12; shield already uses that for every camera
  const log = fs.openSync(path.join(WORK, "scan.log"), "a");
  const child = spawn(BIN, ["scan", source, "--record", "--live", "--work", WORK, "--room", "room-live", "--min-change", "0", "--fps", "2", "-v"], { cwd: APP, stdio: ["ignore", log, log], detached: false });
  g.__shieldScan = child;
  child.on("exit", () => { if (g.__shieldScan === child) g.__shieldScan = null; });
  return Response.json({ ok: true, running: true, source, pid: child.pid });
}

export async function GET() {
  return Response.json({ running: !!g.__shieldScan && g.__shieldScan.exitCode === null });
}
