import fs from "node:fs";
import path from "node:path";
import { WORK } from "@/lib/data";

// Serves a keyframe PNG. Only files inside the work dir (frames/...) are allowed.
export async function GET(req: Request) {
  const p = new URL(req.url).searchParams.get("p") ?? "";
  const abs = path.resolve(WORK, "..", p);
  const framesRoot = path.resolve(WORK, "frames");
  if (!abs.startsWith(framesRoot) || !abs.endsWith(".png") || !fs.existsSync(abs)) {
    return new Response("not found", { status: 404 });
  }
  return new Response(fs.readFileSync(abs), { headers: { "Content-Type": "image/png", "Cache-Control": "private, max-age=60" } });
}
