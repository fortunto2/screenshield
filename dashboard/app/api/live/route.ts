import fs from "node:fs";
import path from "node:path";

// Serves the live frame (live.jpg) and its findings (live.json) written by `shield scan --live`.
const LIVE = path.resolve(process.cwd(), process.env.SHIELD_LIVE ?? "../.shield-live");

export async function GET(req: Request) {
  const u = new URL(req.url);
  const hdr = { "Cache-Control": "no-store" };
  if (u.searchParams.get("img")) {
    const p = path.join(LIVE, "live.jpg");
    if (!fs.existsSync(p)) return new Response("", { status: 404, headers: hdr });
    return new Response(fs.readFileSync(p), { headers: { ...hdr, "Content-Type": "image/jpeg" } });
  }
  const p = path.join(LIVE, "live.json");
  if (!fs.existsSync(p)) return new Response("{}", { status: 404, headers: { ...hdr, "Content-Type": "application/json" } });
  return new Response(fs.readFileSync(p), { headers: { ...hdr, "Content-Type": "application/json" } });
}
