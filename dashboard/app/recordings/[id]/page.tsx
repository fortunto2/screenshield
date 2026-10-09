import Link from "next/link";
import { findings, frameEvents, reviews, secondsOf, sevRank, toolCalls } from "@/lib/data";

export const dynamic = "force-dynamic";
const sevColor: Record<string, string> = { critical: "#ff4d4f", high: "#ffb020", medium: "#ffd166", low: "#4cc9f0" };

export default async function RecordingPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const stream = decodeURIComponent(id);
  const [fe, fi, tc, rv] = await Promise.all([frameEvents(stream), findings(stream), toolCalls(stream), reviews(stream)]);
  const reviewOf = (f: { frame_path: string; rule: string }) => rv.find((r) => r.frame_path === f.frame_path && r.rule === f.rule);
  const byFrame = new Map<string, typeof fi>();
  for (const f of fi) { const k = f.frame_path; byFrame.set(k, [...(byFrame.get(k) ?? []), f]); }
  const frames = [...byFrame.entries()].sort((a, b) => secondsOf(a[0]) - secondsOf(b[0]));
  const duration = Math.max(1, ...fi.map((f) => secondsOf(f.frame_path)), fe.length);
  const worst = fi.reduce((w, f) => (sevRank(f.severity) > sevRank(w) ? f.severity : w), "none");

  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <Link href="/" className="text-sm text-zinc-400 hover:text-zinc-200">← archive</Link>
      <h1 className="mt-2 text-2xl font-semibold">{stream}</h1>
      <p className="text-sm text-zinc-400">{fe.length} keyframes · {fi.length} findings · worst <b style={{ color: sevColor[worst] ?? "#aaa" }}>{worst}</b> · {tc.length} agent actions · {rv.length} reviewed ({rv.filter((r) => r.vision_confirmed === true).length} confirmed by vision, {rv.filter((r) => r.redaction_ok === true).length} blur verified)</p>

      <section className="mt-6 rounded-xl border border-zinc-800 bg-zinc-900 p-4">
        <h2 className="mb-2 text-sm text-zinc-400">timeline (seconds)</h2>
        <div className="relative h-10 w-full rounded bg-zinc-800">
          {fi.map((f, i) => (
            <span key={i} title={`${f.rule} @ ${secondsOf(f.frame_path)}s`} className="absolute top-0 h-10 w-1 rounded"
              style={{ left: `${(secondsOf(f.frame_path) / duration) * 100}%`, background: sevColor[f.severity] ?? "#aaa" }} />
          ))}
        </div>
        <div className="mt-1 flex justify-between text-xs text-zinc-500"><span>0 s</span><span>{duration.toFixed(0)} s</span></div>
      </section>

      <section className="mt-6 grid gap-4 md:grid-cols-2">
        {frames.map(([fp, fs]) => (
          <div key={fp} className="rounded-xl border border-zinc-800 bg-zinc-900 p-3">
            <img alt="" className="w-full rounded border border-zinc-800" src={fs[0].evidence_jpeg ? `data:image/jpeg;base64,${fs[0].evidence_jpeg}` : `/api/frame?p=${encodeURIComponent(fp)}`} />
            <div className="mt-2 text-xs text-zinc-500">t = {secondsOf(fp).toFixed(1)} s</div>
            <ul className="mt-1 space-y-1 text-sm">
              {fs.map((f, i) => (
                <li key={i} className="flex items-start gap-2">
                  <span className="mt-1 inline-block h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: sevColor[f.severity] }} />
                  <span><span className="text-zinc-400">{f.kind}</span> <b>{f.rule}</b> <code className="rounded bg-zinc-800 px-1 text-xs">{f.match.slice(0, 48)}</code><br /><span className="text-xs text-zinc-500">{f.reason} · {f.action}</span>
                    {(() => { const r = reviewOf(f); if (!r) return null; return (
                      <span className="ml-2 inline-flex gap-1 align-middle text-xs">
                        {r.vision_confirmed !== null && <span className={`rounded px-1.5 py-0.5 font-semibold ${r.vision_confirmed ? "bg-emerald-500 text-black" : "bg-red-500 text-black"}`} title={r.vision_why}>{r.vision_confirmed ? "vision ✓" : "vision ✗"}</span>}
                        {r.redaction_ok !== null && <span className={`rounded px-1.5 py-0.5 font-semibold ${r.redaction_ok ? "bg-emerald-500 text-black" : "bg-red-500 text-black"}`}>{r.redaction_ok ? "blur ✓" : "blur ✗"}</span>}
                      </span>); })()}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </section>

      <section className="mt-8 overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900">
        <h2 className="p-3 text-sm text-zinc-400">responder actions</h2>
        <table className="w-full text-sm">
          <thead className="text-left text-zinc-500"><tr><th className="px-3 py-2">tool</th><th className="px-3 py-2">verdict</th><th className="px-3 py-2">args</th><th className="px-3 py-2">note</th></tr></thead>
          <tbody>
            {tc.map((t, i) => (
              <tr key={i} className="border-t border-zinc-800">
                <td className="px-3 py-2 font-medium">{t.tool}</td>
                <td className="px-3 py-2"><span className={`rounded px-2 py-0.5 text-xs font-semibold ${t.verdict === "blocked" ? "bg-red-500 text-black" : t.verdict === "needs_human" ? "bg-amber-400 text-black" : "bg-emerald-500 text-black"}`}>{t.verdict}</span></td>
                <td className="px-3 py-2"><code className="text-xs text-zinc-300">{t.args.slice(0, 120)}</code></td>
                <td className="px-3 py-2 text-xs text-zinc-500">{t.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}
