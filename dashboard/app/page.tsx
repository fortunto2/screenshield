import Link from "next/link";
import { recordings, stats } from "@/lib/data";

export const dynamic = "force-dynamic";
const sevClass: Record<string, string> = {
  critical: "bg-red-500 text-black", high: "bg-amber-400 text-black", medium: "bg-yellow-200 text-black",
  low: "bg-sky-300 text-black", none: "bg-zinc-700 text-zinc-200",
};

export default async function Home() {
  const [s, recs] = await Promise.all([stats(), recordings()]);
  const tiles: [string, string | number][] = [
    ["recordings", s.recordings], ["keyframes", s.frame_events], ["findings", s.findings],
    ["agent actions", s.actions], ["blocked / human", `${s.blocked} / ${s.needs_human}`], ["store", s.backend],
  ];
  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold">ScreenShield <span className="ml-2 text-base font-normal text-zinc-400">archive · the slow loop over every recording</span></h1>
      </header>
      <section className="mb-8 grid grid-cols-2 gap-3 md:grid-cols-6">
        {tiles.map(([k, v]) => (
          <div key={k} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <div className="text-3xl font-semibold">{typeof v === "number" ? v.toLocaleString() : v}</div>
            <div className="text-sm text-zinc-400">{k}</div>
          </div>
        ))}
      </section>
      <section className="mb-8 flex flex-wrap gap-2 text-sm">
        {Object.entries(s.byKind).map(([k, n]) => (
          <span key={k} className="rounded-full border border-zinc-800 bg-zinc-900 px-3 py-1">{k} <b>{n}</b></span>
        ))}
      </section>
      <section className="overflow-x-auto rounded-xl border border-zinc-800 bg-zinc-900">
        <table className="w-full text-sm">
          <thead className="text-left text-zinc-400">
            <tr><th className="p-3">recording</th><th className="p-3">source</th><th className="p-3">keyframes</th><th className="p-3">findings</th><th className="p-3">worst</th><th className="p-3">agent actions</th><th className="p-3">preview</th></tr>
          </thead>
          <tbody>
            {recs.map((r) => (
              <tr key={r.stream_id} className="border-t border-zinc-800 hover:bg-zinc-800/50">
                <td className="p-3"><Link className="font-medium text-sky-300 hover:underline" href={`/recordings/${encodeURIComponent(r.stream_id)}`}>{r.stream_id}</Link><div className="text-xs text-zinc-500">{r.room_id}</div></td>
                <td className="p-3">{r.source_kind}</td>
                <td className="p-3">{r.keyframes}</td>
                <td className="p-3">{r.findings}<span className="ml-2 text-xs text-zinc-500">{Object.entries(r.byKind).map(([k, n]) => `${k} ${n}`).join(" · ")}</span></td>
                <td className="p-3"><span className={`rounded px-2 py-0.5 text-xs font-semibold ${sevClass[r.worst]}`}>{r.worst}</span></td>
                <td className="p-3">{r.actions}{r.blocked ? <span className="ml-2 text-xs text-red-400">{r.blocked} blocked</span> : null}</td>
                <td className="p-3">{r.firstFrame ? <img alt="" className="h-12 rounded border border-zinc-700" src={`/api/frame?p=${encodeURIComponent(r.firstFrame)}`} /> : <span className="text-zinc-600">clean</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
      <p className="mt-6 text-xs text-zinc-500">Fast loop writes frame_events and findings; the responder writes tool_calls. Thumbnails are unredacted keyframes and stay local.</p>
    </main>
  );
}
