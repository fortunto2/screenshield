import Link from "next/link";
import { frameEvents, secondsOf } from "@/lib/data";

export const dynamic = "force-dynamic";

// grep over the archive: every keyframe whose OCR text contains the query. Text, not embeddings: the agent
// asks the same question ("where else did this repo / connection string / function show up?").
export default async function Search({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const { q = "" } = await searchParams;
  const needle = q.trim().toLowerCase();
  const all = await frameEvents();
  const hits = needle
    ? all.filter((e) => ((e as unknown as { ocr_text?: string }).ocr_text ?? "").toLowerCase().includes(needle))
    : [];
  const byStream = new Map<string, typeof hits>();
  for (const h of hits) byStream.set(h.stream_id, [...(byStream.get(h.stream_id) ?? []), h]);
  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <Link href="/" className="text-sm text-zinc-400 hover:text-zinc-200">← archive</Link>
      <h1 className="mt-2 text-2xl font-semibold">grep the archive</h1>
      <form className="mt-4 flex gap-2">
        <input name="q" defaultValue={q} placeholder="repo name, connection string, function, anything that was on a screen" className="w-full rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-zinc-100 outline-none focus:border-sky-400" />
        <button className="rounded-lg bg-sky-400 px-4 py-2 font-semibold text-black" type="submit">search</button>
      </form>
      {needle && <p className="mt-4 text-sm text-zinc-400">{hits.length} keyframes in {byStream.size} recordings contain <code className="rounded bg-zinc-800 px-1">{q}</code></p>}
      <section className="mt-6 space-y-4">
        {[...byStream.entries()].map(([sid, es]) => (
          <div key={sid} className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <Link href={`/recordings/${encodeURIComponent(sid)}`} className="font-medium text-sky-300 hover:underline">{sid}</Link>
            <span className="ml-2 text-xs text-zinc-500">{es.length} keyframes</span>
            <ul className="mt-2 space-y-2">
              {es.slice(0, 6).map((e, i) => {
                const txt = (e as unknown as { ocr_text?: string; frame_path?: string }).ocr_text ?? "";
                const at = txt.toLowerCase().indexOf(needle);
                const snippet = txt.slice(Math.max(0, at - 80), at + needle.length + 80).replace(/\n/g, " ");
                const fp = (e as unknown as { frame_path?: string }).frame_path ?? "";
                return (
                  <li key={i} className="flex gap-3 text-sm">
                    {fp && <img alt="" className="h-14 rounded border border-zinc-700" src={`/api/frame?p=${encodeURIComponent(fp)}`} />}
                    <div><div className="text-xs text-zinc-500">t = {secondsOf(fp).toFixed(1)} s</div><code className="text-xs text-zinc-300">…{snippet}…</code></div>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </section>
    </main>
  );
}
