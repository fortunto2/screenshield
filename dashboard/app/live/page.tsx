"use client";
import { useEffect, useRef, useState } from "react";

type Finding = { kind: string; rule: string; severity: string; match: string };
type Live = { ts: number; keyframe: number; lat_ms: number; texts: number; codes: number; findings: Finding[]; updated: string };

const sev: Record<string, string> = { critical: "#ff4d4f", high: "#ffb020", medium: "#ffd166", low: "#4cc9f0" };

// Live view for the projector: the latest keyframe with leak boxes pixelated, plus a ticker of findings.
export default function LivePage() {
  const [live, setLive] = useState<Live | null>(null);
  const [imgSrc, setImgSrc] = useState<string>("");
  const [history, setHistory] = useState<(Finding & { t: number })[]>([]);
  const last = useRef<string>("");
  useEffect(() => {
    let stop = false;
    const poll = async () => {
      try {
        const r = await fetch(`/api/live?t=${Date.now()}`, { cache: "no-store" });
        if (r.ok) {
          const j = (await r.json()) as Live;
          if (j.updated !== last.current) {
            last.current = j.updated;
            setLive(j);
            setImgSrc(`/api/live?img=1&t=${Date.now()}`);
            if (j.findings.length) setHistory((h) => [...j.findings.map((f) => ({ ...f, t: j.ts })), ...h].slice(0, 14));
          }
        }
      } catch { /* server not up yet */ }
      if (!stop) setTimeout(poll, 400);
    };
    poll();
    return () => { stop = true; };
  }, []);
  return (
    <main className="flex h-screen flex-col bg-black p-4 text-zinc-100">
      <header className="mb-3 flex items-baseline justify-between">
        <h1 className="text-xl font-semibold">ScreenShield <span className="ml-2 text-sm font-normal text-zinc-400">live · fast loop on the device · no LLM</span></h1>
        <div className="font-mono text-sm text-zinc-400">{live ? `keyframe ${live.keyframe} · ${live.lat_ms} ms · ${live.texts} text lines · ${live.codes} codes` : "waiting for shield scan --live"}</div>
      </header>
      <div className="grid min-h-0 flex-1 grid-cols-[2fr_1fr] gap-4">
        <div className="relative min-h-0 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
          {imgSrc ? <img alt="live frame with leaks pixelated" src={imgSrc} className="h-full w-full object-contain" /> : <div className="flex h-full items-center justify-center text-zinc-600">no frame yet</div>}
          <div className="absolute left-3 top-3 rounded bg-red-500 px-2 py-0.5 text-xs font-semibold text-black">● LIVE · leaks pixelated before the recording</div>
        </div>
        <div className="min-h-0 overflow-auto rounded-xl border border-zinc-800 bg-zinc-950 p-3">
          <h2 className="mb-2 text-sm text-zinc-400">findings on the latest keyframe</h2>
          <ul className="space-y-1 text-sm">
            {(live?.findings ?? []).map((f, i) => (
              <li key={i} className="flex items-start gap-2"><span className="mt-1 inline-block h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: sev[f.severity] ?? "#aaa" }} /><span><span className="text-zinc-400">{f.kind}</span> <b>{f.rule}</b> <code className="rounded bg-zinc-800 px-1 text-xs">{f.match}</code></span></li>
            ))}
            {live && live.findings.length === 0 && <li className="text-zinc-500">clean frame</li>}
          </ul>
          <h2 className="mb-2 mt-5 text-sm text-zinc-400">recent</h2>
          <ul className="space-y-1 text-xs text-zinc-400">
            {history.map((f, i) => (<li key={i}><span className="font-mono">{f.t.toFixed(1)}s</span> · <span style={{ color: sev[f.severity] }}>{f.rule}</span> · {f.match}</li>))}
          </ul>
        </div>
      </div>
    </main>
  );
}
