"use client";
import { useEffect, useRef, useState } from "react";

type Box = { x: number; y: number; w: number; h: number };
type Finding = { kind: string; rule: string; severity: string; match: string; box: Box | null };
type ServerLive = { ts: number; keyframe: number; lat_ms: number; findings: Finding[]; updated: string };

const sev: Record<string, string> = { critical: "#ff4d4f", high: "#ffb020", medium: "#ffd166", low: "#4cc9f0" };
const SCREEN = "__screen__", SERVER = "__server__";

// One live page. Source = a browser camera (Chrome's own device list: iPhone, Mac, DJI), a shared screen
// (getDisplayMedia), or the server stream written by `shield scan --live`. Frames go to the Rust fast loop
// (/api/detect); the browser pixelates the leak boxes on a canvas. No LLM anywhere in this loop.
export default function LivePage() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const serverImg = useRef<HTMLImageElement | null>(null);
  const [devices, setDevices] = useState<MediaDeviceInfo[]>([]);
  const [source, setSource] = useState<string>("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [stats, setStats] = useState({ ms: 0, frames: 0 });
  const [history, setHistory] = useState<Finding[]>([]);
  const streamRef = useRef<MediaStream | null>(null);
  const sourceRef = useRef<string>("");
  const lastBoxes = useRef<{ boxes: Finding[]; w: number; h: number }>({ boxes: [], w: 1, h: 1 });
  const lastServer = useRef<string>("");
  type Call = { tool: string; verdict: string; args: string; reason: string; result?: Record<string, unknown> };
  const [agent, setAgent] = useState<{ running: boolean; planner?: string; ms?: number; calls: Call[]; tokens?: string | null; at?: string }>({ running: false, calls: [] });
  const [auto, setAuto] = useState(true);
  const [tab, setTab] = useState<"detect" | "agent" | "clickhouse">("detect");
  type Logs = { frames: Record<string, unknown>[]; findings: Record<string, unknown>[]; calls: Record<string, unknown>[]; totals: { t: string; n: string }[]; ms: number; error?: string };
  const [logs, setLogs] = useState<Logs | null>(null);
  useEffect(() => {
    let stop = false;
    const tick = async () => { try { const r = await fetch(`/api/logs?t=${Date.now()}`, { cache: "no-store" }); setLogs(await r.json()); } catch {} if (!stop) setTimeout(tick, 2000); };
    tick(); return () => { stop = true; };
  }, []);
  const lastAgentRun = useRef(0);
  const runAgent = async (fs: Finding[]) => {
    if (agent.running || !fs.length) return;
    lastAgentRun.current = Date.now();
    setAgent((a) => ({ ...a, running: true })); setTab("agent");
    try {
      const r = await fetch("/api/respond", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ findings: fs }) });
      const j = await r.json();
      setAgent({ running: false, planner: j.planner, ms: j.ms, calls: j.calls ?? [], tokens: j.tokens, at: new Date().toLocaleTimeString() });
    } catch { setAgent((a) => ({ ...a, running: false })); }
  };
  const agentRef = useRef(runAgent); agentRef.current = runAgent;
  const autoRef = useRef(auto); autoRef.current = auto;

  const start = async (src: string) => {
    sourceRef.current = src; setSource(src);
    streamRef.current?.getTracks().forEach((t) => t.stop()); streamRef.current = null;
    if (src === SERVER) return;
    try {
      const stream = src === SCREEN
        ? await navigator.mediaDevices.getDisplayMedia({ video: { width: { ideal: 1920 } }, audio: false })
        : await navigator.mediaDevices.getUserMedia({ video: src ? { deviceId: { exact: src }, width: { ideal: 1920 } } : { width: { ideal: 1920 } }, audio: false });
      streamRef.current = stream;
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play().catch(() => {}); }
      const list = (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === "videoinput");
      setDevices(list);
      if (src !== SCREEN) { const active = stream.getVideoTracks()[0]?.getSettings().deviceId; if (active) { sourceRef.current = active; setSource(active); } }
    } catch (e) { console.error(e); }
  };

  const started = useRef(false);
  useEffect(() => { if (!started.current) { started.current = true; start(""); } return () => streamRef.current?.getTracks().forEach((t) => t.stop()); }, []);

  useEffect(() => {
    let stop = false;
    const off = document.createElement("canvas");
    const loop = async () => {
      const v = videoRef.current;
      if (sourceRef.current === SERVER) {
        try {
          const r = await fetch(`/api/live?t=${Date.now()}`, { cache: "no-store" });
          if (r.ok) {
            const j = (await r.json()) as ServerLive;
            if (j.updated !== lastServer.current) {
              lastServer.current = j.updated;
              const img = new Image(); img.src = `/api/live?img=1&t=${Date.now()}`; await img.decode().catch(() => {}); serverImg.current = img;
              lastBoxes.current = { boxes: [], w: 1, h: 1 };
              setFindings(j.findings); setStats((s) => ({ ms: j.lat_ms, frames: s.frames + 1 }));
              if (j.findings.length) setHistory((h) => [...j.findings, ...h].slice(0, 14));
            }
          }
        } catch {}
      } else if (v && v.videoWidth > 0) {
        off.width = v.videoWidth; off.height = v.videoHeight;
        off.getContext("2d")!.drawImage(v, 0, 0);
        const blob: Blob | null = await new Promise((r) => off.toBlob(r, "image/jpeg", 0.85));
        if (blob) {
          try {
            const r = await fetch("/api/detect", { method: "POST", body: blob });
            if (r.ok) {
              const j = (await r.json()) as { findings: Finding[]; ms: number };
              lastBoxes.current = { boxes: j.findings, w: off.width, h: off.height };
              setFindings(j.findings); setStats((s) => ({ ms: j.ms, frames: s.frames + 1 }));
              if (j.findings.length) setHistory((h) => [...j.findings, ...h].slice(0, 14));
              const serious = j.findings.filter((f) => f.severity === "critical" || f.severity === "high");
              if (autoRef.current && serious.length && Date.now() - lastAgentRun.current > 25000) agentRef.current(serious);
            }
          } catch {}
        }
      }
      if (!stop) setTimeout(loop, sourceRef.current === SERVER ? 300 : 120);
    };
    loop();
    return () => { stop = true; };
  }, []);

  useEffect(() => {
    let raf = 0;
    const draw = () => {
      const v = videoRef.current, c = canvasRef.current;
      if (c) {
        const ctx = c.getContext("2d")!;
        if (sourceRef.current === SERVER) {
          const img = serverImg.current;
          if (img && img.naturalWidth > 0) { if (c.width !== img.naturalWidth) { c.width = img.naturalWidth; c.height = img.naturalHeight; } ctx.drawImage(img, 0, 0); }
        } else if (v && v.videoWidth > 0) {
          if (c.width !== v.videoWidth) { c.width = v.videoWidth; c.height = v.videoHeight; }
          ctx.drawImage(v, 0, 0);
          const { boxes, w, h } = lastBoxes.current;
          const sx = c.width / w, sy = c.height / h;
          for (const f of boxes) {
            if (!f.box) continue;
            if (f.kind === "leak") {
              const pad = 8;
              const x = Math.max(0, (f.box.x - pad) * sx), y = Math.max(0, (f.box.y - pad) * sy);
              const bw = Math.min(c.width - x, (f.box.w + 2 * pad) * sx), bh = Math.min(c.height - y, (f.box.h + 2 * pad) * sy);
              if (bw < 2 || bh < 2) continue;
              const tiny = document.createElement("canvas"); tiny.width = Math.max(1, Math.floor(bw / 22)); tiny.height = Math.max(1, Math.floor(bh / 22));
              tiny.getContext("2d")!.drawImage(c, x, y, bw, bh, 0, 0, tiny.width, tiny.height);
              ctx.imageSmoothingEnabled = false; ctx.drawImage(tiny, 0, 0, tiny.width, tiny.height, x, y, bw, bh); ctx.imageSmoothingEnabled = true;
              ctx.strokeStyle = "#ff4d4f"; ctx.lineWidth = 4; ctx.strokeRect(x, y, bw, bh);
              ctx.fillStyle = "#ff4d4f"; ctx.font = "bold 20px system-ui"; ctx.fillText(f.rule, x + 6, Math.max(22, y - 8));
            } else {
              const x = f.box.x * sx, y = f.box.y * sy;
              ctx.strokeStyle = f.kind === "watch" ? "#2ec4b6" : "#ffb020"; ctx.lineWidth = 3; ctx.strokeRect(x, y, f.box.w * sx, f.box.h * sy);
              ctx.fillStyle = ctx.strokeStyle; ctx.font = "bold 18px system-ui"; ctx.fillText(f.rule, x + 6, Math.max(20, y - 6));
            }
          }
        }
      }
      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);
    return () => cancelAnimationFrame(raf);
  }, []);

  return (
    <main className="flex h-screen flex-col bg-black p-4 text-zinc-100">
      <header className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">ScreenShield <span className="ml-2 text-sm font-normal text-zinc-400">live · fast loop in Rust · no LLM</span></h1>
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm text-zinc-400">{stats.frames} frames · {stats.ms} ms · {findings.length} findings</span>
          <select id="source" value={source} onChange={(e) => start(e.target.value)} className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-sm">
            {devices.map((d) => <option key={d.deviceId} value={d.deviceId}>{d.label || "camera"}</option>)}
            <option value={SCREEN}>Share screen…</option>
            <option value={SERVER}>Server stream (shield scan --live)</option>
          </select>
          <button id="restart" onClick={() => start(source)} className="rounded-lg bg-sky-400 px-3 py-1.5 text-sm font-semibold text-black">⟳ restart</button>
        </div>
      </header>
      <div className="grid min-h-0 flex-1 grid-cols-[2fr_1fr] gap-4">
        <div className="relative min-h-0 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
          <video ref={videoRef} muted playsInline className="hidden" />
          <canvas ref={canvasRef} className="h-full w-full object-contain" />
          <div className="absolute left-3 top-3 rounded bg-red-500 px-2 py-0.5 text-xs font-semibold text-black">● LIVE · leaks pixelated before the recording</div>
        </div>
        <div className="flex min-h-0 flex-col rounded-xl border border-zinc-800 bg-zinc-950 p-3">
          <div className="mb-3 flex gap-1 border-b border-zinc-800 pb-2 text-sm">
            {(["detect", "agent", "clickhouse"] as const).map((t) => (
              <button key={t} id={`tab-${t}`} onClick={() => setTab(t)} className={`rounded-md px-3 py-1 ${tab === t ? "bg-zinc-800 text-zinc-100" : "text-zinc-500 hover:text-zinc-300"}`}>
                {t === "detect" ? "detect" : t === "agent" ? (agent.running ? "agent ●" : "agent") : "ClickHouse"}
              </button>
            ))}
          </div>
          <div className="min-h-0 flex-1 overflow-auto">
          <div hidden={tab !== "detect"}>
          <h2 className="mb-2 text-sm text-zinc-400">findings on the latest frame</h2>
          <ul className="space-y-1 text-sm">
            {findings.map((f, i) => (<li key={i} className="flex items-start gap-2"><span className="mt-1 inline-block h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: sev[f.severity] ?? "#aaa" }} /><span><span className="text-zinc-400">{f.kind}</span> <b>{f.rule}</b> <code className="rounded bg-zinc-800 px-1 text-xs">{f.match}</code></span></li>))}
            {findings.length === 0 && <li className="text-zinc-500">clean frame</li>}
          </ul>
          <h2 className="mb-2 mt-5 text-sm text-zinc-400">recent</h2>
          <ul className="space-y-1 text-xs text-zinc-400">{history.map((f, i) => (<li key={i}><span style={{ color: sev[f.severity] }}>{f.rule}</span> · {f.match}</li>))}</ul>
          </div>
          <div hidden={tab !== "agent"}>
          <div className="flex items-center justify-between">
            <h2 className="text-sm text-zinc-400">responder agent <span className="text-zinc-600">· sgr-agent on AkashML</span></h2>
            <div className="flex items-center gap-2">
              <label className="flex items-center gap-1 text-xs text-zinc-400"><input id="auto" type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> auto after a leak</label>
              <button id="run-agent" disabled={agent.running || !findings.length} onClick={() => runAgent(findings)} className="rounded-lg bg-amber-400 px-3 py-1 text-xs font-semibold text-black disabled:opacity-40">{agent.running ? "thinking…" : "▶ run agent"}</button>
            </div>
          </div>
          <div className="mt-2 rounded-lg border border-zinc-800 bg-black p-2 font-mono text-xs">
            {agent.running && <div className="text-amber-300">→ reading policy · fleet facts · planning tool calls…</div>}
            {!agent.running && agent.calls.length === 0 && <div className="text-zinc-600">no run yet</div>}
            {agent.calls.map((c, i) => (
              <div key={i} className="py-0.5">
                <div className="flex gap-2">
                  <span className={c.verdict === "blocked" || c.verdict === "failed" ? "text-red-400" : c.verdict === "needs_human" ? "text-amber-300" : "text-emerald-400"}>{c.verdict === "blocked" || c.verdict === "failed" ? "✗" : c.verdict === "needs_human" ? "?" : "✓"}</span>
                  <span className="text-zinc-100">{c.tool}</span>
                  <span className="truncate text-zinc-500">{c.args}</span>
                </div>
                {c.result && (
                  <div className="ml-5 mt-1 rounded border border-emerald-900 bg-emerald-950/40 p-2 text-emerald-200">
                    {c.result.error ? <div className="text-red-300">{String(c.result.error)}</div> : (<>
                      <div>incident <b>{String(c.result.incident ?? "")}</b> · {String(c.result.rotated)} value(s) rotated{c.result.branch ? <> · branch <code>{String(c.result.branch)}</code> @ {String(c.result.commit)}</> : null}</div>
                      {Array.isArray(c.result.changes) && (c.result.changes as Record<string, unknown>[]).map((ch, j) => (<div key={j} className="text-emerald-300/80">{String(ch.file)}:{String(ch.line)} <span className="text-red-300 line-through">{String(ch.old)}</span> → {String(ch.new)}</div>))}
                      <div className="text-emerald-300/80">COMPROMISED.md updated · {String(c.result.push ?? "")}{typeof c.result.pr === "string" && c.result.pr.startsWith("http") ? <> · <a className="underline" href={c.result.pr} target="_blank">pull request ↗</a></> : c.result.pr ? ` · ${String(c.result.pr)}` : ""}</div>
                    </>)}
                  </div>
                )}
              </div>
            ))}
            {!agent.running && agent.calls.length > 0 && <div className="mt-1 text-zinc-500">planner={agent.planner} · {agent.ms} ms{agent.tokens ? ` · ${agent.tokens}` : ""} · {agent.at}</div>}
          </div>
          <p className="mt-3 text-xs text-zinc-500">Slow loop: the agent reads the policy and fleet facts, plans tool calls with sgr-agent on AkashML, every call passes the DRIFT gates (taint, destination allowlist, destructive) and is logged to ClickHouse.</p>
          </div>
          <div hidden={tab !== "clickhouse"} className="font-mono text-xs">
            {!logs && <div className="text-zinc-600">connecting…</div>}
            {logs?.error && <div className="text-red-400">{logs.error}</div>}
            {logs && !logs.error && (<>
              <div className="mb-3 flex flex-wrap gap-3 text-zinc-400">{logs.totals.map((t) => (<span key={t.t}><b className="text-zinc-100">{Number(t.n).toLocaleString()}</b> {t.t}</span>))}<span className="text-zinc-600">· query {logs.ms} ms</span></div>
              <h3 className="mb-1 text-zinc-500">tool_calls</h3>
              {logs.calls.map((c, i) => (<div key={i} className="flex gap-2 py-0.5"><span className="text-zinc-600">{String(c.ts).slice(11, 19)}</span><span className={c.verdict === "blocked" ? "text-red-400" : "text-emerald-400"}>{String(c.verdict)}</span><span className="text-zinc-100">{String(c.tool)}</span><span className="truncate text-zinc-500">{String(c.args)}</span></div>))}
              <h3 className="mb-1 mt-3 text-zinc-500">findings</h3>
              {logs.findings.map((f, i) => (<div key={i} className="flex gap-2 py-0.5"><span className="text-zinc-600">{String(f.ts).slice(11, 19)}</span><span style={{ color: sev[String(f.severity)] }}>{String(f.rule)}</span><span className="text-zinc-500">{String(f.kind)}</span><span className="truncate text-zinc-400">{String(f.match)}</span></div>))}
              <h3 className="mb-1 mt-3 text-zinc-500">frame_events</h3>
              {logs.frames.map((f, i) => (<div key={i} className="flex gap-2 py-0.5 text-zinc-400"><span className="text-zinc-600">{String(f.ts).slice(11, 19)}</span><span>{String(f.room_id)}</span><span>{String(f.source_kind)}</span><span>{String(f.n_texts)} texts</span><span>{String(f.n_codes)} codes</span><span>ocr {String(f.ocr_len)} ch</span></div>))}
            </>)}
          </div>
          </div>
        </div>
      </div>
    </main>
  );
}
