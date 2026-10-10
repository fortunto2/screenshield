"use client";
import { useEffect, useRef, useState } from "react";

type Box = { x: number; y: number; w: number; h: number };
type Finding = { kind: string; rule: string; severity: string; match: string; box: Box | null; frame_w: number; frame_h: number };

const sev: Record<string, string> = { critical: "#ff4d4f", high: "#ffb020", medium: "#ffd166", low: "#4cc9f0" };

// Browser-side live demo: the browser owns the camera (Chrome's own device list: iPhone, Mac, DJI),
// sends a frame every ~600 ms to /api/detect (the Rust fast loop), and pixelates the leak boxes itself.
export default function CamPage() {
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [devices, setDevices] = useState<MediaDeviceInfo[]>([]);
  const [deviceId, setDeviceId] = useState<string>("");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [stats, setStats] = useState({ ms: 0, n: 0, frames: 0 });
  const [history, setHistory] = useState<Finding[]>([]);
  const streamRef = useRef<MediaStream | null>(null);
  const lastBoxes = useRef<{ boxes: Finding[]; w: number; h: number }>({ boxes: [], w: 1, h: 1 });

  const start = async (id?: string) => {
    streamRef.current?.getTracks().forEach((t) => t.stop());
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: id ? { deviceId: { exact: id }, width: { ideal: 1920 } } : { width: { ideal: 1920 } }, audio: false });
      streamRef.current = stream;
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play(); }
      const list = (await navigator.mediaDevices.enumerateDevices()).filter((d) => d.kind === "videoinput");
      setDevices(list);
      const active = stream.getVideoTracks()[0]?.getSettings().deviceId;
      if (active) setDeviceId(active);
    } catch (e) { console.error(e); }
  };

  useEffect(() => { start(); return () => streamRef.current?.getTracks().forEach((t) => t.stop()); }, []);

  // detection loop: grab a frame, send it, keep the boxes
  useEffect(() => {
    let stop = false;
    const off = document.createElement("canvas");
    const loop = async () => {
      const v = videoRef.current;
      if (v && v.videoWidth > 0) {
        off.width = v.videoWidth; off.height = v.videoHeight;
        off.getContext("2d")!.drawImage(v, 0, 0);
        const blob: Blob | null = await new Promise((r) => off.toBlob(r, "image/jpeg", 0.85));
        if (blob) {
          try {
            const r = await fetch("/api/detect", { method: "POST", body: blob });
            if (r.ok) {
              const j = (await r.json()) as { findings: Finding[]; ms: number };
              lastBoxes.current = { boxes: j.findings, w: off.width, h: off.height };
              setFindings(j.findings);
              setStats((s) => ({ ms: j.ms, n: j.findings.length, frames: s.frames + 1 }));
              if (j.findings.length) setHistory((h) => [...j.findings, ...h].slice(0, 14));
            }
          } catch {}
        }
      }
      if (!stop) setTimeout(loop, 150);
    };
    loop();
    return () => { stop = true; };
  }, []);

  // render loop: draw the video with leak boxes pixelated, at display rate
  useEffect(() => {
    let raf = 0;
    const draw = () => {
      const v = videoRef.current, c = canvasRef.current;
      if (v && c && v.videoWidth > 0) {
        if (c.width !== v.videoWidth) { c.width = v.videoWidth; c.height = v.videoHeight; }
        const ctx = c.getContext("2d")!;
        ctx.drawImage(v, 0, 0);
        const { boxes, w, h } = lastBoxes.current;
        const sx = c.width / w, sy = c.height / h;
        for (const f of boxes) {
          if (!f.box || f.kind !== "leak") continue;
          const pad = 8;
          const x = Math.max(0, (f.box.x - pad) * sx), y = Math.max(0, (f.box.y - pad) * sy);
          const bw = Math.min(c.width - x, (f.box.w + 2 * pad) * sx), bh = Math.min(c.height - y, (f.box.h + 2 * pad) * sy);
          if (bw < 2 || bh < 2) continue;
          // pixelate: downscale the region into a tiny canvas and scale it back up without smoothing
          const tiny = document.createElement("canvas"); tiny.width = Math.max(1, Math.floor(bw / 22)); tiny.height = Math.max(1, Math.floor(bh / 22));
          tiny.getContext("2d")!.drawImage(c, x, y, bw, bh, 0, 0, tiny.width, tiny.height);
          ctx.imageSmoothingEnabled = false; ctx.drawImage(tiny, 0, 0, tiny.width, tiny.height, x, y, bw, bh); ctx.imageSmoothingEnabled = true;
          ctx.strokeStyle = "#ff4d4f"; ctx.lineWidth = 4; ctx.strokeRect(x, y, bw, bh);
          ctx.fillStyle = "#ff4d4f"; ctx.font = "bold 20px system-ui"; ctx.fillText(f.rule, x + 6, Math.max(22, y - 8));
        }
        for (const f of boxes) {
          if (!f.box || f.kind === "leak") continue;
          const x = f.box.x * sx, y = f.box.y * sy;
          ctx.strokeStyle = f.kind === "watch" ? "#2ec4b6" : "#ffb020"; ctx.lineWidth = 3; ctx.strokeRect(x, y, f.box.w * sx, f.box.h * sy);
          ctx.fillStyle = ctx.strokeStyle; ctx.font = "bold 18px system-ui"; ctx.fillText(f.rule, x + 6, Math.max(20, y - 6));
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
        <h1 className="text-xl font-semibold">ScreenShield <span className="ml-2 text-sm font-normal text-zinc-400">live · camera in the browser · detectors in Rust · no LLM</span></h1>
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm text-zinc-400">{stats.frames} frames · {stats.ms} ms · {stats.n} findings</span>
          <select id="camera" value={deviceId} onChange={(e) => start(e.target.value)} className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-sm">
            {devices.map((d) => <option key={d.deviceId} value={d.deviceId}>{d.label || "camera"}</option>)}
          </select>
          <button onClick={() => start(deviceId)} className="rounded-lg bg-sky-400 px-3 py-1.5 text-sm font-semibold text-black">⟳ restart</button>
        </div>
      </header>
      <div className="grid min-h-0 flex-1 grid-cols-[2fr_1fr] gap-4">
        <div className="relative min-h-0 overflow-hidden rounded-xl border border-zinc-800 bg-zinc-950">
          <video ref={videoRef} muted playsInline className="hidden" />
          <canvas ref={canvasRef} className="h-full w-full object-contain" />
          <div className="absolute left-3 top-3 rounded bg-red-500 px-2 py-0.5 text-xs font-semibold text-black">● LIVE · leaks pixelated before the recording</div>
        </div>
        <div className="min-h-0 overflow-auto rounded-xl border border-zinc-800 bg-zinc-950 p-3">
          <h2 className="mb-2 text-sm text-zinc-400">findings on the latest frame</h2>
          <ul className="space-y-1 text-sm">
            {findings.map((f, i) => (<li key={i} className="flex items-start gap-2"><span className="mt-1 inline-block h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: sev[f.severity] ?? "#aaa" }} /><span><span className="text-zinc-400">{f.kind}</span> <b>{f.rule}</b> <code className="rounded bg-zinc-800 px-1 text-xs">{f.match}</code></span></li>))}
            {findings.length === 0 && <li className="text-zinc-500">clean frame</li>}
          </ul>
          <h2 className="mb-2 mt-5 text-sm text-zinc-400">recent</h2>
          <ul className="space-y-1 text-xs text-zinc-400">{history.map((f, i) => (<li key={i}><span style={{ color: sev[f.severity] }}>{f.rule}</span> · {f.match}</li>))}</ul>
        </div>
      </div>
    </main>
  );
}
