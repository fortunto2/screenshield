mod detect;
mod frames;
mod guard;
mod ocr;
mod store;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "shield", about = "DLP for video: leaks out, attacks in. Fast loop on device, agent over the archive.")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan a video file, 'screen', 'camera:<idx>' or a stream url; one JSON line per finding
    Scan {
        source: String,
        #[arg(long, default_value = ".shield")] work: PathBuf,
        #[arg(long, default_value_t = 2.0)] fps: f64,
        #[arg(long, default_value_t = 6)] min_change: u32,
        #[arg(long)] limit: Option<u64>,
        #[arg(long)] allow: Vec<String>,
        #[arg(long, default_value = "room-local")] room: String,
        #[arg(short, long)] verbose: bool,
    },
}

fn main() -> Result<()> {
    load_env();
    match Cli::parse().cmd {
        Cmd::Scan { source, work, fps, min_change, limit, allow, room, verbose } => scan(&source, &work, fps, min_change, limit, &allow, &room, verbose),
    }
}

fn load_env() {
    for p in [".env", "../.env", "app/.env"] {
        if let Ok(s) = std::fs::read_to_string(p) {
            for line in s.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                if let Some((k, v)) = line.split_once('=') {
                    if std::env::var(k.trim()).is_err() { unsafe { std::env::set_var(k.trim(), v.trim().trim_matches('"').trim_matches('\'')); } }
                }
            }
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn scan(source: &str, work: &Path, fps: f64, min_change: u32, limit: Option<u64>, allow: &[String], room: &str, verbose: bool) -> Result<()> {
    let store = store::Store::new(work)?;
    let mut guard = guard::Guard::new(vec![]);
    let t0 = Instant::now();
    let (mut n_frames, mut n_findings) = (0u64, 0u64);
    let stream_id = format!("{room}-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    for frame in frames::FrameIter::open(source, &work.join("frames"), fps, min_change, limit)? {
        let tf = Instant::now();
        n_frames += 1;
        let res = ocr::scan_images(&[&frame.path])?.remove(0);
        let joined: Vec<String> = res.texts.iter().map(|t| t.text.clone()).collect();
        guard.observe_frame_text(frame.ts, &joined.join("\n"));
        let findings = detect::detect_all(&res.texts, &res.codes, allow);
        let mpx = f64::from(res.width.max(1) * res.height.max(1)) / 1e6;
        store.insert("frame_events", &[serde_json::json!({
            "ts": store::now_iso(), "org_id": "demo", "site_id": "local", "room_id": room, "device_id": "mac",
            "stream_id": stream_id, "source_kind": if source == "screen" { "screen" } else { "camera" },
            "phash": frame.dhash, "text_density": (joined.join("").len() as f64 / mpx).round(), "n_texts": res.texts.len(),
            "n_codes": res.codes.len(), "app_class": "unknown", "token_hashes": [], "qr_payload": res.codes.first().map(|c| c.payload.clone()).unwrap_or_default(),
            "viewers": 1, "embedding": []
        })])?;
        let mut rows = Vec::new();
        for f in &findings {
            n_findings += 1;
            let masked = if f.kind == "leak" { mask(&f.r#match) } else { f.r#match.clone() };
            rows.push(serde_json::json!({
                "ts": store::now_iso(), "org_id": "demo", "room_id": room, "stream_id": stream_id, "kind": f.kind, "rule": f.rule,
                "severity": f.severity, "match_hash": 0, "match": masked, "reason": f.reason,
                "box": f.r#box.as_ref().map(|b| vec![b.x, b.y, b.w, b.h]).unwrap_or_default(),
                "action": if f.r#box.is_some() && f.kind == "leak" { "blurred" } else { "logged" }, "frame_path": frame.path.to_string_lossy()
            }));
            println!("{}", serde_json::json!({"ts": frame.ts, "frame": frame.path, "lat_ms": tf.elapsed().as_millis() as u64, "kind": f.kind, "rule": f.rule, "severity": f.severity, "match": f.r#match, "reason": f.reason, "box": f.r#box}));
        }
        store.insert("findings", &rows)?;
        if verbose { eprintln!("# kf {} t={:.1}s texts={} codes={} findings={} lat={}ms", frame.index, frame.ts, res.texts.len(), res.codes.len(), findings.len(), tf.elapsed().as_millis()); }
    }
    eprintln!("# done frames={n_frames} findings={n_findings} store={} in {:.1}s", store.backend(), t0.elapsed().as_secs_f64());
    Ok(())
}

fn mask(s: &str) -> String { if s.len() > 8 { format!("{}{}", &s[..4], "*".repeat(s.len() - 4)) } else { "*".repeat(s.len()) } }
