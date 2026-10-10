//! `shield run --in <source> --out <destination>`: the fast loop as a stream processor. Frames come in from a camera,
//! the screen, a file or a URL; they go out to RTMP/SRT/a file with leak boxes pixelated. The output is delayed by
//! `--delay` seconds so a secret is blurred BEFORE its first frame leaves (a frame waits in the buffer while the
//! detector looks at it). No LLM on this path. One ffmpeg decodes, one ffmpeg encodes, OCR runs in a worker thread.
use crate::{detect, frames, ocr, store};
use anyhow::{Context, Result};
use image::RgbImage;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const W: u32 = 1280;
pub const H: u32 = 720;
type Boxes = Vec<(f64, f64, f64, f64)>;

struct Detected { index: u64, boxes: Boxes, findings: Vec<detect::Finding>, texts: usize, codes: usize, lat_ms: u64 }

pub fn output_args(out: &str) -> Vec<String> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let enc = ["-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency", "-pix_fmt", "yuv420p", "-g", "30", "-b:v", "3M"];
    let mut v = s(&enc);
    let l = out.to_lowercase();
    if l.starts_with("rtmp://") || l.starts_with("rtmps://") { v.extend(s(&["-f", "flv"])); }
    else if l.starts_with("srt://") || l.starts_with("udp://") { v.extend(s(&["-f", "mpegts"])); }
    else if l.ends_with(".mp4") || l.ends_with(".mov") { v.extend(s(&["-movflags", "+faststart"])); }
    v.push(out.to_string());
    v
}

pub fn run(input: &str, out: &str, work: &std::path::Path, fps: u32, delay_s: f64, hold_s: f64, interval_ms: u64, allow: &[String], room: &str, verbose: bool) -> Result<()> {
    std::fs::create_dir_all(work.join("frames"))?;
    let st = store::Store::new(work)?;
    let stream_id = format!("{room}-{}", chrono::Utc::now().format("%Y%m%d%H%M%S"));
    let frame_len = (W * H * 3) as usize;

    // decoder: any source → raw RGB frames at a fixed size and rate
    let mut dec = Command::new("ffmpeg");
    dec.args(["-hide_banner", "-loglevel", "error"]);
    if !input.starts_with("cam:") && !input.starts_with("camera:") && input != "screen" && !input.contains("://") { dec.arg("-re"); }
    dec.args(frames::input_args(input))
        .args(["-vf", &format!("fps={fps},scale={W}:{H}:force_original_aspect_ratio=decrease,pad={W}:{H}:(ow-iw)/2:(oh-ih)/2"), "-f", "rawvideo", "-pix_fmt", "rgb24", "-"])
        .stdout(Stdio::piped()).stdin(Stdio::piped());
    let mut dec = dec.spawn().context("ffmpeg (decoder) failed to start")?;
    let mut src = dec.stdout.take().unwrap();

    // encoder: raw RGB → H.264 to the destination
    let mut enc = Command::new("ffmpeg");
    enc.args(["-hide_banner", "-loglevel", "error", "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", &format!("{W}x{H}"), "-r", &fps.to_string(), "-i", "-"])
        .args(output_args(out)).stdin(Stdio::piped());
    let mut enc = enc.spawn().context("ffmpeg (encoder) failed to start")?;
    let mut dst = enc.stdin.take().unwrap();

    // detector thread: PNG → Apple Vision OCR+QR → detectors → boxes
    let (to_det, det_rx) = mpsc::sync_channel::<(u64, Vec<u8>)>(1);
    let (det_tx, from_det) = mpsc::channel::<Detected>();
    let allow_v = allow.to_vec();
    let frames_dir = work.join("frames");
    std::thread::spawn(move || {
        for (index, rgb) in det_rx {
            let t = Instant::now();
            let path = frames_dir.join(format!("f{index:06}_{:08.2}.png", index as f64 / fps as f64));
            let Some(img) = RgbImage::from_raw(W, H, rgb) else { continue };
            if img.save(&path).is_err() { continue }
            let Ok(mut res) = ocr::scan_images(&[&path]) else { continue };
            let Some(res) = res.pop() else { continue };
            let findings = detect::detect_all(&res.texts, &res.codes, &allow_v);
            let boxes = findings.iter().filter(|f| f.kind == "leak").filter_map(|f| f.r#box.as_ref().map(|b| (b.x, b.y, b.w, b.h))).collect();
            if findings.is_empty() { let _ = std::fs::remove_file(&path); }
            let _ = det_tx.send(Detected { index, boxes, findings, texts: res.texts.len(), codes: res.codes.len(), lat_ms: t.elapsed().as_millis() as u64 });
        }
    });

    let delay_frames = (delay_s * fps as f64).round() as usize;
    let hold_frames = (hold_s * fps as f64).round() as u64;
    let mut queue: VecDeque<(u64, Vec<u8>)> = VecDeque::new();
    let mut active: Boxes = Vec::new();
    let mut active_until: u64 = 0;
    let mut index: u64 = 0;
    let mut last_sent = Instant::now() - Duration::from_secs(10);
    let (mut n_findings, t0) = (0u64, Instant::now());
    eprintln!("# run {input} → {out} · {W}x{H}@{fps} · delay {delay_s}s · hold {hold_s}s · detector every {interval_ms}ms · store={}", st.backend());

    let mut buf = vec![0u8; frame_len];
    loop {
        if src.read_exact(&mut buf).is_err() { break; }
        index += 1;
        // hand a frame to the detector when it is free and the interval passed
        if last_sent.elapsed() >= Duration::from_millis(interval_ms) && to_det.try_send((index, buf.clone())).is_ok() { last_sent = Instant::now(); }
        // results: apply to every buffered frame from the detected one onward, and hold
        while let Ok(d) = from_det.try_recv() {
            if !d.boxes.is_empty() { active = d.boxes.clone(); active_until = index.max(d.index) + hold_frames; }
            if !d.findings.is_empty() {
                n_findings += d.findings.len() as u64;
                let rows: Vec<serde_json::Value> = d.findings.iter().map(|f| serde_json::json!({
                    "ts": store::now_iso(), "org_id": "demo", "room_id": room, "stream_id": stream_id, "kind": f.kind, "rule": f.rule, "severity": f.severity,
                    "match_hash": 0, "match": if f.kind == "leak" { store_mask(&f.r#match) } else { f.r#match.clone() }, "reason": f.reason,
                    "box": f.r#box.as_ref().map(|b| vec![b.x, b.y, b.w, b.h]).unwrap_or_default(),
                    "action": if f.r#box.is_some() && f.kind == "leak" { "blurred" } else { "logged" }, "frame_path": "", "evidence_jpeg": "" })).collect();
                let _ = st.insert("findings", &rows);
                for f in &d.findings { println!("{}", serde_json::json!({"t": d.index as f64 / fps as f64, "kind": f.kind, "rule": f.rule, "severity": f.severity, "match": if f.kind == "leak" { store_mask(&f.r#match) } else { f.r#match.clone() }, "lat_ms": d.lat_ms})); }
            }
            for (qi, frame) in queue.iter_mut() { if *qi >= d.index && !d.boxes.is_empty() { pixelate(frame, &d.boxes); } }
            if verbose { eprintln!("# kf {} texts={} codes={} findings={} lat={}ms", d.index, d.texts, d.codes, d.findings.len(), d.lat_ms); }
        }
        let mut frame = std::mem::replace(&mut buf, vec![0u8; frame_len]);
        if index <= active_until && !active.is_empty() { pixelate(&mut frame, &active); }
        queue.push_back((index, frame));
        while queue.len() > delay_frames {
            let (_, f) = queue.pop_front().unwrap();
            if dst.write_all(&f).is_err() { break; }
        }
    }
    for (_, f) in queue.drain(..) { let _ = dst.write_all(&f); }
    drop(dst);
    let _ = enc.wait();
    let _ = dec.wait();
    eprintln!("# done frames={index} findings={n_findings} in {:.1}s", t0.elapsed().as_secs_f64());
    Ok(())
}

fn store_mask(s: &str) -> String { crate::repo::mask(s) }

/// Pixelate the leak boxes in a raw RGB frame (same look as the live view: coarse blocks + red frame).
pub fn pixelate(rgb: &mut Vec<u8>, boxes: &Boxes) {
    let Some(mut img) = RgbImage::from_raw(W, H, std::mem::take(rgb)) else { return };
    store::pixelate_image(&mut img, boxes);
    *rgb = img.into_raw();
}
