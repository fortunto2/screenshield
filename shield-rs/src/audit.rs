//! audit: the slow loop. Walk an archive of recordings, run the fast path, hand findings to the responder,
//! and write the dataset the fast loop learns from (labelled keyframes + expectations) plus report.json.
use crate::{detect, frames, ocr, respond::Responder, store::Store};
use anyhow::Result;
use serde_json::json;
use std::path::Path;
use std::time::Instant;

const VIDEO: &[&str] = &["mp4", "mov", "mkv", "webm", "m4v"];

pub fn run(archive: &Path, work: &Path, dataset: &Path, fps: f64, min_change: u32, responder: &mut Responder, store: &Store) -> Result<serde_json::Value> {
    std::fs::create_dir_all(dataset)?;
    let t0 = Instant::now();
    let (mut recs, mut kfs, mut finds, mut acts, mut items) = (0, 0, 0, 0, 0);
    let mut files: Vec<_> = walk(archive);
    files.sort();
    for rec in files {
        recs += 1;
        let stream_id = rec.file_stem().unwrap().to_string_lossy().to_string();
        for frame in frames::FrameIter::open(&rec.to_string_lossy(), &work.join("frames").join(&stream_id), fps, min_change, None)? {
            kfs += 1;
            let res = ocr::scan_images(&[&frame.path])?.remove(0);
            let findings = detect::detect_all(&res.texts, &res.codes, &responder.policy.allowed_qr_domains);
            let labels: Vec<String> = findings.iter().map(|f| f.rule.to_string()).collect();
            for f in &findings {
                finds += 1;
                let row = json!({"ts": frame.ts, "stream_id": stream_id, "room_id": stream_id.split('-').next().unwrap_or("room"), "frame_path": frame.path,
                                 "kind": f.kind, "rule": f.rule, "severity": f.severity, "match": f.r#match, "reason": f.reason, "box": f.r#box});
                acts += responder.respond(&row, &json!({}), store).len();
            }
            if !labels.is_empty() {
                let item = dataset.join(format!("{stream_id}_{:06}.png", frame.index));
                std::fs::copy(&frame.path, &item)?;
                let mut must: Vec<String> = labels.clone(); must.sort(); must.dedup();
                std::fs::write(item.with_extension("expect.json"), serde_json::to_string_pretty(&json!({"must": must, "must_not": [], "source": rec.file_name().unwrap().to_string_lossy(), "t": frame.ts}))?)?;
                items += 1;
            }
        }
    }
    let report = json!({"recordings": recs, "keyframes": kfs, "findings": finds, "actions": acts, "dataset_items": items,
                        "seconds": (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0, "policy": responder.policy.source, "store": store.backend()});
    std::fs::write(dataset.join("report.json"), serde_json::to_string_pretty(&report)?)?;
    Ok(report)
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() { out.extend(walk(&p)); }
            else if p.extension().and_then(|x| x.to_str()).map(|x| VIDEO.contains(&x.to_lowercase().as_str())).unwrap_or(false) { out.push(p); }
        }
    }
    out
}
