//! Redaction: blur boxes in a recording for time ranges, one ffmpeg pass.
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct Region { pub t_from: f64, pub t_to: f64, pub x: f64, pub y: f64, pub w: f64, pub h: f64 }

fn even(v: f64) -> i64 { let n = (v.round() as i64).max(2); if n % 2 == 0 { n } else { n + 1 } }

pub fn build_filter(regions: &[Region]) -> (String, String) {
    let mut parts = Vec::new();
    let mut prev = "0:v".to_string();
    for (i, r) in regions.iter().enumerate() {
        let pad = 8.0;
        let (x, y) = ((r.x - pad).max(0.0) as i64, (r.y - pad).max(0.0) as i64);
        let (w, h) = (even(r.w + 2.0 * pad), even(r.h + 2.0 * pad));
        parts.push(format!("[{prev}]split[s{i}][p{i}]"));
        parts.push(format!("[p{i}]crop={w}:{h}:{x}:{y},boxblur=luma_radius=12:luma_power=2:chroma_radius=5:chroma_power=2[b{i}]"));
        parts.push(format!("[s{i}][b{i}]overlay={x}:{y}:enable='between(t,{:.3},{:.3})'[v{i}]", r.t_from, r.t_to));
        prev = format!("v{i}");
    }
    (parts.join(";"), prev)
}

/// Merge regions whose boxes overlap (same on-screen line across consecutive keyframes) into one region
/// spanning the union box and the whole time window. 22 overlapping overlays → 1 or 2: ffmpeg goes from
/// minutes to seconds and the blur stays continuous instead of flickering.
pub fn merge_regions(mut regs: Vec<Region>) -> Vec<Region> {
    regs.sort_by(|a, b| a.t_from.partial_cmp(&b.t_from).unwrap());
    let mut out: Vec<Region> = Vec::new();
    for r in regs {
        if let Some(m) = out.iter_mut().find(|m| overlaps(m, &r) && r.t_from <= m.t_to + 2.0) {
            let x0 = m.x.min(r.x); let y0 = m.y.min(r.y);
            let x1 = (m.x + m.w).max(r.x + r.w); let y1 = (m.y + m.h).max(r.y + r.h);
            m.x = x0; m.y = y0; m.w = x1 - x0; m.h = y1 - y0;
            m.t_from = m.t_from.min(r.t_from); m.t_to = m.t_to.max(r.t_to);
        } else { out.push(r); }
    }
    out
}

fn overlaps(a: &Region, b: &Region) -> bool {
    let ix = (a.x + a.w).min(b.x + b.w) - a.x.max(b.x);
    let iy = (a.y + a.h).min(b.y + b.h) - a.y.max(b.y);
    if ix <= 0.0 || iy <= 0.0 { return false; }
    let inter = ix * iy;
    inter / (a.w * a.h).min(b.w * b.h).max(1.0) > 0.3
}

pub fn video_width(src: &Path) -> Option<f64> {
    let out = Command::new("ffprobe").args(["-v", "error", "-select_streams", "v:0", "-show_entries", "stream=width", "-of", "csv=p=0"]).arg(src).output().ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

pub fn redact(src: &Path, dst: &Path, regions: &[Region]) -> Result<()> {
    anyhow::ensure!(!regions.is_empty(), "no regions");
    let (graph, last) = build_filter(regions);
    let st = Command::new("ffmpeg").args(["-hide_banner", "-loglevel", "error", "-y", "-i"]).arg(src)
        .args(["-filter_complex", &graph, "-map", &format!("[{last}]"), "-map", "0:a?", "-c:v", "libx264", "-preset", "veryfast", "-crf", "20", "-c:a", "copy"]).arg(dst)
        .status().context("ffmpeg")?;
    anyhow::ensure!(st.success(), "ffmpeg redact failed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn merge_collapses_same_line_over_time() {
        let regs: Vec<Region> = (0..10).map(|i| Region { t_from: i as f64 * 0.5, t_to: i as f64 * 0.5 + 1.0, x: 100.0 + i as f64, y: 50.0, w: 400.0, h: 30.0 }).collect();
        let m = merge_regions(regs);
        assert_eq!(m.len(), 1);
        assert!((m[0].t_to - 5.5).abs() < 1e-9 && m[0].t_from == 0.0);
    }
    #[test]
    fn one_overlay_per_region_with_window() {
        let (g, last) = build_filter(&[Region { t_from: 1.0, t_to: 2.5, x: 10.0, y: 20.0, w: 100.0, h: 30.0 }, Region { t_from: 3.0, t_to: 4.0, x: 0.0, y: 0.0, w: 50.0, h: 50.0 }]);
        assert_eq!(g.matches("overlay=").count(), 2);
        assert!(g.contains("between(t,1.000,2.500)"));
        assert_eq!(last, "v1");
    }
}
