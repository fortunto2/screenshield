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
    fn one_overlay_per_region_with_window() {
        let (g, last) = build_filter(&[Region { t_from: 1.0, t_to: 2.5, x: 10.0, y: 20.0, w: 100.0, h: 30.0 }, Region { t_from: 3.0, t_to: 4.0, x: 0.0, y: 0.0, w: 50.0, h: 50.0 }]);
        assert_eq!(g.matches("overlay=").count(), 2);
        assert!(g.contains("between(t,1.000,2.500)"));
        assert_eq!(last, "v1");
    }
}
