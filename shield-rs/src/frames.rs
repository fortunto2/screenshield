//! Frame sources and keyframe selection. ffmpeg decodes (screen, camera, file, SRT/RTMP all look alike);
//! a frame is kept when its dHash moved >= min_change bits from the last kept one.

use anyhow::{Context, Result};
use image::{DynamicImage, GenericImageView};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub struct Frame {
    pub index: u64,
    pub ts: f64,
    pub path: PathBuf,
    pub dhash: u64,
}

pub fn dhash(img: &DynamicImage) -> u64 {
    let g = img.resize_exact(9, 8, image::imageops::FilterType::Triangle).to_luma8();
    let mut bits = 0u64;
    for y in 0..8 {
        for x in 0..8 {
            bits = (bits << 1) | u64::from(g.get_pixel(x, y)[0] > g.get_pixel(x + 1, y)[0]);
        }
    }
    bits
}

pub fn hamming(a: u64, b: u64) -> u32 { (a ^ b).count_ones() }

pub fn input_args(source: &str) -> Vec<String> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    if source == "screen" {
        let idx = avf_index("Capture screen").unwrap_or(5);
        return s(&["-f", "avfoundation", "-framerate", "5", "-pixel_format", "uyvy422", "-capture_cursor", "1", "-i", &format!("{idx}:none")]);
    }
    if let Some(name) = source.strip_prefix("cam:") {
        let idx = avf_index(name).unwrap_or(0);
        return s(&["-f", "avfoundation", "-framerate", "30", "-pixel_format", "uyvy422", "-i", &format!("{idx}:none")]);
    }
    if let Some(idx) = source.strip_prefix("camera:") {
        return s(&["-f", "avfoundation", "-framerate", "30", "-pixel_format", "uyvy422", "-i", &format!("{idx}:none")]);
    }
    s(&["-i", source])
}

/// Index of the first avfoundation video device whose name contains `needle` (devices shift when a phone or
/// camera is plugged in, so never hardcode).
pub fn avf_index(needle: &str) -> Option<u32> {
    let out = Command::new("ffmpeg").args(["-hide_banner", "-f", "avfoundation", "-list_devices", "true", "-i", ""]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stderr);
    let mut in_video = false;
    for line in text.lines() {
        if line.contains("video devices") { in_video = true; continue; }
        if line.contains("audio devices") { break; }
        if in_video && line.contains(needle) {
            if let (Some(a), Some(b)) = (line.rfind('['), line.rfind(']')) { return line[a + 1..b].parse().ok(); }
        }
    }
    None
}

fn is_image(source: &str) -> bool {
    let l = source.to_lowercase();
    [".png", ".jpg", ".jpeg", ".webp", ".bmp"].iter().any(|e| l.ends_with(e))
}

pub struct FrameIter {
    child: Child,
    buf: Vec<u8>,
    index: u64,
    kept: u64,
    fps: f64,
    min_change: u32,
    limit: Option<u64>,
    last: Option<u64>,
    out_dir: PathBuf,
}

const IEND: &[u8] = b"IEND\xaeB`\x82";

impl FrameIter {
    /// `record`: also write the source to this file from the SAME ffmpeg process (a second output), because
    /// macOS lets only one process own the screen/camera device.
    pub fn open(source: &str, out_dir: &Path, fps: f64, min_change: u32, limit: Option<u64>, record: Option<&Path>) -> Result<Self> {
        std::fs::create_dir_all(out_dir)?;
        let mut cmd = Command::new("ffmpeg");
        cmd.args(["-hide_banner", "-loglevel", "error", "-y"]).args(input_args(source));
        if let Some(rec) = record {
            // keyframe every second and 1 s fragments: a recording stopped early is still playable; Retina screens are
            // scaled to 1080p for the encoder (the analysis path keeps full resolution)
            cmd.args(["-vf", "scale='min(1920,iw)':-2", "-c:v", "libx264", "-preset", "ultrafast", "-pix_fmt", "yuv420p", "-g", "5",
                      "-movflags", "+frag_keyframe+empty_moov+default_base_moof", "-frag_duration", "1000000"]).arg(rec);
        }
        if !is_image(source) { cmd.args(["-vf", &format!("fps={fps}")]); }
        cmd.args(["-f", "image2pipe", "-vcodec", "png", "-"]).stdout(Stdio::piped()).stdin(Stdio::piped());
        let child = cmd.spawn().context("ffmpeg not found or failed to start")?;
        Ok(Self { child, buf: Vec::new(), index: 0, kept: 0, fps, min_change, limit, last: None, out_dir: out_dir.into() })
    }

    fn next_png(&mut self) -> Option<Vec<u8>> {
        let stdout = self.child.stdout.as_mut()?;
        let mut chunk = [0u8; 1 << 16];
        loop {
            if let Some(i) = self.buf.windows(IEND.len()).position(|w| w == IEND) {
                let end = i + IEND.len();
                let png = self.buf[..end].to_vec();
                self.buf.drain(..end);
                return Some(png);
            }
            match stdout.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
            }
        }
    }
}

impl Iterator for FrameIter {
    type Item = Frame;
    fn next(&mut self) -> Option<Frame> {
        if let Some(l) = self.limit { if self.kept >= l { self.stop(); return None; } }
        loop {
            let png = self.next_png()?;
            let ts = self.index as f64 / self.fps;
            self.index += 1;
            let Ok(img) = image::load_from_memory(&png) else { continue };
            let (w, h) = img.dimensions();
            let small = if w > 640 { img.resize(640, 360, image::imageops::FilterType::Triangle) } else { img };
            let hsh = dhash(&small);
            if let Some(last) = self.last { if hamming(hsh, last) < self.min_change { continue; } }
            self.last = Some(hsh);
            let path = self.out_dir.join(format!("f{:06}_{:08.2}.png", self.index, ts));
            if std::fs::write(&path, &png).is_err() { continue; }
            self.kept += 1;
            let _ = (w, h);
            return Some(Frame { index: self.index, ts, path, dhash: hsh });
        }
    }
}

impl FrameIter {
    /// Ask ffmpeg to finish cleanly (so the recording gets its trailer), then kill if it lingers.
    pub fn stop(&mut self) {
        use std::io::Write;
        if let Some(mut si) = self.child.stdin.take() { let _ = si.write_all(b"q"); let _ = si.flush(); }
        for _ in 0..100 {
            if let Ok(Some(_)) = self.child.try_wait() { return; }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = self.child.kill();
    }
}

impl Drop for FrameIter { fn drop(&mut self) { self.stop(); } }
