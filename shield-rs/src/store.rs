//! Store: JSONL always; ClickHouse over HTTP (JSONEachRow) when CLICKHOUSE_URL is set.
use anyhow::Result;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct Store {
    pub work: PathBuf,
    pub ch: Option<(String, String, String)>, // url, user, password
}

impl Store {
    pub fn new(work: &Path) -> Result<Self> {
        std::fs::create_dir_all(work)?;
        let ch = std::env::var("CLICKHOUSE_URL").ok().map(|u| (u, std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into()), std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default()));
        Ok(Self { work: work.into(), ch })
    }
    pub fn backend(&self) -> &'static str { if self.ch.is_some() { "clickhouse" } else { "jsonl" } }

    pub fn insert(&self, table: &str, rows: &[Value]) -> Result<()> {
        if rows.is_empty() { return Ok(()); }
        let mut f = OpenOptions::new().create(true).append(true).open(self.work.join(format!("{table}.jsonl")))?;
        for r in rows { writeln!(f, "{r}")?; }
        if let Some((url, user, pass)) = &self.ch {
            let body: String = rows.iter().map(|r| r.to_string() + "\n").collect();
            let q = format!("INSERT INTO {table} FORMAT JSONEachRow");
            let resp = ureq::post(url).query("query", &q).query("input_format_skip_unknown_fields", "1").query("date_time_input_format", "best_effort")
                .header("X-ClickHouse-User", user).header("X-ClickHouse-Key", pass).send(body.as_bytes());
            if let Err(e) = resp { eprintln!("# clickhouse insert failed: {e}"); }
        }
        Ok(())
    }
}

/// Evidence for an incident: the flagged keyframe as a 640px JPEG, base64. Ordinary keyframes stay text + hash.
pub fn evidence_jpeg_b64(frame: &std::path::Path) -> String {
    use base64::Engine;
    let Ok(img) = image::open(frame) else { return String::new() };
    let small = img.resize(640, 360, image::imageops::FilterType::Triangle);
    let mut buf = std::io::Cursor::new(Vec::new());
    if image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 70).encode_image(&small).is_err() { return String::new(); }
    base64::engine::general_purpose::STANDARD.encode(buf.into_inner())
}

/// Live view: the latest keyframe with every leak box pixelated, as a JPEG for the /live page.
/// Boxes are [x, y, w, h] in frame pixels. Returns the encoded JPEG bytes.
pub fn live_frame_jpeg(frame: &std::path::Path, boxes: &[(f64, f64, f64, f64)], max_w: u32) -> Option<Vec<u8>> {
    let mut img = image::open(frame).ok()?.to_rgb8();
    let (iw, ih) = img.dimensions();
    pixelate_image(&mut img, boxes);
    let out = if iw > max_w { image::imageops::resize(&img, max_w, (ih as f64 * max_w as f64 / iw as f64) as u32, image::imageops::FilterType::Triangle) } else { img };
    let mut buf = std::io::Cursor::new(Vec::new());
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 78).encode_image(&out).ok()?;
    Some(buf.into_inner())
}

/// Coarse blocks over each leak box plus a red frame, in place.
pub fn pixelate_image(img: &mut image::RgbImage, boxes: &[(f64, f64, f64, f64)]) {
    let (iw, ih) = img.dimensions();
    for &(x, y, w, h) in boxes {
        let pad = 8.0;
        let x0 = (x - pad).max(0.0) as u32; let y0 = (y - pad).max(0.0) as u32;
        let x1 = ((x + w + pad).min(iw as f64)) as u32; let y1 = ((y + h + pad).min(ih as f64)) as u32;
        if x1 <= x0 + 2 || y1 <= y0 + 2 { continue; }
        let sub = image::imageops::crop_imm(img, x0, y0, x1 - x0, y1 - y0).to_image();
        let small = image::imageops::resize(&sub, ((x1 - x0) / 24).max(1), ((y1 - y0) / 24).max(1), image::imageops::FilterType::Triangle);
        let big = image::imageops::resize(&small, x1 - x0, y1 - y0, image::imageops::FilterType::Nearest);
        image::imageops::replace(img, &big, x0 as i64, y0 as i64);
        // red frame around the pixelated region
        for xx in x0..x1 { for yy in [y0, y0 + 1, y1.saturating_sub(2), y1.saturating_sub(1)] { if yy < ih { img.put_pixel(xx, yy, image::Rgb([255, 77, 79])); } } }
        for yy in y0..y1 { for xx in [x0, x0 + 1, x1.saturating_sub(2), x1.saturating_sub(1)] { if xx < iw { img.put_pixel(xx, yy, image::Rgb([255, 77, 79])); } } }
    }
}

pub fn now_iso() -> String { chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string() }
