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

pub fn now_iso() -> String { chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string() }
