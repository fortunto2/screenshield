//! OCR + barcodes via the Swift `visionscan` helper (Apple Vision, on-device).
use crate::detect::{CodeHit, TextHit};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Deserialize)]
pub struct ScanResult {
    pub path: String,
    pub width: u32,
    pub height: u32,
    pub texts: Vec<TextHit>,
    pub codes: Vec<CodeHit>,
    pub error: Option<String>,
}

pub fn visionscan_bin() -> PathBuf {
    if let Ok(p) = std::env::var("SHIELD_VISIONSCAN") { return p.into(); }
    // installed next to the shield binary (Homebrew, release tarball)
    if let Ok(exe) = std::env::current_exe() { if let Some(d) = exe.parent() { let p = d.join("visionscan"); if p.exists() { return p; } } }
    for c in ["bin/visionscan", "../bin/visionscan", "app/bin/visionscan"] {
        if Path::new(c).exists() { return c.into(); }
    }
    "visionscan".into()
}

pub fn scan_images(paths: &[&Path]) -> Result<Vec<ScanResult>> {
    if paths.is_empty() { return Ok(vec![]); }
    let out = Command::new(visionscan_bin()).args(paths).output().context("visionscan helper missing: build it with `make vision` in app/")?;
    anyhow::ensure!(out.status.success(), "visionscan exit {:?}: {}", out.status, String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).context("bad visionscan json")).collect()
}
