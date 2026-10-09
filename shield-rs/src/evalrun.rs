//! eval: run the real OCR + detector path over a fixtures dir; `<name>.expect.json` lists must / must_not rules.
use crate::{detect, ocr};
use anyhow::Result;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Deserialize, Default)]
struct Expect { #[serde(default)] must: Vec<String>, #[serde(default)] must_not: Vec<String> }

pub fn run(fixtures: &Path, allowed: &[String]) -> Result<serde_json::Value> {
    let mut images: Vec<_> = std::fs::read_dir(fixtures)?.filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| matches!(p.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).as_deref(), Some("png" | "jpg" | "jpeg"))).collect();
    images.sort();
    let refs: Vec<&Path> = images.iter().map(|p| p.as_path()).collect();
    let results = ocr::scan_images(&refs)?;
    let (mut expected, mut caught, mut fps) = (0usize, 0usize, 0usize);
    let mut items = Vec::new();
    for (img, res) in images.iter().zip(results) {
        let got: BTreeSet<String> = detect::detect_all(&res.texts, &res.codes, allowed).iter().map(|f| f.rule.to_string()).collect();
        let side = img.with_extension("expect.json");
        let exp: Expect = std::fs::read_to_string(&side).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let must: BTreeSet<String> = exp.must.into_iter().collect();
        let must_not: BTreeSet<String> = exp.must_not.into_iter().collect();
        let missed: Vec<_> = must.difference(&got).cloned().collect();
        let fp: Vec<_> = got.intersection(&must_not).cloned().collect();
        expected += must.len(); caught += must.intersection(&got).count(); fps += fp.len();
        items.push(json!({"image": img.file_name().unwrap().to_string_lossy(), "got": got, "missed": missed, "false_positives": fp, "ocr_lines": res.texts.len(), "codes": res.codes.len()}));
    }
    let rate = if expected > 0 { Some((caught as f64 / expected as f64 * 1000.0).round() / 1000.0) } else { None };
    Ok(json!({"fixtures": items, "expected_hits": expected, "caught": caught, "false_positives": fps, "catch_rate": rate}))
}
