//! Policy: what the agent must know BEFORE it acts. Senso (verified org context) when SENSO_API_KEY is set,
//! else policy.json. The frame can never change it.
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Policy {
    #[serde(default = "d_org")] pub org: String,
    #[serde(default)] pub allowed_qr_domains: Vec<String>,
    #[serde(default)] pub approved_destinations: Vec<String>,
    #[serde(default)] pub sensitive_classes: Vec<String>,
    #[serde(skip)] pub source: String,
}
fn d_org() -> String { "demo".into() }

impl Policy {
    pub fn load() -> Policy {
        if let Ok(key) = std::env::var("SENSO_API_KEY") {
            match Self::from_senso(&key) { Ok(p) => return p, Err(e) => eprintln!("# senso policy unavailable ({e}); using policy.json") }
        }
        for c in ["policy.json", "../policy.json", "app/policy.json"] {
            if let Ok(s) = std::fs::read_to_string(c) {
                if let Ok(mut p) = serde_json::from_str::<Policy>(&s) { p.source = format!("file:{}", Path::new(c).file_name().unwrap().to_string_lossy()); return p; }
            }
        }
        Policy { source: "default".into(), ..Default::default() }
    }

    fn from_senso(key: &str) -> anyhow::Result<Policy> {
        let body = serde_json::json!({"query": "ScreenShield policy: allowed QR domains, approved stream destinations, sensitive classes"});
        let mut resp = ureq::post("https://apiv2.senso.ai/api/v1/org/search/context").header("X-API-Key", key).send_json(&body)?;
        let v: serde_json::Value = resp.body_mut().read_json()?;
        for r in v["results"].as_array().into_iter().flatten() {
            let t = r["chunk_text"].as_str().unwrap_or("");
            if let (Some(a), Some(b)) = (t.find('{'), t.rfind('}')) {
                if t.contains("approved_destinations") {
                    let mut p: Policy = serde_json::from_str(&t[a..=b])?; p.source = "senso".into(); return Ok(p);
                }
            }
        }
        anyhow::bail!("no policy document in Senso")
    }
}
