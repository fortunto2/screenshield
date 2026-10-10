//! Repo remediation. A credential that was shown on a recorded screen is burned: the responder rotates it in the
//! repository (new placeholder value in the same format), records it in COMPROMISED.md, and commits on a separate
//! branch through a git worktree, so the developer's checkout and main stay untouched. Pushing the branch and
//! opening a PR are best effort with a timeout: the live loop must never hang on the network.
use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Rotation { pub file: PathBuf, pub line: usize, pub old_masked: String, pub new_masked: String }

fn stamp() -> String { chrono::Utc::now().format("%Y%m%d%H%M%S").to_string() }

/// New value in the same shape as the old one; "ROTATED" + timestamp so a reader sees it is a placeholder.
fn new_value(rule: &str, old: &str) -> String {
    let ts = stamp();
    let fill = |prefix: &str, n: usize, upper: bool| {
        let mut body = format!("ROTATED{ts}");
        while body.len() < n { body.push('0'); }
        body.truncate(n);
        format!("{prefix}{}", if upper { body.to_uppercase() } else { body })
    };
    match rule {
        "aws-access-key" => fill("AKIA", 16, true),
        "github-token" => fill("ghp_", 36, false),
        "stripe-live-key" => fill("sk_live_", 24, false),
        "openai-key" => fill("sk-proj-", 32, false),
        "anthropic-key" => fill("sk-ant-", 32, false),
        "google-api-key" => fill("AIza", 35, false),
        "slack-token" => fill("xoxb-", 24, false),
        "db-connection-string" => {
            // keep scheme, user and host; only the password changes
            let re = regex::Regex::new(r"^(\w+(?:\+srv)?://[^:/]+:)([^@]+)(@.*)$").unwrap();
            re.replace(old, |c: &regex::Captures| format!("{}ROTATED{ts}{}", &c[1], &c[3])).into_owned()
        }
        "env-secret" | "password-assignment" => {
            let re = regex::Regex::new(r"^(.*?[:=]\s*)(\S+)$").unwrap();
            re.replace(old, |c: &regex::Captures| format!("{}ROTATED{ts}", &c[1])).into_owned()
        }
        _ => format!("<ROTATED-{ts}>"),
    }
}

pub fn mask(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 { return "*".repeat(n); }
    format!("{}{}{}", s.chars().take(4).collect::<String>(), "*".repeat(n.saturating_sub(8).min(12)), s.chars().skip(n - 4).collect::<String>())
}

fn run(dir: &Path, args: &[&str], secs: u64) -> Result<String> {
    let (prog, rest) = args.split_first().unwrap();
    let mut child = Command::new(prog).args(rest).current_dir(dir).stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null()).spawn().with_context(|| format!("spawn {prog}"))?;
    let t0 = Instant::now();
    loop {
        if child.try_wait()?.is_some() { break; }
        if t0.elapsed() > Duration::from_secs(secs) { let _ = child.kill(); return Err(anyhow!("{prog} timed out after {secs}s")); }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() { return Err(anyhow!("{prog} {}: {}", rest.join(" "), String::from_utf8_lossy(&out.stderr).trim())); }
    Ok(text)
}

fn text_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() { if !(name == ".git" || name == "node_modules" || name == "target" || name.starts_with(".shield")) { text_files(&p, out); } }
        else if p.metadata().map(|m| m.len() < 1_000_000).unwrap_or(false) { out.push(p); }
    }
}

fn open_incident_for(root: &Path, rule: &str) -> Option<String> {
    let list = run(root, &["git", "for-each-ref", "--format=%(refname:short) %(subject)", "refs/heads/screenshield/"], 10).ok()?;
    let needle = format!("rotate {rule} ");
    for line in list.lines().rev() {
        let (name, subject) = line.split_once(' ')?;
        if !subject.contains(&needle) { continue; }
        // merged already → main has the rotation, a new incident would be legitimate again
        let merged = Command::new("git").args(["merge-base", "--is-ancestor", name, "HEAD"]).current_dir(root).status().map(|s| s.success()).unwrap_or(false);
        if !merged { return Some(name.to_string()); }
    }
    None
}

/// Rotate every occurrence of `rule` under `scope` (a directory inside a git repo). Returns what changed.
/// dry_run: report the matches, touch nothing.
pub fn rotate(scope: &Path, rule: &str, room: &str, dry_run: bool) -> Result<Value> {
    let re = crate::detect::secret_regex(rule).ok_or_else(|| anyhow!("no secret rule named {rule}"))?;
    let scope = scope.canonicalize().with_context(|| format!("repo scope {}", scope.display()))?;
    let root = PathBuf::from(run(&scope, &["git", "rev-parse", "--show-toplevel"], 10)?);
    let rel = scope.strip_prefix(&root).unwrap_or(Path::new("")).to_path_buf();
    // one open incident per rule: a branch that already rotates this rule and is not merged yet is reused
    if let Some(existing) = open_incident_for(&root, rule) {
        let pr = run(&root, &["gh", "pr", "list", "--head", &existing, "--json", "url", "--jq", ".[0].url"], 15).unwrap_or_default();
        return Ok(json!({"rule": rule, "rotated": 0, "branch": existing, "pr": pr, "note": "already rotated on an open incident branch; nothing new to commit"}));
    }
    let ts = stamp();
    let incident = format!("SS-{ts}");
    let branch = format!("screenshield/incident-{ts}");

    // work in a throwaway worktree so the developer's checkout and main are never touched
    let wt = std::env::temp_dir().join(format!("shield-wt-{ts}"));
    let edit_root = if dry_run { root.clone() } else {
        run(&root, &["git", "worktree", "add", "-b", &branch, wt.to_str().unwrap(), "HEAD"], 20)?;
        wt.clone()
    };
    let mut files = Vec::new();
    text_files(&edit_root.join(&rel), &mut files);
    let mut rotations: Vec<Rotation> = Vec::new();
    for f in &files {
        let Ok(src) = std::fs::read_to_string(f) else { continue };
        if !re.is_match(&src) { continue; }
        let mut out = String::with_capacity(src.len());
        for (i, line) in src.lines().enumerate() {
            if let Some(m) = re.find(line) {
                let nv = new_value(rule, m.as_str());
                rotations.push(Rotation { file: f.strip_prefix(&edit_root).unwrap_or(f).to_path_buf(), line: i + 1, old_masked: mask(m.as_str()), new_masked: mask(&nv) });
                out.push_str(&line[..m.start()]); out.push_str(&nv); out.push_str(&line[m.end()..]);
            } else { out.push_str(line); }
            out.push('\n');
        }
        if !dry_run { std::fs::write(f, out)?; }
    }
    if rotations.is_empty() {
        if !dry_run { let _ = run(&root, &["git", "worktree", "remove", "--force", wt.to_str().unwrap()], 10); let _ = run(&root, &["git", "branch", "-D", &branch], 10); }
        return Ok(json!({"rule": rule, "rotated": 0, "note": "no occurrence in the repo scope"}));
    }
    let listed: Vec<Value> = rotations.iter().map(|r| json!({"file": r.file.display().to_string(), "line": r.line, "old": r.old_masked, "new": r.new_masked})).collect();
    if dry_run { return Ok(json!({"rule": rule, "incident": incident, "rotated": rotations.len(), "changes": listed, "note": "dry-run; pass --execute to commit"})); }

    // COMPROMISED.md: the burned credentials, so the old values get revoked at the provider
    let md = edit_root.join("COMPROMISED.md");
    let mut body = if md.exists() { std::fs::read_to_string(&md)? } else { "# Compromised credentials\n\nWritten by the ScreenShield responder when a credential was shown on a recorded screen. The old value is burned: revoke it at the provider. The new value is a placeholder in the same format; fill in the real one from your secret manager.\n\n| when (UTC) | incident | rule | file:line | old (masked) | new (masked) | status |\n|---|---|---|---|---|---|---|\n".to_string() };
    let when = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    for r in &rotations { body.push_str(&format!("| {when} | {incident} | {rule} | {}:{} | `{}` | `{}` | rotated in repo, revoke at provider, seen in {room} |\n", r.file.display(), r.line, r.old_masked, r.new_masked)); }
    std::fs::write(&md, body)?;

    let title = format!("ScreenShield {incident}: rotate {rule} shown on screen in {room}");
    run(&wt, &["git", "add", "-A"], 10)?;
    run(&wt, &["git", "-c", "user.name=ScreenShield responder", "-c", "user.email=responder@screenshield.local", "commit", "-q", "-m",
        &format!("{title}\n\n{} occurrence(s) replaced with a placeholder in the same format; COMPROMISED.md lists the burned values.\nThe old credential must be revoked at the provider. Generated by the responder agent, no human reviewed this yet.", rotations.len())], 15)?;
    let commit = run(&wt, &["git", "rev-parse", "--short", "HEAD"], 10)?;
    let push = run(&root, &["git", "push", "-q", "-u", "origin", &branch], 25).map(|_| "pushed".to_string()).unwrap_or_else(|e| format!("push skipped: {e}"));
    let pr = if push == "pushed" {
        run(&root, &["gh", "pr", "create", "--head", &branch, "--title", &title, "--body", &format!("Opened by the ScreenShield responder agent.\n\nA `{rule}` credential was visible on a recorded screen ({room}). The value is burned, so this PR:\n\n- replaces every occurrence under `{}` with a placeholder in the same format\n- adds the burned values (masked) to `COMPROMISED.md`\n\n**Revoke the old credential at the provider before merging.**", rel.display())], 25).unwrap_or_else(|e| format!("pr skipped: {e}"))
    } else { "pr skipped: not pushed".into() };
    let _ = run(&root, &["git", "worktree", "remove", "--force", wt.to_str().unwrap()], 10);
    Ok(json!({"rule": rule, "incident": incident, "rotated": rotations.len(), "changes": listed, "branch": branch, "commit": commit, "push": push, "pr": pr}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_values_keep_the_shape() {
        assert!(regex::Regex::new(r"^AKIA[0-9A-Z]{16}$").unwrap().is_match(&new_value("aws-access-key", "AKIAIOSFODNN7EXAMPLE")));
        let db = new_value("db-connection-string", "postgres://billing:Sup3r!@db.internal:5432/prod");
        assert!(db.starts_with("postgres://billing:ROTATED") && db.ends_with("@db.internal:5432/prod"));
        assert!(new_value("env-secret", "SMTP_PASSWORD = mailRelay2026!").starts_with("SMTP_PASSWORD = ROTATED"));
        assert_eq!(mask("AKIAIOSFODNN7EXAMPLE"), "AKIA************MPLE");
    }
    #[test]
    fn dry_run_finds_the_demo_keys_without_touching_them() {
        let scope = Path::new(env!("CARGO_MANIFEST_DIR")).join("../demo/fake-secrets");
        if !scope.exists() { return; }
        let before = std::fs::read_to_string(scope.join("payments.py")).unwrap();
        let v = rotate(&scope, "aws-access-key", "room-test", true).unwrap();
        assert!(v["rotated"].as_u64().unwrap_or(0) >= 1, "{v}");
        assert_eq!(std::fs::read_to_string(scope.join("payments.py")).unwrap(), before);
    }
}
