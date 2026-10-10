---
name: screenshield
description: Scan a video, a camera, a screen or a live stream for leaked secrets, PII, QR phishing and prompt injection; blur leaks before they leave; run the responder agent. Use when the user mentions a recording, a lecture capture, a demo video, a stream key, "did I leak something on screen", or wants a stream with secrets blurred.
---

# ScreenShield

One binary, `shield`, built on macOS (Apple Vision OCR on device, ffmpeg for video). No LLM in the fast path.

## Install

```bash
brew tap fortunto2/tap && brew trust fortunto2/tap && brew install screenshield   # Homebrew 7 asks to trust third-party taps
shield --help
```

From source: `git clone https://github.com/fortunto2/screenshield && cd screenshield/app && make vision && cd shield-rs && cargo build --release`.

## Commands

| Task | Command |
|---|---|
| Scan a recording or an image | `shield scan lecture.mp4 --work .shield` |
| Scan a camera / the screen live | `shield scan "cam:iPhone Camera" --live --record` / `shield scan screen --live` |
| **Stream in → stream out with leaks blurred** | `shield run --in "cam:iPhone Camera" --out rtmp://host/app/key` |
| Blur a recording from its findings | `shield redact in.mp4 .shield/findings.jsonl out.mp4` |
| Let the agent act on findings | `shield respond .shield/findings.jsonl --execute` (dry-run without `--execute`) |
| Crawl an archive (slow loop) | `shield audit ./recordings --work .shield` |
| Catch rate on fixtures | `shield eval fixtures/` |

`--in` accepts `cam:<name substring>`, `screen`, a file, or an `rtmp://` / `srt://` URL. `--out` accepts `rtmp://`, `srt://`, or a `.mp4`. The output is delayed by `--delay` (default 1 s) so a secret is pixelated before its first frame leaves. `--hold` keeps a blur 3 s after the last detection.

## Reading the output

`scan` and `run` print one JSON line per finding: `kind` (leak / pii / quishing / injection / watch), `rule` (e.g. `aws-access-key`, `env-secret`, `db-connection-string`, `device-control-verbs`), `severity`, a masked `match`, and a `box` in frame pixels. `watch/source-code` means code was on screen: it is NOT blurred, only credential lines inside it are. Everything also lands in `<work>/findings.jsonl` and, when `CLICKHOUSE_URL` is set, in ClickHouse (`frame_events`, `findings`, `tool_calls`, `reviews`).

## The agent

`shield respond` plans with sgr-agent (tool calling on any OpenAI-compatible endpoint, `AKASHML_API_KEY`; rule-based planner offline). Tools: `redact_segment`, `revoke_credential`, `block_destination`, `notify_human`, `apply_retention`, `rotate_in_repo`, `write_incident`. Every call passes the DRIFT gates (frame text is tainted and never followed; destinations must be on the allowlist). `rotate_in_repo` needs `SHIELD_REPO=<dir inside a git repo>`: it replaces the burned value with a placeholder in the same format, lists it in `COMPROMISED.md`, commits on `screenshield/incident-<ts>` and opens a PR. Main is never touched.

## When the user asks "did I leak anything?"

1. `shield scan <file> --work .shield-check` and read the JSON lines.
2. Summarise by rule and severity, with timestamps; quote only the masked matches.
3. Offer `shield redact` for the file and `shield respond --execute` if a credential rule fired.
