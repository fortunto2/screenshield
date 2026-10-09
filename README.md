# ScreenShield — DLP for video. Video is an untrusted channel.

Cyberdefense Hackathon, SF Tech Week, 9 Oct 2026 (tokens& · AWS Builder Loft). Tracks: threat discovery + continuous defense.

Every lecture hall, boardroom and webinar records a screen. Screens show API keys, passwords, grades and e-mails
(**leaks out**). The same frames carry QR codes aimed at viewers and instruction text aimed at the AI agents that now
watch camera feeds through MCP (**attacks in**). ScreenShield watches the stream, live and across the archive, and acts.

```
stream (screen · camera · SRT/RTMP) ─► keyframes ─► OCR + QR (Apple Vision, on-device)
      ─► detectors: leaks · quishing · injection      (deterministic, outside the model)
      ─► guard: taint · approved destination · isolator (DRIFT-style gates for any agent watching the feed)
      ─► store: ClickHouse (fleet events, findings, tool calls) or JSONL
      ─► responder agent (open model on AkashML): redact · revoke · block · notify · retention · incident
```

## Try it (macOS, 2 minutes)

```bash
make vision                       # builds bin/visionscan (Swift, Apple Vision OCR + barcode)
uv sync
uv run shield eval                # OCR + detectors over fixtures/, catch rate
uv run shield scan fixtures/lecture-7s.mp4     # findings as JSON lines
uv run shield live screen --limit 20 -v        # watch your own screen, record, store
uv run shield respond .shield/findings.jsonl   # the agent decides what to do (dry-run)
uv run shield dashboard                        # http://127.0.0.1:8787
uv run shield ingest-synth --rooms 10000       # fleet-scale telemetry into ClickHouse
```

Set `CLICKHOUSE_HOST/USER/PASSWORD`, `AKASHML_API_KEY`, `SENSO_API_KEY` in `.env` to switch from local fallbacks.

## What the agent knows before it writes

- **Policy** (Senso, verified org context; `policy.json` offline): allowed QR domains, approved stream destinations,
  what counts as sensitive here. The frame can never change it.
- **Fleet facts** (ClickHouse): is this the first room showing this QR, or the 31st in 20 minutes?
- **Boundaries**: anything that would drop a live stream goes to a human first. Destinations are allowlisted.
  Text from frames is tainted: a tool argument that appeared on screen seconds earlier is blocked.

## Sponsor tools

| Tool | Where |
|---|---|
| ClickHouse | `frame_events` (one row per keyframe across the fleet), `findings`, `tool_calls`; the three fleet queries on the dashboard |
| Semgrep | Guardian on this repo while it was written; secrets patterns mirrored in `detectors.py` |
| AkashML | responder agent (gpt-oss-120b, tool calling) and vision review of flagged frames (Qwen3.8-27B) |
| Senso | the org policy document the agent reads before acting |
| Guild | hosts and traces the responder |

## Background

Chaowei Xiao (JHU / NVIDIA) at "Rethinking Agents", Stanford, 8 Oct 2026: once a device opens to third-party AI,
the video itself is an attack surface. Gates in this repo follow DRIFT (Li, Xiao et al., NeurIPS 2025): control
constraints, data provenance, injection isolation. Visual prompt injection against computer-use agents reaches
100% success in VPI-Bench (ICLR 2026); the gate therefore sits outside the model.

MIT. Built with Claude Code. No Epiphan code or data.
