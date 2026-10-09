#!/usr/bin/env bash
# Scripted 3-minute demo. Start QuickTime screen recording (⌘⇧5) first, then: bash demo/run-demo.sh
# Scenes print a title, run the real command, pause so the viewer can read. Camera scene needs the phone signs.
set -u
SH=${SH:-$HOME/.cargo-target/release/shield}
W=.shield-demo; rm -rf $W; mkdir -p $W
say() { printf "\n\033[1;36m%s\033[0m\n\n" "$1"; }
pause() { sleep "${1:-4}"; }
clear
say "ScreenShield — video is an untrusted channel. Leaks out, attacks in. Live + archive."
pause 3

say "1/5  Live leak: a work screen with a .env open. Fast loop on device, no LLM."
open -a Preview fixtures/work-screen.png; sleep 2
$SH scan screen --work $W --limit 2 -v 2>&1 | grep -v NSKVO | python3 -c "
import sys,json
for l in sys.stdin:
    if l.startswith('#'): print(l.rstrip()); continue
    r=json.loads(l); print(f\"  {r['severity']:8} {r['kind']:9} {r['rule']:24} {r['match'][:40]}  ({r['lat_ms']} ms)\")"
osascript -e 'tell application "Preview" to quit' >/dev/null 2>&1
pause 5

say "2/5  Redaction: the recording leaves with the secret already removed."
$SH scan fixtures/lecture-7s.mp4 --record --work $W-rec > $W/rec.jsonl 2>/dev/null
$SH redact $W-rec/recording.mp4 $W/rec.jsonl $W/redacted.mp4 --hold 4 2>&1 | tail -1
open $W/redacted.mp4; pause 9
osascript -e 'tell application "QuickTime Player" to close (every window whose name contains "redacted")' >/dev/null 2>&1

say "3/5  Quishing: a QR on a slide, aimed at 300 viewers."
open -a Preview fixtures/qr-slide.png; sleep 2
$SH scan screen --work $W-qr --limit 2 2>&1 | grep -v NSKVO | python3 -c "
import sys,json
for l in sys.stdin:
    if l.startswith('#') or not l.strip(): continue
    r=json.loads(l); print(f\"  {r['severity']:8} {r['kind']:9} {r['rule']:12} {r['match'][:48]}  -> {r['reason']}\")"
osascript -e 'tell application "Preview" to quit' >/dev/null 2>&1
pause 4

say "4/5  Injection to an agent: show the phone sign to the camera. Frame text is tainted; the tool call is blocked."
$SH scan "cam:MacBook Pro Camera" --work $W-cam --limit 6 2>&1 | grep -v NSKVO | python3 -c "
import sys,json
for l in sys.stdin:
    if l.startswith('#') or not l.strip(): continue
    r=json.loads(l); print(f\"  {r['severity']:8} {r['kind']:9} {r['rule']:24} {r['match'][:48]}\")"
cat $W/rec.jsonl $W-cam/findings.jsonl 2>/dev/null | grep injection | head -2 > $W/inj.jsonl
$SH respond $W/inj.jsonl --work $W 2>&1 | head -3
pause 5

say "5/5  The slow loop: the agent audits an archive and writes the dataset the fast loop learns from."
$SH audit fixtures --work $W-audit --dataset $W/dataset 2>/dev/null | head -12
pause 5
say "Policy from Senso, facts from ClickHouse, gates outside the model. MIT, on GitHub."
pause 3
