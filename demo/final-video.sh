#!/usr/bin/env bash
# Final video = motion explainer (45 s) + screencast. Usage: bash demo/final-video.sh <screencast.mov> [out.mp4]
set -eu
INTRO="$HOME/Downloads/screenshield-video-is-an-untrusted-channel.mp4"
CAST="$1"; OUT="${2:-$HOME/Downloads/screenshield-demo-final.mp4}"
T=$(mktemp -d)
ffmpeg -hide_banner -loglevel error -y -i "$INTRO" -vf "scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,fps=30" -c:v libx264 -preset veryfast -crf 20 -an "$T/a.mp4"
ffmpeg -hide_banner -loglevel error -y -i "$CAST" -vf "scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,fps=30" -c:v libx264 -preset veryfast -crf 20 -c:a aac -ar 48000 "$T/b.mp4"
# give the intro a silent track so concat keeps audio
ffmpeg -hide_banner -loglevel error -y -f lavfi -i anullsrc=r=48000:cl=stereo -i "$T/a.mp4" -shortest -c:v copy -c:a aac "$T/a2.mp4"
printf "file '%s'\nfile '%s'\n" "$T/a2.mp4" "$T/b.mp4" > "$T/list.txt"
ffmpeg -hide_banner -loglevel error -y -f concat -safe 0 -i "$T/list.txt" -c copy "$OUT"
echo "final: $OUT ($(ffprobe -v error -show_entries format=duration -of csv=p=0 "$OUT") s)"
