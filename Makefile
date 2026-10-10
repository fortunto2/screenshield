.PHONY: vision test lint scan-screen
vision:
	swiftc -O vision/VisionScan.swift -o bin/visionscan
test:
	uv run pytest -q
lint:
	uv run ruff check .
scan-screen:
	uv run shield scan screen --limit 20 -v

SH ?= $(HOME)/.cargo-target/release/shield
rust:
	cd shield-rs && cargo build --release && cargo test --release
demo-live:
	mkdir -p .shield && $(SH) scan screen --record --live --work .shield -v | tee .shield/scan.jsonl
demo-live-iphone:
	mkdir -p .shield-live && $(SH) scan "cam:iPhone Camera" --record --live --work .shield-live --room room-live --min-change 3 -v | tee .shield-live/scan.jsonl
demo-redact:
	$(SH) redact .shield/recording.mp4 .shield/scan.jsonl .shield/redacted.mp4 --hold 30 && open .shield/redacted.mp4
live-page:
	cd dashboard && set -a && . ../.env && set +a && pnpm exec next dev -p 3100 -H 127.0.0.1
demo-camera:
	$(SH) scan "cam:MacBook Pro Camera" --work .shield-cam -v
demo-audit:
	$(SH) audit fixtures --work .shield-audit --dataset dataset

# Release tarball for the Homebrew formula (fortunto2/homebrew-tap, Formula/screenshield.rb)
release-tarball: vision
	cd shield-rs && cargo build --release
	rm -rf dist && mkdir -p dist/pkg && cp $(HOME)/.cargo-target/release/shield bin/visionscan README.md dist/pkg/
	cd dist/pkg && tar czf ../screenshield-$(V)-aarch64-apple-darwin.tar.gz shield visionscan README.md
	shasum -a 256 dist/screenshield-$(V)-aarch64-apple-darwin.tar.gz
