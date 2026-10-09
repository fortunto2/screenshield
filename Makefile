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
	$(SH) scan screen --record --work .shield -v | tee .shield/findings.jsonl
demo-redact:
	$(SH) redact .shield/recording.mp4 .shield/findings.jsonl .shield/redacted.mp4 --hold 30 && open .shield/redacted.mp4
demo-camera:
	$(SH) scan "cam:MacBook Pro Camera" --work .shield-cam -v
demo-audit:
	$(SH) audit fixtures --work .shield-audit --dataset dataset
