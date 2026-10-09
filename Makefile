.PHONY: vision test lint scan-screen
vision:
	swiftc -O vision/VisionScan.swift -o bin/visionscan
test:
	uv run pytest -q
lint:
	uv run ruff check .
scan-screen:
	uv run shield scan screen --limit 20 -v
