#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(pwd)"
SANDBOX_DIR="$PROJECT_DIR/demo/sandbox_normal"
mkdir -p "$SANDBOX_DIR"

echo "[demo] Simulate reading project files"
cat README.md >/dev/null || true

echo "[demo] Simulate modifying a project-local file"
echo "normal update" >> "$SANDBOX_DIR/notes.txt"

echo "[demo] Simulate normal development commands"
git status >/dev/null || true
make --version >/dev/null || true
python3 --version >/dev/null || true

echo "[demo] Done — expected: SAFE or REVIEW_NEEDED"
