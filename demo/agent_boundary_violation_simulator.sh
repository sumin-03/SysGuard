#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(pwd)"
SANDBOX_DIR="$PROJECT_DIR/demo/sandbox_risky"
mkdir -p "$SANDBOX_DIR/build"

echo "SECRET_KEY=dummy_value" > "$SANDBOX_DIR/.env"
echo "echo test" > "$SANDBOX_DIR/test.sh"

echo "[demo] Simulate sensitive file access"
cat "$SANDBOX_DIR/.env" >/dev/null

echo "[demo] Simulate unsafe permission command"
chmod 777 "$SANDBOX_DIR/test.sh"

echo "[demo] Simulate recursive delete inside sandbox"
rm -rf "$SANDBOX_DIR/build"

echo "[demo] Simulate destructive Git command pattern"
bash -c 'echo "git reset --hard" >/dev/null'

echo "[demo] Done — expected: UNSAFE"
