#!/bin/bash
# SysGuard Demo — harmless commands that trigger alerts
echo "[SysGuard Demo] Starting benign simulation..."

echo "[1] Normal: listing files"
ls /tmp > /dev/null

echo "[2] Normal: reading hostname"
hostname

echo "[3] Alert trigger: reading /etc/passwd"
cat /etc/passwd > /dev/null

echo "[4] Alert trigger: curl"
curl --version > /dev/null 2>&1

echo "[5] Alert trigger: base64"
echo "hello" | base64

echo "[6] Alert trigger: chmod"
chmod 644 /tmp/.sysguard_demo_file 2>/dev/null || true

echo "[7] Normal: echo"
echo "done"

echo "[SysGuard Demo] Simulation complete."
