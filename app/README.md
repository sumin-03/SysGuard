# SysGuard GUI Usage

## Quick Start

```bash
# 1. Build the C engine
make

# 2. Run GUI
cd app && python3 main.py
```

## Features
- **Start Monitoring**: Launches `sysguard` engine (fake or real eBPF mode)
- **Stop**: Sends SIGINT to stop monitoring gracefully
- **Refresh Logs**: Scans `logs/` for session JSONL files
- **Open Report**: Converts selected JSONL to styled HTML and opens in browser

## Fake Mode
Check "Use fake collector" to run without root/eBPF. Generates sample events for testing.
