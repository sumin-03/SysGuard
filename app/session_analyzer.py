"""Lightweight session analyzer — target process filtering + summary."""

import json

AGENT_COMMS = {"claude", "codex", "gemini", "cursor", "code"}


def load_events(jsonl_path: str) -> list:
    events = []
    with open(jsonl_path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return events


def filter_target_events(events: list, target_comm: str = "") -> list:
    if not target_comm:
        return events

    target_pids = set()
    filtered = []

    for ev in events:
        comm = ev.get("comm", "")
        pid = ev.get("pid", 0)
        ppid = ev.get("ppid", 0)

        is_target = (
            comm == target_comm
            or comm in AGENT_COMMS
            or pid in target_pids
            or ppid in target_pids
        )

        if is_target:
            target_pids.add(pid)
            filtered.append(ev)

    return filtered if filtered else events


def summarize_session(events: list) -> dict:
    commands = []
    files_accessed = []
    alerts = []

    for ev in events:
        if ev.get("event") == "execve":
            argv = ev.get("argv", "")
            if argv:
                commands.append(argv)
        elif ev.get("event") == "openat":
            path = ev.get("path", "")
            if path:
                files_accessed.append(path)
        if ev.get("alert"):
            alerts.append(ev)

    return {
        "total_events": len(events),
        "commands_executed": commands,
        "files_accessed": files_accessed,
        "alert_count": len(alerts),
        "alerts": alerts,
    }
