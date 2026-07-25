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
    files_deleted = []       # unlinkat target paths
    files_renamed = []       # {old_path, new_path, flags} from renameat2
    permission_changes = []  # {path, mode} from fchmodat
    process_exits = []       # {pid, comm} from exit_group
    alerts = []
    event_counts = {}

    for ev in events:
        etype = ev.get("event", "")
        event_counts[etype] = event_counts.get(etype, 0) + 1

        if etype == "execve":
            argv = ev.get("argv", "")
            if argv:
                commands.append(argv)
        elif etype == "openat":
            path = ev.get("path", "")
            if path:
                files_accessed.append(path)
        elif etype == "unlinkat":
            path = ev.get("path", "")
            if path:
                files_deleted.append(path)
        elif etype == "renameat2":
            # `path` is empty by design for renames; the endpoints live in
            # old_path/new_path. Keep them paired for summary/report consumers.
            files_renamed.append({
                "old_path": ev.get("old_path", ""),
                "new_path": ev.get("new_path", ""),
                "flags": ev.get("flags", 0),
            })
        elif etype == "fchmodat":
            permission_changes.append({
                "path": ev.get("path", ""),
                "mode": ev.get("mode", 0),
            })
        elif etype == "exit_group":
            process_exits.append({
                "pid": ev.get("pid", 0),
                "comm": ev.get("comm", ""),
            })

        if ev.get("alert"):
            alerts.append(ev)

    return {
        "total_events": len(events),
        "commands_executed": commands,
        "files_accessed": files_accessed,
        "files_deleted": files_deleted,
        "files_renamed": files_renamed,
        "permission_changes": permission_changes,
        "process_exits": process_exits,
        "event_counts": event_counts,
        "alert_count": len(alerts),
        "alerts": alerts,
    }
