"""Shared test fixtures for SysGuard's Python modules."""

import json
import os


def make_event(event_type, **overrides):
    event = {
        "event": event_type,
        "pid": 100,
        "ppid": 1,
        "comm": "codex",
        "path": "",
        "project_path": "/project",
        "argv": "",
        "alert": False,
    }
    event.update(overrides)
    return event


def write_jsonl(directory, events, filename="session.jsonl"):
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as stream:
        for event in events:
            stream.write(json.dumps(event) + "\n")
    return path


def fake_git_summary():
    return {"status": " M tracked.py", "diff_stat": " tracked.py | 1 +"}


def read_text(path):
    with open(path, "r", encoding="utf-8") as stream:
        return stream.read()
