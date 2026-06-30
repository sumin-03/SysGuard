"""SysGuard policy engine — boundary / protected path / dangerous command checks."""

import os

PROTECTED_PATHS = [
    ".env", ".env.local", ".env.production",
    "config/secrets.json",
    "~/.ssh/", ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/config",
    "~/.aws/credentials", ".aws/credentials",
    "/etc/shadow", "/etc/sudoers",
]

DANGEROUS_COMMANDS = [
    "rm -rf", "rm -r",
    "git reset --hard",
    "git clean -fd", "git clean -f",
    "chmod 777", "chmod a+rwx",
    "chown root",
    "curl", "wget",
    "nc", "netcat", "ncat",
]

TARGET_PROCESSES = ["claude", "codex", "gemini", "cursor", "code"]


def is_protected_path(path: str) -> bool:
    if not path:
        return False
    for p in PROTECTED_PATHS:
        if p in path:
            return True
    return False


def is_dangerous_command(argv: str) -> bool:
    if not argv:
        return False
    for cmd in DANGEROUS_COMMANDS:
        if cmd in argv:
            return True
    return False


def is_inside_project(path: str, project_path: str) -> bool:
    if not path or not project_path:
        return True
    try:
        rp = os.path.realpath(path)
        pp = os.path.realpath(project_path)
        return rp.startswith(pp + "/") or rp == pp
    except Exception:
        return path.startswith(project_path)


def is_boundary_violation(path: str, project_path: str) -> bool:
    if not path or not project_path or project_path == ".":
        return False
    return not is_inside_project(path, project_path)


def classify_event(event: dict) -> dict:
    """Classify a single JSONL event and return findings."""
    findings = []
    path = event.get("path", "")
    argv = event.get("argv", "")
    project_path = event.get("project_path", "")
    ev_type = event.get("event", "")

    if ev_type == "openat" and path:
        if is_protected_path(path):
            findings.append({
                "type": "protected_path_access",
                "severity": "high",
                "detail": f"Protected path accessed: {path}",
            })
        if is_boundary_violation(path, project_path):
            findings.append({
                "type": "boundary_violation",
                "severity": "high",
                "detail": f"Access outside project boundary: {path}",
            })

    if ev_type == "execve" and argv:
        if is_dangerous_command(argv):
            findings.append({
                "type": "dangerous_command",
                "severity": "high",
                "detail": f"Dangerous command: {argv}",
            })

    return {
        "event": event,
        "findings": findings,
    }


def evaluate_commit_safety(events: list, project_path: str = "") -> dict:
    """Evaluate all events and return commit safety result."""
    all_findings = []
    protected_accesses = []
    boundary_violations = []
    dangerous_commands = []
    normal_activities = []

    for ev in events:
        result = classify_event(ev)
        for f in result["findings"]:
            all_findings.append(f)
            if f["type"] == "protected_path_access":
                protected_accesses.append(f)
            elif f["type"] == "boundary_violation":
                boundary_violations.append(f)
            elif f["type"] == "dangerous_command":
                dangerous_commands.append(f)

        if not result["findings"]:
            normal_activities.append(ev)

    # Determine safety
    has_critical = any(
        ev.get("severity") == "critical" for ev in events if ev.get("alert")
    )
    has_env = any(".env" in f["detail"] for f in protected_accesses)
    has_ssh = any(".ssh" in f["detail"] for f in protected_accesses)
    has_shadow = any("/etc/shadow" in f["detail"] for f in protected_accesses)

    if has_critical or has_env or has_ssh or has_shadow or boundary_violations or dangerous_commands:
        safety = "UNSAFE"
    elif len(all_findings) > 0:
        safety = "REVIEW_NEEDED"
    else:
        safety = "SAFE"

    recommendations = []
    if has_env:
        recommendations.append("Review whether .env secrets were exposed. Rotate API keys if needed.")
    if has_ssh:
        recommendations.append("Check whether SSH credentials were compromised.")
    if has_shadow:
        recommendations.append("Verify /etc/shadow access authorization.")
    if dangerous_commands:
        recommendations.append("Review git reflog and verify destructive commands were intentional.")
    if boundary_violations:
        recommendations.append("Investigate file access outside project boundary.")
    if not recommendations:
        recommendations.append("No issues detected. Safe to commit.")

    return {
        "safety": safety,
        "total_events": len(events),
        "alert_count": sum(1 for e in events if e.get("alert")),
        "normal_count": len(normal_activities),
        "protected_accesses": protected_accesses,
        "boundary_violations": boundary_violations,
        "dangerous_commands": dangerous_commands,
        "recommendations": recommendations,
    }
