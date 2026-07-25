"""SysGuard policy engine — boundary / protected path / dangerous command checks."""

import os

PROTECTED_PATHS = [
    ".env", ".env.local", ".env.production",
    "config/secrets.json",
    "~/.ssh/", ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/config",
    "~/.aws/credentials", ".aws/credentials",
    "/etc/shadow", "/etc/sudoers",
]

# Destructive commands that each independently force an UNSAFE verdict. Aligned
# with the README/C canonical rules (destructive-rm, git-reset-hard,
# git-clean-force, unsafe-chmod).
#
# Deliberately NOT here:
#   curl / wget  -> downloader-exec (MEDIUM in the C engine); a standalone
#                   download is not UNSAFE on its own. It escalates only via the
#                   .env-then-transfer sequence (possible-secret-exfiltration,
#                   see detect_suspicious_sequences).
#   chown root   -> non-canonical (unsafe-chown), dropped from the C engine in
#                   TASK-A-003.
#   nc/netcat/ncat -> non-canonical (suspicious-netcat), dropped in TASK-A-003.
DANGEROUS_COMMANDS = [
    "rm -rf", "rm -r",
    "git reset --hard",
    "git clean -fd", "git clean -f",
    "chmod 777", "chmod a+rwx",
]

TARGET_PROCESSES = ["claude", "codex", "gemini", "cursor", "code"]

# Read-only system locations every process touches at startup (loader, libs,
# locale, terminfo, /proc self-inspection). Not meaningful boundary signals —
# without this allowlist every session is judged UNSAFE. Genuinely sensitive
# system files (/etc/shadow, /etc/sudoers, ~/.ssh, ...) are still caught by
# the PROTECTED_PATHS check, which runs before the boundary check.
SYSTEM_PATH_PREFIXES = [
    "/usr/", "/lib/", "/lib64/", "/opt/",
    "/proc/", "/sys/", "/dev/", "/run/",
    "/etc/ld.so", "/etc/locale", "/etc/nsswitch.conf",
    "/etc/passwd", "/etc/group", "/etc/localtime",
    "/etc/gitconfig", "/etc/gitattributes",
    "/etc/terminfo", "/etc/inputrc", "/etc/bash",
]

# Benign per-user config that tools read on every invocation (git global
# config, etc.). Matched against the path after stripping the home directory.
USER_CONFIG_SUFFIXES = [
    "/.gitconfig", "/.config/git/",
]


def is_system_path(path: str) -> bool:
    if any(path.startswith(p) for p in SYSTEM_PATH_PREFIXES):
        return True
    return any(s in path for s in USER_CONFIG_SUFFIXES)


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
    if is_system_path(path):
        return False
    return not is_inside_project(path, project_path)


def is_env_file_path(path: str) -> bool:
    """True only for dotenv-family secret files (.env, .env.local, ...).

    Deliberately narrower than is_protected_path: the exfiltration precursor is
    specifically a .env file, not SSH/AWS/shadow. `foo.env` and `.environment`
    do NOT qualify.
    """
    if not path:
        return False
    base = os.path.basename(path)
    return base == ".env" or base.startswith(".env.")


def external_transfer_tool(event: dict):
    """Return 'curl'/'wget' if this execve runs an external-transfer tool, else None.

    Matches the executable basename exactly (falling back to the first argv
    token when path is empty) so `curl-helper`, `mywget`, or a URL substring do
    not match.
    """
    if event.get("event") != "execve":
        return None
    path = event.get("path", "")
    if path:
        name = os.path.basename(path)
    else:
        # `.get("argv", "")` is not enough: an explicit JSON null returns None
        # (the default only applies when the key is absent), and None.split()
        # would raise. Normalize null the same as missing.
        tokens = (event.get("argv") or "").split()
        name = os.path.basename(tokens[0]) if tokens else ""
    return name if name in ("curl", "wget") else None


def detect_suspicious_sequences(events: list) -> list:
    """Detect '.env access then curl/wget execution' within one ordered session.

    Single forward scan: remember the first `.env` openat, then on the first
    later curl/wget execve emit exactly one CRITICAL finding and stop. Order
    matters — a transfer before any `.env` access does not trigger. No PID
    matching (the shell and the child tool have different PIDs). All state is
    local to this call, so separate sessions never share sequence state.

    Only the access *fact* is recorded — never secret contents.
    """
    env_path = None
    for ev in events:
        if env_path is None and ev.get("event") == "openat" \
                and is_env_file_path(ev.get("path", "")):
            env_path = ev.get("path", "")
            continue
        if env_path is not None:
            tool = external_transfer_tool(ev)
            if tool:
                return [{
                    "type": "suspicious_sequence",
                    "rule_id": "possible-secret-exfiltration",
                    "severity": "critical",
                    "path": env_path,
                    "tool": tool,
                    "detail": f".env access ({env_path}) followed by {tool} execution",
                }]
    return []


def classify_event(event: dict) -> dict:
    """Classify a single JSONL event and return findings.

    Events are captured at syscall *entry*, so mutation events (unlinkat,
    fchmodat) describe requested actions, not confirmed results. renameat2 and
    exit_group carry no independent safety finding here (rename is tracked as
    evidence; exit is lifecycle only).
    """
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

    if ev_type == "unlinkat" and path:
        # A deletion was requested. On its own this is a review signal, not an
        # automatic UNSAFE — see evaluate_commit_safety.
        findings.append({
            "type": "file_deletion",
            "severity": "medium",
            "detail": f"File deletion requested: {path}",
        })

    if ev_type == "fchmodat":
        try:
            mode = int(event.get("mode", 0) or 0)
        except (TypeError, ValueError):
            mode = 0
        if mode & 0o002:  # world-writable
            findings.append({
                "type": "permission_change",
                "severity": "high",
                "detail": f"World-writable permission set: {path} mode {mode & 0o7777:04o}",
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
    file_deletions = []
    unsafe_permission_changes = []
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
            elif f["type"] == "file_deletion":
                file_deletions.append(f)
            elif f["type"] == "permission_change":
                unsafe_permission_changes.append(f)

        if not result["findings"]:
            normal_activities.append(ev)

    # Ordered, session-scoped sequence detection (.env access -> curl/wget).
    suspicious_sequences = detect_suspicious_sequences(events)

    # Determine safety
    has_critical = any(
        ev.get("severity") == "critical" for ev in events if ev.get("alert")
    )
    has_env = any(".env" in f["detail"] for f in protected_accesses)
    has_ssh = any(".ssh" in f["detail"] for f in protected_accesses)
    has_shadow = any("/etc/shadow" in f["detail"] for f in protected_accesses)

    if (has_critical or has_env or has_ssh or has_shadow
            or boundary_violations or dangerous_commands
            or unsafe_permission_changes or suspicious_sequences):
        safety = "UNSAFE"
    elif file_deletions or len(all_findings) > 0:
        # A deletion (or any other non-UNSAFE finding) warrants a look but is not
        # on its own an UNSAFE verdict. Broader REVIEW_NEEDED heuristics: B-003.
        safety = "REVIEW_NEEDED"
    else:
        safety = "SAFE"

    recommendations = []
    if suspicious_sequences:
        recommendations.append(
            "Stop the commit, review the transfer command, and rotate credentials "
            "if secret exposure is possible.")
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
    if unsafe_permission_changes:
        recommendations.append("Restrict world-writable permissions to the minimum required.")
    if file_deletions:
        recommendations.append("Review deleted files. Check git status for anything unexpectedly removed.")
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
        "file_deletions": file_deletions,
        "unsafe_permission_changes": unsafe_permission_changes,
        "suspicious_sequences": suspicious_sequences,
        "recommendations": recommendations,
    }
