"""SysGuard policy engine — boundary / protected path / dangerous command checks."""

import fnmatch
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

# --- REVIEW_NEEDED heuristics (README section 7) -----------------------------
# A change set touching at least this many distinct files (per `git status
# --short`) is worth a look even without any clear violation. README gives no
# number; this is a documented project policy choice, kept in one constant.
HIGH_VOLUME_CHANGE_THRESHOLD = 20

# Build / dependency / config files whose change warrants review (not UNSAFE).
# Deliberately an explicit allowlist, not broad patterns like every *.json or
# anything under config/, to avoid false positives.
BUILD_CONFIG_BASENAMES = {
    "Makefile", "CMakeLists.txt", "package.json", "pyproject.toml",
    "setup.py", "setup.cfg", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
    "pom.xml", "gradle.properties", "Gemfile", "Gemfile.lock",
    "composer.json", "composer.lock", "Dockerfile",
}
BUILD_CONFIG_PATTERNS = [
    "requirements*.txt", "*.lock", "build.gradle", "build.gradle.kts",
    "docker-compose*.yml", "docker-compose*.yaml",
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


# Open flags that make an openat *mutating* (write/create/truncate/append) vs a
# routine read. openat's `flags` field is captured in the event.
_MUTATE_FLAG_BITS = os.O_CREAT | os.O_TRUNC | os.O_APPEND
# O_TMPFILE is a compound flag: on Linux it is (__O_TMPFILE | O_DIRECTORY), so it
# must be matched by whole-pattern equality, NOT OR-folded into the mask above —
# otherwise a routine read-only directory scan (O_RDONLY | O_DIRECTORY) would set
# the O_DIRECTORY bit and be misread as a mutation. Mirrors src/rules.c.
_O_TMPFILE = getattr(os, "O_TMPFILE", 0)


def open_flags_may_mutate(flags):
    """True if an openat with these flags can change filesystem state, False if
    it is a pure read, or None when the operation is unknown (flags absent or
    not an int — legacy records). Note O_RDONLY|O_CREAT still *creates*, so the
    create/trunc/append bits are checked, not only the access mode."""
    if flags is None:
        return None
    try:
        f = int(flags)
    except (TypeError, ValueError):
        return None
    if (f & os.O_ACCMODE) in (os.O_WRONLY, os.O_RDWR):
        return True
    if f & _MUTATE_FLAG_BITS:
        return True
    return bool(_O_TMPFILE) and (f & _O_TMPFILE) == _O_TMPFILE


def is_boundary_violation(path: str, project_path: str, flags=None) -> bool:
    """True for an open OUTSIDE the project that can MUTATE the filesystem
    (write/create/truncate/append).

    Read-only outside-project access is routine agent/runtime behaviour (its own
    install, config, caches, TLS certs, node_modules, ...) and is NOT a
    violation. Sensitive paths are handled separately by the protected-path
    rules, which the caller evaluates first. Missing/unknown flags -> not a
    violation here (surfaced as an informational unknown-operation count by
    evaluate_commit_safety).

    The system-path allowlist is deliberately NOT applied here: writing to /usr,
    /etc, /opt, /run, ... is a persistence/tampering signal, so the allowlist
    (in evaluate_commit_safety) only suppresses informational reads, never
    mutations."""
    if not path or not project_path or project_path == ".":
        return False
    if is_inside_project(path, project_path):
        return False
    return open_flags_may_mutate(flags) is True


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


def is_build_config_path(path: str) -> bool:
    """True if `path`'s basename is a build/dependency/config file worth review."""
    if not path:
        return False
    base = os.path.basename(path)
    if base in BUILD_CONFIG_BASENAMES:
        return True
    return any(fnmatch.fnmatch(base, pat) for pat in BUILD_CONFIG_PATTERNS)


def parse_git_status(status_text: str) -> list:
    """Parse `git status --short` porcelain into (status_code, path) records.

    Best-effort and defensive: tolerates the leading-space loss that
    git_summary.get_git_status() introduces via .strip(), filenames containing
    spaces, and rename/copy `old -> new` entries (path = destination). Returns
    [] for empty input or the git_summary failure placeholders (which begin with
    "(", e.g. "(git not available)") so those are treated as *unavailable
    evidence*, never as filenames.
    """
    records = []
    # Non-string (e.g. a malformed {"status": 123}), empty, or the git_summary
    # failure placeholders ("(git not available)") are all "unavailable
    # evidence" -> no findings, no raise.
    if not isinstance(status_text, str) or not status_text \
            or status_text.lstrip().startswith("("):
        return records
    for line in status_text.splitlines():
        if not line.strip():
            continue
        # Porcelain short is "XY<space>path" (XY = 2 status chars, may be space).
        # The very first line can lose its leading space(s) to an upstream
        # .strip(); fall back to splitting the status token off in that case.
        if len(line) >= 3 and line[2] == " ":
            code, path = line[:2], line[3:]
        else:
            parts = line.split(None, 1)
            code, path = (parts[0], parts[1]) if len(parts) == 2 else ("", line)
        if " -> " in path:  # rename/copy: the destination is the current path
            path = path.split(" -> ", 1)[1]
        path = path.strip().strip('"')
        if path:
            records.append((code, path))
    return records


def detect_review_signals(git_summary) -> list:
    """Derive REVIEW_NEEDED findings from a git status/diff summary.

    Signals: a high-volume change set, build/config file edits, and git-reported
    deletions. Returns structured findings (empty when git evidence is absent or
    unavailable). Never raises on malformed input.
    """
    findings = []
    status_text = (git_summary or {}).get("status", "") if isinstance(git_summary, dict) else ""
    records = parse_git_status(status_text)
    changed_paths = {path for _code, path in records}

    if len(changed_paths) >= HIGH_VOLUME_CHANGE_THRESHOLD:
        findings.append({
            "type": "high_volume_changes",
            "detail": (f"High-volume change set: {len(changed_paths)} files changed "
                       f"(>= {HIGH_VOLUME_CHANGE_THRESHOLD})."),
        })

    build_hits = sorted({path for _code, path in records if is_build_config_path(path)})
    if build_hits:
        findings.append({
            "type": "build_config_change",
            "detail": "Build/config files changed: " + ", ".join(build_hits),
        })

    deletions = sorted({path for code, path in records if "D" in code and path})
    if deletions:
        findings.append({
            "type": "sandbox_deletion",
            "detail": "Files deleted per git status: " + ", ".join(deletions),
        })

    return findings


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
        # Protected/sensitive paths are violations regardless of read/write and
        # take precedence over the boundary rule (no double finding). A
        # non-sensitive open outside the project is a violation ONLY when it can
        # mutate the filesystem — routine read-only runtime access is not.
        if is_protected_path(path):
            findings.append({
                "type": "protected_path_access",
                "severity": "high",
                "detail": f"Protected path accessed: {path}",
            })
        elif is_boundary_violation(path, project_path, event.get("flags")):
            findings.append({
                "type": "boundary_violation",
                "severity": "high",
                "detail": f"Write/create outside project boundary: {path}",
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


def evaluate_commit_safety(events: list, project_path: str = "", git_summary=None) -> dict:
    """Evaluate all events and return commit safety result.

    `git_summary` (optional, the dict from git_summary.get_git_summary) supplies
    the README section-7 REVIEW_NEEDED heuristics. When it is absent or
    unavailable the event-derived behavior is authoritative, and the call stays
    backward compatible with the two-argument form.
    """
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

    # README section-7 REVIEW_NEEDED signals from the git change summary.
    review_findings = detect_review_signals(git_summary)

    # Informational: non-sensitive outside-project opens that are NOT violations
    # (proven read-only), or whose operation is unknown (legacy records without
    # flags). Routine agent/runtime reads land here instead of flooding alerts.
    outside_read_count = 0
    outside_unknown_count = 0
    outside_read_paths = []
    _seen_read = set()
    for ev in events:
        if ev.get("event") != "openat":
            continue
        p = ev.get("path", "")
        # Establish "outside the project" by LOCATION only (do not apply the
        # system/tool-config read-noise allowlist yet — it must not hide an open
        # whose operation is still unknown and could be a write).
        if (not p or is_protected_path(p) or not project_path
                or project_path == "." or is_inside_project(p, project_path)):
            continue
        mut = open_flags_may_mutate(ev.get("flags"))
        if mut is True:
            continue  # already captured as a boundary-write finding
        if mut is None:
            # Operation unknown (legacy record): may be a write -> review signal,
            # even for system/tool-config paths.
            outside_unknown_count += 1
        elif is_system_path(p):
            continue  # proven read of a routine system path -> pure noise, drop
        else:
            outside_read_count += 1
            if p not in _seen_read and len(outside_read_paths) < 50:
                _seen_read.add(p)
                outside_read_paths.append(p)

    # Determine safety
    has_critical = any(
        ev.get("severity") == "critical" for ev in events if ev.get("alert")
    )
    has_env = any(".env" in f["detail"] for f in protected_accesses)
    has_ssh = any(".ssh" in f["detail"] for f in protected_accesses)
    has_shadow = any("/etc/shadow" in f["detail"] for f in protected_accesses)

    # Precedence: any UNSAFE condition wins; then the REVIEW_NEEDED signals
    # (outside-project writes, operation-unknown outside opens, deletions, git
    # high-volume/build-config/deletion); then SAFE. An outside-project WRITE is
    # review-worthy, not automatically unsafe; routine outside-project READS are
    # informational only. Operation-unknown outside opens (legacy flag-less
    # records) cannot be ruled out as writes, so they require review too.
    if (has_critical or has_env or has_ssh or has_shadow
            or dangerous_commands
            or unsafe_permission_changes or suspicious_sequences):
        safety = "UNSAFE"
    elif (boundary_violations or file_deletions or review_findings
            or outside_unknown_count
            or len(all_findings) > 0):
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
        recommendations.append(
            "Review attempted writes/creates outside the project; verify any "
            "cache/config/plugin changes were intended.")
    if outside_unknown_count:
        recommendations.append(
            "Some outside-project opens had no recorded operation (legacy "
            "events); review them since a write cannot be ruled out.")
    if unsafe_permission_changes:
        recommendations.append("Restrict world-writable permissions to the minimum required.")
    if file_deletions:
        recommendations.append("Review deleted files. Check git status for anything unexpectedly removed.")
    for rf in review_findings:
        if rf["type"] == "high_volume_changes":
            recommendations.append("Large change set — review the full diff and changed files before committing.")
        elif rf["type"] == "build_config_change":
            recommendations.append("Build/configuration files changed — verify the build and dependency changes are intended.")
        elif rf["type"] == "sandbox_deletion":
            recommendations.append("Files were deleted — confirm the removals are intended and recoverable via git.")
    # Only the SAFE verdict gets the reassuring message; never claim "safe to
    # commit" on a REVIEW_NEEDED/UNSAFE result with no other recommendation.
    if safety == "SAFE" and not recommendations:
        recommendations.append("No issues detected. Safe to commit.")

    return {
        "safety": safety,
        "total_events": len(events),
        "alert_count": sum(1 for e in events if e.get("alert")),
        "normal_count": len(normal_activities),
        "protected_accesses": protected_accesses,
        "boundary_violations": boundary_violations,
        "outside_project_reads": outside_read_count,
        "outside_project_read_paths": outside_read_paths,
        "outside_project_unknown_opens": outside_unknown_count,
        "dangerous_commands": dangerous_commands,
        "file_deletions": file_deletions,
        "unsafe_permission_changes": unsafe_permission_changes,
        "suspicious_sequences": suspicious_sequences,
        "review_findings": review_findings,
        "recommendations": recommendations,
    }
