"""SysGuard policy engine — boundary / protected path / dangerous command checks."""

import fnmatch
import os
import re

PROTECTED_PATHS = [
    ".env", ".env.local", ".env.production",
    "config/secrets.json",
    "~/.ssh/", ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/config",
    "~/.aws/credentials", ".aws/credentials",
    "/etc/shadow", "/etc/sudoers",
]

# --- TASK-B-012: operation classified by EFFECT, not just location ------------
# An AI agent and its toolchain write their own runtime bookkeeping (session
# state, npm/IDE caches and logs, atomic config temp files) on every run,
# regardless of the task. Those writes are NOT a security signal. But genuinely
# dangerous writes — persistence/activation, credentials, system tampering — are
# escalated. Three buckets for outside/at-boundary WRITES:
#   runtime-noise  -> informational (narrowly recognized bookkeeping)
#   persistence    -> UNSAFE (persistence-sensitive-write)
#   everything else-> REVIEW_NEEDED (outside-project-write)
# All matches are exact / prefix / component-aware — never a broad substring
# like "/.cache/" — so a writable runtime dir cannot become a hiding place.

# Runtime bookkeeping writes, matched RELATIVE to the monitored user's home.
# NOTE (documented limitation, TASK-B-012 Phase 1): `.claude/session-env/` holds
# scripts that can be sourced and `.claude/plugins/cache/` holds executable
# plugin content; exempting them by path alone is a known cache-poisoning /
# session-script false-negative tradeoff, accepted here to keep routine sessions
# readable. A hardened profile would require session-created roots + integrity.
RUNTIME_NOISE_HOME_PREFIXES = (
    ".claude/projects/", ".claude/sessions/", ".claude/backups/",
    ".claude/session-env/", ".claude/plugins/cache/",
    ".npm/_cacache/", ".npm/_logs/",
    ".cache/claude-cli-nodejs/", ".config/Code/logs/",
    ".claude/shell-snapshots/",
)
RUNTIME_NOISE_HOME_EXACT = (".claude/history.jsonl",)
# No-op sinks and the exact kernel tracing markers (never all of /dev|/proc|/sys).
RUNTIME_NOISE_ABS_EXACT = (
    "/dev/null", "/dev/tty",
    "/sys/kernel/debug/tracing/trace_marker",
    "/sys/kernel/tracing/trace_marker",
)
# Agent scratch under /tmp. Deliberately NOT all of /tmp (which is arbitrary
# staging ground): only the agent's own uid-scoped run directory and its cwd
# marker files. The numeric component must EQUAL the writing process's uid, so
# "/tmp/claude-9999/payload" written by uid 1000 is not exempt — otherwise any
# monitored process could hide writes behind a predictable directory name.
# Writing to /tmp is not itself persistence or credential access: those are
# caught by their own rules regardless of location, and a staged file renamed
# onto a protected/persistence target is caught by the rename rule.
_TMP_AGENT_DIR_RE = re.compile(r"^/tmp/claude-([0-9]+)/")
_TMP_AGENT_CWD_RE = re.compile(r"^/tmp/claude-[0-9a-f]{4,16}-cwd$")
# Atomic config staging file directly under home: .claude.json.tmp.<pid>.<hex>.
_CLAUDE_JSON_TMP_RE = re.compile(r"^\.claude\.json\.tmp\.[0-9]+\.[0-9A-Fa-f]+$")

# Persistence / activation targets: a MUTATION here is UNSAFE (reads are fine —
# shells read .bashrc constantly). Home-relative unless absolute.
PERSIST_HOME_EXACT = (
    ".bashrc", ".bash_profile", ".profile",
    ".zshrc", ".zprofile", ".zlogin", ".zshenv",
    ".gitconfig", ".config/git/config",
    ".claude.json", ".claude/settings.json", ".claude/settings.local.json",
    ".ssh/authorized_keys", ".ssh/authorized_keys2",
)
PERSIST_HOME_PREFIXES = (
    ".config/autostart/", ".config/systemd/user/",
    ".local/share/systemd/user/", ".config/environment.d/",
)
PERSIST_ABS_EXACT = (
    "/etc/crontab", "/etc/profile", "/etc/bash.bashrc",
    "/etc/ld.so.preload", "/etc/ld.so.conf",
)
PERSIST_ABS_PREFIXES = (
    "/etc/cron.d/", "/var/spool/cron/",
    "/etc/systemd/system/", "/run/systemd/system/",
    "/usr/lib/systemd/system/", "/lib/systemd/system/",
    "/etc/profile.d/", "/etc/zsh/", "/etc/ld.so.conf.d/",
)

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


def resolve_monitored_home(events: list):
    """Return the monitored agent's home directory, or None (fail-closed).

    The home RECORDED BY THE COLLECTOR (the `home_path` JSONL field) wins, so the
    report classifies writes exactly as the live C engine did — including when
    the run used an explicit --home-path. Only when no record carries one is it
    re-derived from the dominant non-root uid via the passwd database — i.e. the
    MONITORED user's home, never the report process's $HOME (which may be root
    under sudo). Returns None when the only activity is root's, when no uid is
    present, or when the lookup fails; callers then disable all home-relative
    exemptions and keep the conservative verdict.
    """
    # The collector's decision is authoritative whenever it recorded one — including
    # an EMPTY value, which means it deliberately failed closed (e.g. running as
    # bare root). Re-deriving from uid in that case would be more permissive than
    # the live engine and could downgrade the verdict, so only records that lack
    # the field entirely (legacy logs) fall through to uid resolution.
    for ev in events:
        if "home_path" in ev:
            recorded = ev.get("home_path")
            if (isinstance(recorded, str) and recorded.startswith("/")
                    and recorded.rstrip("/")):
                return recorded.rstrip("/")
            return None

    from collections import Counter
    uids = Counter()
    for ev in events:
        u = ev.get("uid")
        if isinstance(u, int) and u > 0:
            uids[u] += 1
    if not uids:
        return None
    uid = uids.most_common(1)[0][0]
    try:
        import pwd
        home = pwd.getpwuid(uid).pw_dir
    except Exception:  # fail closed on any lookup error
        return None
    if not home or home == "/" or not home.startswith("/"):
        return None
    return home.rstrip("/")


def _has_dot_segment(path: str) -> bool:
    """True if any path component is '.' or '..' — i.e. a lexical prefix match
    cannot be trusted to describe the real target."""
    return any(part in (".", "..") for part in path.split("/"))


def _home_rel(path: str, home_path):
    """Path relative to the monitored home ('.bashrc'), or None if not under it."""
    if not path or not home_path:
        return None
    prefix = home_path.rstrip("/") + "/"
    if path.startswith(prefix):
        return path[len(prefix):]
    return None


def _tmp_path_is_redirected(path: str) -> bool:
    """Best-effort check that an agent-scratch path under /tmp still resolves to
    itself; True when a symlink component currently points somewhere else.

    This is DEFENCE IN DEPTH, not a guarantee. The report runs after the session,
    so a link created and removed during the run resolves to itself here and the
    exemption is granted. Symlink redirection is a systemic limitation of every
    lexical exemption in this policy (`~/.claude/projects/x` linked at `~/.bashrc`
    behaves the same way), not something specific to /tmp — see README §6. The
    sound fix is to record collector-resolved targets at event time (TASK-A-014).
    """
    try:
        return os.path.realpath(path) != path
    except (OSError, ValueError):
        return True    # cannot verify -> fail closed


def is_runtime_noise_write(path: str, home_path, uid=None) -> bool:
    """True for a narrowly recognized agent/toolchain bookkeeping write that is
    informational, not a violation. Never a broad substring match.

    `uid` is the writing process's uid, required to accept its own uid-scoped
    /tmp run directory; without it that exemption is refused (fail closed)."""
    if not path:
        return False
    # Traversal defeats lexical prefix matching: ".claude/projects/../../.bashrc"
    # starts with an exempt prefix but resolves elsewhere. Never grant an
    # exemption to a path we cannot read literally (fail closed -> stays a
    # reportable outside-project write).
    if _has_dot_segment(path):
        return False
    if path in RUNTIME_NOISE_ABS_EXACT:
        return True
    m = _TMP_AGENT_DIR_RE.match(path)
    if m:
        # Only the writer's OWN uid-scoped directory, never an arbitrary number.
        # Canonical spelling only: "/tmp/claude-00001000/" is an attacker-chosen
        # directory, not the agent's actual runtime dir. Bounded to 10 digits so
        # the C engine (32-bit uid_t, no bignums) rejects exactly the same set.
        digits = m.group(1)
        if len(digits) > 10 or digits.startswith("0"):
            return False
        try:
            if not (uid is not None and int(digits) == int(uid) <= 0xFFFFFFFF):
                return False
        except (TypeError, ValueError):
            return False
        return not _tmp_path_is_redirected(path)
    if _TMP_AGENT_CWD_RE.match(path):
        return not _tmp_path_is_redirected(path)
    rel = _home_rel(path, home_path)
    if rel is None:
        return False
    if rel in RUNTIME_NOISE_HOME_EXACT:
        return True
    if "/" not in rel and _CLAUDE_JSON_TMP_RE.match(rel):
        return True
    return any(rel.startswith(pfx) for pfx in RUNTIME_NOISE_HOME_PREFIXES)


def is_persistence_sensitive(path: str, home_path) -> bool:
    """True when a MUTATION of this path is a persistence/activation risk
    (shell rc, ssh authorized_keys, cron, systemd units, autostart, git hooks,
    live agent config, ld.so preload). Callers must gate on mutation; reads of
    these paths are ordinary."""
    if not path:
        return False
    # Collapse "." / ".." lexically so traversal cannot evade DETECTION either
    # (".claude/projects/../../.bashrc" must still be seen as ~/.bashrc).
    if _has_dot_segment(path):
        path = os.path.normpath(path)
    if path in PERSIST_ABS_EXACT:
        return True
    if any(path.startswith(p) for p in PERSIST_ABS_PREFIXES):
        return True
    # Component-aware git-hooks match (a real ".git/hooks/" path component).
    if "/.git/hooks/" in path:
        return True
    rel = _home_rel(path, home_path)
    if rel is None:
        return False
    if rel in PERSIST_HOME_EXACT:
        return True
    return any(rel.startswith(p) for p in PERSIST_HOME_PREFIXES)


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


def classify_event(event: dict, home_path=None) -> dict:
    """Classify a single JSONL event and return findings.

    Events are captured at syscall *entry*, so mutation events (unlinkat,
    fchmodat) describe requested actions, not confirmed results. `home_path` is
    the monitored user's home for home-relative persistence/runtime-noise
    matching; when None those matches are disabled (fail-closed).
    """
    findings = []
    path = event.get("path", "")
    argv = event.get("argv", "")
    project_path = event.get("project_path", "")
    ev_type = event.get("event", "")

    if ev_type == "openat" and path:
        # Effect-ordered classification (TASK-B-012):
        #   1. protected/sensitive  -> read or write, UNSAFE
        #   2. persistence-sensitive -> MUTATION only, UNSAFE
        #   3. mutation outside project -> runtime-noise? informational : REVIEW
        # Each path yields at most one finding (first match wins).
        mutates = open_flags_may_mutate(event.get("flags")) is True
        if is_protected_path(path):
            findings.append({
                "type": "protected_path_access",
                "severity": "high",
                "detail": f"Protected path accessed: {path}",
            })
        elif mutates and is_persistence_sensitive(path, home_path):
            findings.append({
                "type": "persistence_sensitive_write",
                "severity": "critical",
                "detail": f"Write to persistence/activation target: {path}",
            })
        elif is_boundary_violation(path, project_path, event.get("flags")):
            if is_runtime_noise_write(path, home_path, event.get("uid")):
                findings.append({
                    "type": "runtime_noise_write",
                    "severity": "info",
                    "detail": f"Runtime bookkeeping write: {path}",
                })
            else:
                findings.append({
                    "type": "boundary_violation",
                    "severity": "high",
                    "detail": f"Write/create outside project boundary: {path}",
                })

    # A rename is classified by its DESTINATION, with the same precedence as an
    # open: protected first, then persistence. Otherwise a file staged in an
    # exempt runtime directory could be renamed onto .env / ~/.aws/credentials /
    # ~/.claude.json and never be reported.
    if ev_type == "renameat2":
        dest = event.get("new_path", "") or ""
        if dest and is_protected_path(dest):
            findings.append({
                "type": "protected_path_access",
                "severity": "high",
                "detail": f"Protected path replaced by rename: {dest}",
            })
        elif dest and is_persistence_sensitive(dest, home_path):
            findings.append({
                "type": "persistence_sensitive_write",
                "severity": "critical",
                "detail": f"Rename onto persistence/activation target: {dest}",
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


def evaluate_commit_safety(events: list, project_path: str = "", git_summary=None,
                           home_path=None) -> dict:
    """Evaluate all events and return commit safety result.

    `git_summary` (optional, the dict from git_summary.get_git_summary) supplies
    the README section-7 REVIEW_NEEDED heuristics. When it is absent or
    unavailable the event-derived behavior is authoritative, and the call stays
    backward compatible with the two-argument form.

    `home_path` is the monitored user's home for home-relative persistence /
    runtime-noise matching (TASK-B-012). When omitted it is resolved from the
    session's dominant non-root uid; if it cannot be resolved, home-relative
    exemptions are disabled (fail-closed) and such writes stay REVIEW_NEEDED.
    """
    if home_path is None:
        home_path = resolve_monitored_home(events)

    all_findings = []
    protected_accesses = []
    persistence_writes = []
    boundary_violations = []
    runtime_noise_writes = []
    dangerous_commands = []
    file_deletions = []
    unsafe_permission_changes = []
    normal_activities = []

    for ev in events:
        result = classify_event(ev, home_path)
        for f in result["findings"]:
            all_findings.append(f)
            if f["type"] == "protected_path_access":
                protected_accesses.append(f)
            elif f["type"] == "persistence_sensitive_write":
                persistence_writes.append(f)
            elif f["type"] == "boundary_violation":
                boundary_violations.append(f)
            elif f["type"] == "runtime_noise_write":
                runtime_noise_writes.append(f)
            elif f["type"] == "dangerous_command":
                dangerous_commands.append(f)
            elif f["type"] == "file_deletion":
                file_deletions.append(f)
            elif f["type"] == "permission_change":
                unsafe_permission_changes.append(f)

        # A runtime-noise write carries a finding, so it is not counted as clean
        # "normal development" activity, and it lives only in its own
        # informational bucket — it never reaches the verdict below.
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

    # Precedence: any UNSAFE condition wins; then the REVIEW_NEEDED signals;
    # then SAFE.
    #   UNSAFE  = ANY protected-path access (read or write — all of them, not
    #             just env/ssh/shadow), any persistence/activation mutation, a
    #             destructive command, a world-writable chmod, or a secret-
    #             exfiltration sequence.
    #   REVIEW  = an ordinary outside-project WRITE, an operation-unknown outside
    #             open (a write cannot be ruled out), a deletion, or a git
    #             high-volume/build-config/deletion signal.
    #   SAFE    = none of the above. Routine outside-project READS and narrowly
    #             recognized runtime-bookkeeping WRITES are informational only.
    if (has_critical or protected_accesses or persistence_writes
            or dangerous_commands
            or unsafe_permission_changes or suspicious_sequences):
        safety = "UNSAFE"
    elif (boundary_violations or file_deletions or review_findings
            or outside_unknown_count):
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
    if protected_accesses and not (has_env or has_ssh or has_shadow):
        # Every protected path forces UNSAFE, so the remaining ones (AWS
        # credentials, sudoers, secrets.json, ...) must explain themselves too.
        recommendations.append(
            "A protected path was accessed. Verify the access was authorized and "
            "rotate the affected credentials if exposure is possible.")
    if persistence_writes:
        recommendations.append(
            "A write targeted a persistence/activation location (shell startup, "
            "cron, systemd, autostart, git hooks, or live agent config). Verify "
            "it was intended and inspect the target for injected commands.")
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
        "persistence_writes": persistence_writes,
        "boundary_violations": boundary_violations,
        "runtime_noise_writes": runtime_noise_writes,
        "monitored_home": home_path,
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
