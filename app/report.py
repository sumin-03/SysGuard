#!/usr/bin/env python3
"""SysGuard Commit Safety Report — JSONL to HTML."""

import json
import html
import sys
import os
from policy import evaluate_commit_safety
from session_analyzer import load_events, filter_target_events, summarize_session
from git_summary import get_git_summary

SAFETY_COLORS = {
    "SAFE": "#28a745",
    "REVIEW_NEEDED": "#fd7e14",
    "UNSAFE": "#dc3545",
}
SEV_COLORS = {
    "critical": "#dc3545",
    "high": "#e25555",
    "medium": "#fd7e14",
    "low": "#0d6efd",
}


def format_event_detail(ev: dict) -> str:
    """Event-aware, human-readable detail for one event.

    Returns RAW text — every caller must html.escape() the result. Covers all
    six event types the C engine emits so rename/chmod/unlink/exit rows are
    never blank (renameat2 leaves `path` empty by design).
    """
    etype = ev.get("event", "")
    if etype == "execve":
        return ev.get("argv", "") or ev.get("path", "")
    if etype == "openat":
        return ev.get("path", "")
    if etype == "unlinkat":
        return f"delete: {ev.get('path', '')}"
    if etype == "renameat2":
        old = ev.get("old_path", "")
        new = ev.get("new_path", "")
        s = f"{old} → {new}"
        if ev.get("flags", 0):
            s += f" (flags {ev.get('flags')})"
        return s
    if etype == "fchmodat":
        try:
            mode = int(ev.get("mode", 0) or 0)
        except (TypeError, ValueError):
            mode = 0
        return f"{ev.get('path', '')} mode {mode & 0o7777:04o}"
    if etype == "exit_group":
        return f"pid {ev.get('pid', '')} ({ev.get('comm', '')}) exited"
    if etype == "connect":
        addr = ev.get("dest_addr", "")
        port = ev.get("dest_port", 0)
        if not addr:
            return f"connect (family {ev.get('addr_family', 0)})"
        return f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"
    return ev.get("path", "") or ev.get("argv", "") or etype


def generate_report(jsonl_path: str, target_comm: str = "", project_path: str = "") -> str:
    html_path = jsonl_path.replace(".jsonl", ".html")

    all_events = load_events(jsonl_path)
    if not all_events and not project_path:
        project_path = "."
    if not project_path:
        project_path = all_events[0].get("project_path", ".") if all_events else "."
    if not target_comm and all_events:
        target_comm = all_events[0].get("target_comm", "")

    events = filter_target_events(all_events, target_comm)
    summary = summarize_session(events)
    # Fetch the git summary before evaluating so its change set can feed the
    # REVIEW_NEEDED heuristics (README section 7).
    git = get_git_summary(project_path)
    safety = evaluate_commit_safety(events, project_path, git)

    safety_color = SAFETY_COLORS.get(safety["safety"], "#666")
    session_id = all_events[0].get("session_id", os.path.basename(jsonl_path)) if all_events else ""

    h = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SysGuard Commit Safety Report</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #333; padding: 2rem; }}
.container {{ max-width: 960px; margin: 0 auto; }}
h1 {{ color: #1a3a5c; font-size: 1.8rem; margin-bottom: 0.3rem; }}
.subtitle {{ color: #666; margin-bottom: 1.5rem; }}
.safety-badge {{ display: inline-block; padding: 0.6rem 1.5rem; border-radius: 8px;
  color: white; font-size: 1.4rem; font-weight: bold; background: {safety_color}; margin: 0.5rem 0 1rem; }}
.meta {{ background: white; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 1rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.meta td {{ padding: 0.3rem 1rem 0.3rem 0; }}
.meta .label {{ font-weight: bold; color: #555; white-space: nowrap; }}
.section {{ background: white; border-radius: 8px; padding: 1.2rem 1.5rem; margin-bottom: 1rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.section h2 {{ color: #1a3a5c; font-size: 1.1rem; margin-bottom: 0.7rem;
  border-bottom: 2px solid #e9ecef; padding-bottom: 0.4rem; }}
.section h3 {{ color: #1a3a5c; font-size: 0.95rem; margin: 0.9rem 0 0.4rem; }}
.empty {{ color: #888; font-style: italic; }}
ul {{ padding-left: 1.2rem; }}
li {{ margin-bottom: 0.3rem; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 0.5rem; }}
th, td {{ border: 1px solid #dee2e6; padding: 0.45rem 0.7rem; text-align: left; font-size: 0.82rem; }}
th {{ background: #1a3a5c; color: white; }}
tr:nth-child(even) {{ background: #f8f9fa; }}
.sev {{ font-weight: bold; padding: 2px 8px; border-radius: 4px; color: white; font-size: 0.78rem; }}
pre {{ background: #f1f3f5; padding: 0.8rem; border-radius: 6px; font-size: 0.82rem;
  overflow-x: auto; white-space: pre-wrap; }}
.footer {{ text-align: center; color: #aaa; font-size: 0.75rem; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="container">
<h1>&#128737; SysGuard Commit Safety Report</h1>
<p class="subtitle">AI Agent Boundary Auditor</p>

<div class="section meta"><h2>&#128203; Session Metadata</h2>
<table>
<tr><td class="label">Session</td><td>{html.escape(session_id)}</td></tr>
<tr><td class="label">Target Agent</td><td>{html.escape(target_comm or "(all)")}</td></tr>
<tr><td class="label">Project Path</td><td>{html.escape(project_path)}</td></tr>
<tr><td class="label">Total Events</td><td>{safety["total_events"]}</td></tr>
<tr><td class="label">Alerts</td><td>{safety["alert_count"]}</td></tr>
<tr><td class="label">Commands Executed</td><td>{len(summary["commands_executed"])}</td></tr>
<tr><td class="label">Files Accessed</td><td>{len(summary["files_accessed"])}</td></tr>
<tr><td class="label">Deleted</td><td>{len(summary["files_deleted"])}</td></tr>
<tr><td class="label">Renamed</td><td>{len(summary["files_renamed"])}</td></tr>
<tr><td class="label">Permission Changes</td><td>{len(summary["permission_changes"])}</td></tr>
<tr><td class="label">Process Exits</td><td>{len(summary["process_exits"])}</td></tr>
</table>
</div>

<div class="safety-badge">Commit Safety: {html.escape(safety["safety"])}</div>
"""

    # Normal activity
    h += '<div class="section"><h2>&#9989; Normal Development Activity</h2>\n'
    normal_cmds = [e.get("argv","") for e in events if e.get("event")=="execve" and not e.get("alert")]
    normal_files = [e.get("path","") for e in events if e.get("event")=="openat" and not e.get("alert")]
    if normal_cmds:
        h += "<ul>\n"
        for c in normal_cmds[:20]:
            h += f"  <li><code>{html.escape(c)}</code></li>\n"
        h += "</ul>\n"
    if normal_files:
        h += "<p><b>Files:</b></p><ul>\n"
        for f in normal_files[:20]:
            h += f"  <li>{html.escape(f)}</li>\n"
        h += "</ul>\n"
    # File-mutation evidence that did not raise an alert (renames, safe chmods,
    # exits, and any non-alerting deletion) — event-aware so nothing is blank.
    normal_renames = [e for e in events if e.get("event") == "renameat2" and not e.get("alert")]
    normal_chmods  = [e for e in events if e.get("event") == "fchmodat" and not e.get("alert")]
    normal_deletes = [e for e in events if e.get("event") == "unlinkat" and not e.get("alert")]
    exits          = [e for e in events if e.get("event") == "exit_group"]
    if normal_deletes:
        h += "<p><b>Deletions:</b></p><ul>\n"
        for e in normal_deletes[:20]:
            h += f"  <li>{html.escape(format_event_detail(e))}</li>\n"
        h += "</ul>\n"
    if normal_renames:
        h += "<p><b>Renames:</b></p><ul>\n"
        for e in normal_renames[:20]:
            h += f"  <li>{html.escape(format_event_detail(e))}</li>\n"
        h += "</ul>\n"
    if normal_chmods:
        h += "<p><b>Permission changes:</b></p><ul>\n"
        for e in normal_chmods[:20]:
            h += f"  <li>{html.escape(format_event_detail(e))}</li>\n"
        h += "</ul>\n"
    if exits:
        h += "<p><b>Process exits:</b></p><ul>\n"
        for e in exits[:20]:
            h += f"  <li>{html.escape(format_event_detail(e))}</li>\n"
        h += "</ul>\n"
    if not (normal_cmds or normal_files or normal_renames
            or normal_chmods or normal_deletes or exits):
        h += "<p>No normal activity recorded.</p>\n"
    h += "</div>\n"

    # 4. Boundary Violations — always rendered so the README section-9 layout is
    # stable regardless of session content.
    h += '<div class="section"><h2>&#128683; Boundary Violations</h2>\n'
    if safety["boundary_violations"]:
        h += "<ul>\n"
        for f in safety["boundary_violations"]:
            h += f'  <li>{html.escape(f["detail"])}</li>\n'
        h += "</ul>\n"
    else:
        h += '<p class="empty">No boundary violations.</p>\n'
    h += "</div>\n"

    # 5. Protected Path Access — always rendered.
    h += '<div class="section"><h2>&#128274; Protected Path Access</h2>\n'
    if safety["protected_accesses"]:
        h += "<ul>\n"
        for f in safety["protected_accesses"]:
            h += f'  <li>{html.escape(f["detail"])}</li>\n'
        h += "</ul>\n"
    else:
        h += '<p class="empty">No protected path access.</p>\n'
    h += "</div>\n"

    # 6. Dangerous Commands — always rendered.
    h += '<div class="section"><h2>&#9888;&#65039; Dangerous Commands</h2>\n'
    if safety["dangerous_commands"]:
        h += "<ul>\n"
        for f in safety["dangerous_commands"]:
            h += f'  <li>{html.escape(f["detail"])}</li>\n'
        h += "</ul>\n"
    else:
        h += '<p class="empty">No dangerous commands.</p>\n'
    h += "</div>\n"

    # 7. Git Status/Diff Summary
    h += '<div class="section"><h2>&#128204; Git Status/Diff Summary</h2>\n'
    h += f'<p><b>git status:</b></p><pre>{html.escape(git["status"] or "(clean)")}</pre>\n'
    h += f'<p><b>git diff --stat:</b></p><pre>{html.escape(git["diff_stat"] or "(no changes)")}</pre>\n'
    h += "</div>\n"

    # 8. Alert Details — the C rule-engine alert table plus the Python-derived
    # finding subsections (B-001 unsafe permission / file deletions, B-002
    # suspicious sequences, B-003 review-needed). Rendered even with no C alert,
    # since Python findings can independently support the verdict.
    alerts = [e for e in events if e.get("alert")]
    has_findings = bool(alerts or safety.get("suspicious_sequences")
                        or safety.get("unsafe_permission_changes")
                        or safety.get("file_deletions") or safety.get("review_findings"))
    h += '<div class="section"><h2>&#128680; Alert Details</h2>\n'
    if alerts:
        h += "<table>\n"
        h += "<tr><th>Severity</th><th>Rule</th><th>PID</th><th>Comm</th><th>Path/Argv</th><th>Reason</th></tr>\n"
        for a in alerts:
            sev = a.get("severity", "")
            sc = SEV_COLORS.get(sev, "#666")
            h += (f"<tr><td><span class='sev' style='background:{sc}'>{html.escape(sev)}</span></td>"
                  f"<td>{html.escape(a.get('rule_id',''))}</td>"
                  f"<td>{html.escape(str(a.get('pid','')))}</td>"
                  f"<td>{html.escape(a.get('comm',''))}</td>"
                  f"<td>{html.escape(format_event_detail(a))}</td>"
                  f"<td>{html.escape(a.get('reason',''))}</td></tr>\n")
        h += "</table>\n"
    if safety.get("suspicious_sequences"):
        h += '<h3>&#128680; Suspicious Sequences</h3><ul>\n'
        for f in safety["suspicious_sequences"]:
            sc = SEV_COLORS.get(f.get("severity", ""), "#666")
            h += (f'  <li><span class="sev" style="background:{sc}">'
                  f'{html.escape(f.get("severity", ""))}</span> '
                  f'{html.escape(f.get("rule_id", ""))} — '
                  f'{html.escape(f.get("detail", ""))} '
                  f'(tool: {html.escape(f.get("tool", ""))}, '
                  f'path: {html.escape(f.get("path", ""))})</li>\n')
        h += "</ul>\n"
    if safety.get("unsafe_permission_changes"):
        h += '<h3>&#128275; Unsafe Permission Changes</h3><ul>\n'
        for f in safety["unsafe_permission_changes"]:
            h += f'  <li>{html.escape(f["detail"])}</li>\n'
        h += "</ul>\n"
    if safety.get("file_deletions"):
        h += '<h3>&#128465;&#65039; File Deletions</h3><ul>\n'
        for f in safety["file_deletions"]:
            h += f'  <li>{html.escape(f["detail"])}</li>\n'
        h += "</ul>\n"
    if safety.get("review_findings"):
        h += '<h3>&#128269; Review Needed</h3><ul>\n'
        for f in safety["review_findings"]:
            h += f'  <li>{html.escape(f["detail"])}</li>\n'
        h += "</ul>\n"
    if not has_findings:
        h += '<p class="empty">No alerts or findings.</p>\n'
    h += "</div>\n"

    # 9. Recent Events — the last 50 filtered events, newest first, each with
    # event-aware detail so all six event types render meaningfully.
    h += '<div class="section"><h2>&#128220; Recent Events</h2>\n'
    recent = events[-50:][::-1]
    if recent:
        h += (f'<p>Showing the most recent {len(recent)} of {len(events)} '
              f'event(s), newest first.</p>\n')
        h += "<table>\n<tr><th>Event</th><th>PID</th><th>Comm</th><th>Detail</th></tr>\n"
        for e in recent:
            h += (f"<tr><td>{html.escape(e.get('event',''))}</td>"
                  f"<td>{html.escape(str(e.get('pid','')))}</td>"
                  f"<td>{html.escape(e.get('comm',''))}</td>"
                  f"<td>{html.escape(format_event_detail(e))}</td></tr>\n")
        h += "</table>\n"
    else:
        h += '<p class="empty">No events recorded.</p>\n'
    h += "</div>\n"

    # 10. Recommended Actions
    h += '<div class="section"><h2>&#128161; Recommended Actions</h2><ul>\n'
    for r in safety["recommendations"]:
        h += f"  <li>{html.escape(r)}</li>\n"
    h += "</ul></div>\n"

    h += '<p class="footer">Generated by SysGuard Commit Safety Report Engine</p>\n'
    h += "</div></body></html>"

    with open(html_path, "w") as f:
        f.write(h)
    return html_path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 report.py <session.jsonl> [--agent <name>] [--project-path <dir>]")
        sys.exit(1)

    jsonl = sys.argv[1]
    agent = ""
    proj = ""
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == "--agent" and i + 1 < len(sys.argv):
            agent = sys.argv[i + 1]; i += 2
        elif sys.argv[i] == "--project-path" and i + 1 < len(sys.argv):
            proj = sys.argv[i + 1]; i += 2
        else:
            i += 1

    path = generate_report(jsonl, agent, proj)
    print(f"Report generated: {path}")
