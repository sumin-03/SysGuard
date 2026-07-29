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


def aggregate_for_display(items, key_fn):
    """Group display items by ``key_fn``, preserving first-seen order.

    Returns a list of ``(representative_item, count)`` — the representative is
    the FIRST item seen for each key; later matches only bump the count. Pure
    and render-only: it does not mutate the inputs or their dicts, escape, emit
    HTML, read timestamps, or touch policy. Aggregation is applied ONLY when
    rendering, after the Commit Safety verdict has been computed over the full
    event list, so it can never change the verdict.
    """
    order = []
    buckets = {}
    for item in items:
        k = key_fn(item)
        entry = buckets.get(k)
        if entry is None:
            entry = [item, 1]
            buckets[k] = entry
            order.append(entry)
        else:
            entry[1] += 1
    return [(item, count) for item, count in order]


def _count_suffix(count):
    """Static, injection-safe ' ×N' marker (empty for a single occurrence).

    ``count`` is an internally derived integer, so the markup carries no
    event-derived data and needs no escaping."""
    return f' <span class="count">&times;{count}</span>' if count > 1 else ""


def format_event_detail(ev: dict) -> str:
    """Event-aware, human-readable detail for one event.

    Returns RAW text — every caller must html.escape() the result. Covers all
    seven event types the C engine emits (execve/openat/unlinkat/renameat2/
    fchmodat/exit_group/connect) so mutation/exit/connect rows render
    meaningfully rather than blank. (A degenerate event with no argv/path can
    still format to an empty string.)
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


def build_summary(safety, events=None):
    """Chips + a one-line explanation of the verdict.

    Returns RAW text pieces; the caller escapes. The chips mirror the policy
    buckets so a reader can see WHY the badge says what it says without
    scrolling through nine sections. Counts come straight from the verdict
    result — this is presentation only and cannot change the verdict.
    """
    chips = [
        ("Protected", len(safety.get("protected_accesses", [])), "hit"),
        ("Persistence", len(safety.get("persistence_writes", [])), "hit"),
        ("Dangerous cmd", len(safety.get("dangerous_commands", [])), "hit"),
        ("Outside writes", len(safety.get("boundary_violations", [])), "review"),
        ("Deletions", len(safety.get("file_deletions", [])), "review"),
        ("Outside reads", safety.get("outside_project_reads", 0), "info"),
        ("Runtime noise", len(safety.get("runtime_noise_writes", []))
                          + len(safety.get("runtime_noise_deletions", [])), "info"),
    ]

    # The verdict's actual drivers, in the same precedence the policy uses.
    # Tracked in two groups so an UNSAFE badge is never explained by
    # review-level reasons alone.
    unsafe_drivers = []
    for label, items in (("protected path access", safety.get("protected_accesses")),
                         ("persistence/activation write", safety.get("persistence_writes")),
                         ("dangerous command", safety.get("dangerous_commands")),
                         ("world-writable chmod", safety.get("unsafe_permission_changes")),
                         ("secret-exfiltration sequence", safety.get("suspicious_sequences"))):
        if items:
            unsafe_drivers.append(f"{label} \u00d7{len(items)}")

    # A critical alert forces UNSAFE on its own, even when it maps to none of the
    # buckets above (a new collector rule, say). Report it whenever nothing else
    # accounts for the UNSAFE badge — otherwise the summary could list only a
    # review-level reason under an UNSAFE verdict.
    if not unsafe_drivers and events:
        critical = sum(1 for e in events
                       if e.get("alert") and e.get("severity") == "critical")
        if critical:
            unsafe_drivers.append(f"critical alert \u00d7{critical}")

    review_drivers = []
    for label, items in (("outside-project write", safety.get("boundary_violations")),
                         ("file deletion", safety.get("file_deletions"))):
        if items:
            review_drivers.append(f"{label} \u00d7{len(items)}")
    unknown = safety.get("outside_project_unknown_opens", 0)
    if unknown:
        review_drivers.append(f"operation-unknown open \u00d7{unknown}")
    for rf in safety.get("review_findings", []):
        review_drivers.append(rf.get("type", "").replace("_", " "))

    drivers = unsafe_drivers + review_drivers

    return chips, drivers


def _details(summary_text, body, count=None, open_by_default=False):
    """Wrap a long, low-signal block in a collapsed <details>.

    Uses the native element so the report stays a single self-contained file
    with no scripting; @media print force-expands it for PDF export.
    """
    label = html.escape(summary_text)
    if count is not None:
        label += f' <span class="count">({count})</span>'
    attr = " open" if open_by_default else ""
    return f"<details{attr}><summary>{label}</summary>\n{body}</details>\n"


def _summary_html(safety, events=None):
    """Render the summary strip. All text here is internally derived, except the
    verdict name which is escaped by the caller's template."""
    chips, drivers = build_summary(safety, events)
    out = ['<div class="summary">']
    for label, count, kind in chips:
        cls = kind if count else "info"
        out.append(f'<div class="chip {cls}"><span class="n">{count:,}</span>'
                   f'<span class="k">{html.escape(label)}</span></div>')
    out.append("</div>")
    if drivers:
        out.append('<div class="why"><b>Why this verdict:</b> '
                   + html.escape(", ".join(drivers)) + "</div>")
    elif safety.get("safety") == "SAFE":
        out.append('<div class="why"><b>Why this verdict:</b> no policy findings; '
                   'outside-project reads and runtime bookkeeping are informational.</div>')
    else:
        # Never claim "no findings" under a non-SAFE badge.
        out.append('<div class="why"><b>Why this verdict:</b> see the sections '
                   'below \u2014 the badge was set by a condition not summarized '
                   'here.</div>')
    return "\n".join(out)


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
/* Eleven stacked rows pushed the verdict below the fold; the same fields fit in
   a few lines as a grid, keeping README section 9's ordering intact. */
.metagrid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
  gap: 0.35rem 1.2rem; font-size: 0.86rem; }}
.metagrid > div {{ display: flex; justify-content: space-between; gap: 0.6rem;
  border-bottom: 1px dotted #e9ecef; padding: 0.15rem 0; overflow-wrap: anywhere; }}
.metagrid .label {{ font-weight: bold; color: #555; }}
.section {{ background: white; border-radius: 8px; padding: 1.2rem 1.5rem; margin-bottom: 1rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
.section h2 {{ color: #1a3a5c; font-size: 1.1rem; margin-bottom: 0.7rem;
  border-bottom: 2px solid #e9ecef; padding-bottom: 0.4rem; }}
.section h3 {{ color: #1a3a5c; font-size: 0.95rem; margin: 0.9rem 0 0.4rem; }}
.empty {{ color: #888; font-style: italic; }}
.count {{ color: #888; font-size: 0.82em; font-weight: bold; }}
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

/* Verdict summary: why this session got its badge, without scrolling. */
.summary {{ display: flex; flex-wrap: wrap; gap: 0.6rem; margin: 0 0 1rem; }}
.chip {{ background: white; border-radius: 8px; padding: 0.55rem 0.9rem; min-width: 7.5rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 4px solid #ced4da; }}
.chip .n {{ display: block; font-size: 1.35rem; font-weight: bold; color: #1a3a5c; line-height: 1.1; }}
.chip .k {{ display: block; font-size: 0.72rem; color: #666; text-transform: uppercase;
  letter-spacing: 0.03em; margin-top: 0.15rem; }}
.chip.hit {{ border-left-color: #dc3545; }}
.chip.hit .n {{ color: #dc3545; }}
.chip.review {{ border-left-color: #fd7e14; }}
.chip.review .n {{ color: #fd7e14; }}
.chip.info {{ border-left-color: #adb5bd; }}
.chip.info .n {{ color: #868e96; }}
.why {{ background: white; border-radius: 8px; padding: 0.7rem 1rem; margin-bottom: 1rem;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 4px solid {safety_color}; font-size: 0.9rem; }}
.why b {{ color: #1a3a5c; }}
.reason {{ color: #777; font-size: 0.92em; }}

/* Long, low-signal blocks collapse; <details> keeps the report self-contained
   (no scripting) while letting a reader skip to what matters. */
details {{ margin-top: 0.3rem; }}
details > summary {{ cursor: pointer; color: #1a3a5c; font-weight: bold; font-size: 0.9rem;
  padding: 0.2rem 0; }}
details > summary:hover {{ text-decoration: underline; }}
thead th {{ position: sticky; top: 0; z-index: 1; }}

@media print {{
  /* A printed/PDF copy must show everything, collapsed or not. */
  details > div, details > ul, details > table {{ display: block !important; }}
  details[open] > summary::marker, details > summary::marker {{ content: ""; }}
  body {{ padding: 0.5rem; }}
  .section {{ box-shadow: none; border: 1px solid #dee2e6; page-break-inside: avoid; }}
}}
</style>
</head>
<body>
<div class="container">
<h1>&#128737; SysGuard Commit Safety Report</h1>
<p class="subtitle">AI Agent Boundary Auditor</p>

<div class="section meta"><h2>&#128203; Session Metadata</h2>
<div class="metagrid">
<div><span class="label">Session</span>{html.escape(session_id)}</div>
<div><span class="label">Target Agent</span>{html.escape(target_comm or "(all)")}</div>
<div><span class="label">Project Path</span>{html.escape(project_path)}</div>
<div><span class="label">Total Events</span>{safety["total_events"]:,}</div>
<div><span class="label">Alerts</span>{safety["alert_count"]:,}</div>
<div><span class="label">Commands</span>{len(summary["commands_executed"]):,}</div>
<div><span class="label">Files Accessed</span>{len(summary["files_accessed"]):,}</div>
<div><span class="label">Deleted</span>{len(summary["files_deleted"]):,}</div>
<div><span class="label">Renamed</span>{len(summary["files_renamed"]):,}</div>
<div><span class="label">Permission Changes</span>{len(summary["permission_changes"]):,}</div>
<div><span class="label">Process Exits</span>{len(summary["process_exits"]):,}</div>
</div>
</div>

<div class="safety-badge">Commit Safety: {html.escape(safety["safety"])}</div>
{_summary_html(safety, events)}
"""

    # Normal activity
    h += '<div class="section"><h2>&#9989; Normal Development Activity</h2>\n'
    normal_cmds = [e.get("argv","") for e in events if e.get("event")=="execve" and not e.get("alert")]
    normal_files = [e.get("path","") for e in events if e.get("event")=="openat" and not e.get("alert")]
    # Aggregate repeated entries into one row + a ×N count, THEN cap at 20 unique
    # rows (so repeated early activity doesn't hide later distinct activity).
    # Routine toolchain activity is the bulkiest, least surprising block, so it
    # is collapsed by default and the reader opens it only when curious.
    if normal_cmds:
        body = "<ul>\n"
        for c, n in aggregate_for_display(normal_cmds, lambda s: s)[:20]:
            body += f"  <li><code>{html.escape(c)}</code>{_count_suffix(n)}</li>\n"
        body += "</ul>\n"
        h += _details("Commands", body, count=len(normal_cmds))
    if normal_files:
        body = "<ul>\n"
        for f, n in aggregate_for_display(normal_files, lambda s: s)[:20]:
            body += f"  <li>{html.escape(f)}{_count_suffix(n)}</li>\n"
        body += "</ul>\n"
        h += _details("Files", body, count=len(normal_files))
    # File-mutation evidence that did not raise an alert (renames, safe chmods,
    # exits, and any non-alerting deletion) — event-aware so nothing is blank.
    normal_renames = [e for e in events if e.get("event") == "renameat2" and not e.get("alert")]
    normal_chmods  = [e for e in events if e.get("event") == "fchmodat" and not e.get("alert")]
    normal_deletes = [e for e in events if e.get("event") == "unlinkat" and not e.get("alert")]
    exits          = [e for e in events if e.get("event") == "exit_group"]
    def _evidence_block(label, rows, collapse):
        body = "<ul>\n"
        for e, n in aggregate_for_display(rows, format_event_detail)[:20]:
            body += f"  <li>{html.escape(format_event_detail(e))}{_count_suffix(n)}</li>\n"
        body += "</ul>\n"
        if collapse:
            return _details(label, body, count=len(rows))
        return f"<p><b>{html.escape(label)}:</b></p>" + body

    # Deletions, renames and permission changes are the parts of this section a
    # reviewer actually looks at, so they stay open; process exits are lifecycle
    # bookkeeping and are the bulkiest, so they collapse.
    if normal_deletes:
        h += _evidence_block("Deletions", normal_deletes, collapse=False)
    if normal_renames:
        h += _evidence_block("Renames", normal_renames, collapse=False)
    if normal_chmods:
        h += _evidence_block("Permission changes", normal_chmods, collapse=False)
    if exits:
        h += _evidence_block("Process exits", exits, collapse=True)
    if not (normal_cmds or normal_files or normal_renames
            or normal_chmods or normal_deletes or exits):
        h += "<p>No normal activity recorded.</p>\n"
    h += "</div>\n"

    # 4. Outside-Project Mutations — outside/at-boundary writes split by EFFECT:
    # review-worthy writes, then narrowly recognized runtime bookkeeping and
    # read-only access as informational context. Persistence-sensitive writes are
    # escalated and rendered in their own section below.
    h += '<div class="section"><h2>&#128683; Outside-Project Mutations</h2>\n'
    h += "<h3>Review-worthy outside writes</h3>\n"
    if safety["boundary_violations"]:
        h += "<ul>\n"
        for f, n in aggregate_for_display(safety["boundary_violations"], lambda x: x["detail"]):
            h += f'  <li>{html.escape(f["detail"])}{_count_suffix(n)}</li>\n'
        h += "</ul>\n"
    else:
        h += '<p class="empty">No review-worthy writes outside the project.</p>\n'

    # Informational runtime bookkeeping: writes and deletions of disposable
    # artifacts. Exempt activity is never hidden — it is always shown here with
    # counts and representative paths, it just does not drive the verdict.
    noise = (safety.get("runtime_noise_writes", [])
             + safety.get("runtime_noise_deletions", []))
    if noise:
        n_del = len(safety.get("runtime_noise_deletions", []))
        kinds = "write(s)" if not n_del else f"write(s) and {n_del} scratch deletion(s)"
        h += "<h3>Runtime bookkeeping &mdash; informational</h3>\n"
        h += (f'<p class="empty">Observed {len(noise) - n_del} known runtime-bookkeeping '
              f'{kinds}; these did not target protected, persistence-sensitive, or '
              'ordinary user paths, so they do not affect the verdict.</p>\n')
        h += "<ul>\n"
        for f, n in aggregate_for_display(noise, lambda x: x["detail"])[:20]:
            h += f'  <li class="empty">{html.escape(f["detail"])}{_count_suffix(n)}</li>\n'
        h += "</ul>\n"

    reads = safety.get("outside_project_reads", 0)
    unknown = safety.get("outside_project_unknown_opens", 0)
    read_paths = safety.get("outside_project_read_paths", [])
    if reads or unknown:
        h += "<h3>Outside reads and unknown-operation opens</h3>\n"
        note = (f'Non-sensitive outside-project reads: {reads} event(s)'
                f'{", " + str(len(read_paths)) + " unique path(s) sampled below" if read_paths else ""}'
                ' — routine runtime access, not treated as violations.')
        if unknown:
            note += (f' Unknown-operation opens (legacy records): {unknown} — these '
                     'require review because a write cannot be ruled out.')
        h += f'<p class="empty">{html.escape(note)}</p>\n'
        if read_paths:
            h += "<ul>\n"
            for p in read_paths[:20]:
                h += f'  <li class="empty">{html.escape(p)}</li>\n'
            h += "</ul>\n"
    h += "</div>\n"

    # 4b. Persistence-Sensitive Writes — mutations of shell startup files, cron,
    # systemd units, autostart, git hooks, or live agent config. Only rendered
    # when present; each one forces UNSAFE.
    if safety.get("persistence_writes"):
        h += '<div class="section"><h2>&#9888;&#65039; Persistence-Sensitive Writes</h2>\n'
        h += ('<p>A write targeted a location that can execute or activate code on '
              'a later run. Inspect each target for injected commands.</p>\n')
        h += "<ul>\n"
        for f, n in aggregate_for_display(safety["persistence_writes"], lambda x: x["detail"]):
            h += f'  <li>{html.escape(f["detail"])}{_count_suffix(n)}</li>\n'
        h += "</ul>\n</div>\n"

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
        # Collapse identical alert rows into one + an occurrence count. The key
        # keeps severity and PID so different-importance / different-process
        # alerts never merge, while the same curl alert emitted N times by one
        # process becomes a single ×N row.
        def _alert_key(a):
            return (a.get("severity", ""), a.get("rule_id", ""), a.get("pid", ""),
                    a.get("comm", ""), format_event_detail(a), a.get("reason", ""))
        def _alert_table(rows):
            # No Reason column: it restates rule + target + pid/comm, which are
            # already their own columns, and the extra width squeezed the path.
            out = ["<table>",
                   "<thead><tr><th>Severity</th><th>Rule</th><th>PID</th>"
                   "<th>Comm</th><th>Target &amp; reason</th><th>Count</th></tr></thead><tbody>"]
            for a, n in aggregate_for_display(rows, _alert_key):
                sev = a.get("severity", "")
                sc = SEV_COLORS.get(sev, "#666")
                occ = f"&times;{n}" if n > 1 else "&mdash;"
                # The reason moves under the target instead of into its own
                # column: it repeats rule/pid/comm, and as a 7th column it
                # squeezed the path it was explaining. It still carries detail
                # the other cells lack (octal modes, sequence wording), so it is
                # kept as a muted second line.
                detail = html.escape(format_event_detail(a))
                reason = html.escape(a.get("reason", ""))
                cell = detail or "&mdash;"
                if reason and reason != detail:
                    cell += f'<br><span class="reason">{reason}</span>'
                out.append(
                    f"<tr><td><span class='sev' style='background:{sc}'>{html.escape(sev)}</span></td>"
                    f"<td>{html.escape(a.get('rule_id',''))}</td>"
                    f"<td>{html.escape(str(a.get('pid','')))}</td>"
                    f"<td>{html.escape(a.get('comm',''))}</td>"
                    f"<td>{cell}</td>"
                    f"<td>{occ}</td></tr>")
            out.append("</tbody></table>")
            return "\n".join(out) + "\n"

        # Network observation is evidence, not a violation (README section 7):
        # a single agent run emits dozens of connects, which visually swamped the
        # findings that actually drive the verdict. Split it out and collapse it.
        # A CRITICAL outbound alert would set the verdict to UNSAFE, so it must
        # not be filed as "evidence only" — only routine, non-critical network
        # observation is split out.
        network = [a for a in alerts if a.get("rule_id") == "outbound-connect"
                   and a.get("severity") != "critical"]
        findings = [a for a in alerts if a not in network]
        if findings:
            h += _alert_table(findings)
        elif not network:
            h += '<p class="empty">No alerts or findings.</p>\n'
        if network:
            if not findings:
                h += ('<p class="empty">No rule findings. The connections below are '
                      'recorded as evidence and do not affect the verdict.</p>\n')
            h += _details("Outbound connections (evidence only)",
                          _alert_table(network), count=len(network))
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
        body = ("<table>\n<thead><tr><th>Event</th><th>PID</th><th>Comm</th>"
                "<th>Detail</th></tr></thead><tbody>\n")
        for e in recent:
            body += (f"<tr><td>{html.escape(e.get('event',''))}</td>"
                     f"<td>{html.escape(str(e.get('pid','')))}</td>"
                     f"<td>{html.escape(e.get('comm',''))}</td>"
                     f"<td>{html.escape(format_event_detail(e))}</td></tr>\n")
        body += "</tbody></table>\n"
        # A raw tail is reference material, not a finding: collapsed by default.
        h += _details("Event log", body, count=len(recent))
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
