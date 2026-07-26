"""Headless per-session Commit Safety verdict for the GUI list preview (B-007).

Pure and Tkinter-free: computes an *event-derived* verdict for one JSONL session
so the GUI can show an at-a-glance status next to each log file. Deliberately
passes ``git_summary=None`` (no per-session ``git`` shell-outs on refresh), so
this preview may report ``SAFE`` where the full report reports ``REVIEW_NEEDED``
— the git-only heuristics (high-volume/build-config/git-deletion) are not
available here. ``report.generate_report`` remains the authoritative, git-aware
verdict shown on "Open Report".

Never raises and never invokes git; any missing/empty/malformed input or
pipeline error yields ``"UNKNOWN"``.
"""

from session_analyzer import load_events, filter_target_events
from policy import evaluate_commit_safety

_VERDICTS = ("SAFE", "REVIEW_NEEDED", "UNSAFE")


def compute_session_safety(jsonl_path, target_comm="", project_path=""):
    """Return one of "SAFE"/"REVIEW_NEEDED"/"UNSAFE" for the session at
    ``jsonl_path``, or "UNKNOWN" when it cannot be computed (missing, empty, or
    malformed file, no valid events, or any pipeline error). Never raises."""
    try:
        all_events = load_events(jsonl_path)
        if not all_events:
            return "UNKNOWN"
        # Mirror report.generate_report's fallbacks for the two scoping inputs.
        if not project_path:
            project_path = all_events[0].get("project_path", ".")
        if not target_comm:
            target_comm = all_events[0].get("target_comm", "")
        events = filter_target_events(all_events, target_comm)
        result = evaluate_commit_safety(events, project_path, git_summary=None)
        safety = result.get("safety", "")
        return safety if safety in _VERDICTS else "UNKNOWN"
    except Exception:
        return "UNKNOWN"
