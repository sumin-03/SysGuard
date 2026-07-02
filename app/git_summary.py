"""Git status/diff summary helper for SysGuard Commit Safety Report."""

import subprocess
import os


def get_git_status(project_path: str = ".") -> str:
    try:
        result = subprocess.run(
            ["git", "status", "--short"],
            cwd=project_path, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() if result.returncode == 0 else "(git status unavailable)"
    except Exception:
        return "(git not available)"


def get_git_diff_stat(project_path: str = ".") -> str:
    try:
        result = subprocess.run(
            ["git", "diff", "--stat"],
            cwd=project_path, capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() if result.returncode == 0 else "(git diff unavailable)"
    except Exception:
        return "(git not available)"


def get_git_summary(project_path: str = ".") -> dict:
    return {
        "status": get_git_status(project_path),
        "diff_stat": get_git_diff_stat(project_path),
    }
