#!/usr/bin/env python3
"""SysGuard GUI Wrapper - AI Agent Boundary Auditor."""

import tkinter as tk
from tkinter import messagebox, ttk
import subprocess
import os
import glob
import webbrowser
import signal
import getpass
import pwd
import threading
import time

from safety_preview import compute_session_safety

SYSGUARD_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "sysguard")
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")

# README safety badge colors (SAFE=green, REVIEW_NEEDED=orange, UNSAFE=red);
# neutral gray when the preview cannot be computed.
SAFETY_COLORS = {
    "SAFE": "#28a745",
    "REVIEW_NEEDED": "#fd7e14",
    "UNSAFE": "#dc3545",
    "UNKNOWN": "#666666",
}
REAL_USER = os.environ.get("SUDO_USER", getpass.getuser())
REAL_UID = int(os.environ.get("SUDO_UID", os.getuid()))
REAL_GID = int(os.environ.get("SUDO_GID", os.getgid()))



def human_size(n):
    """Byte count as a compact human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def count_new_lines(path, offset):
    """Count complete lines added to `path` after byte `offset`.

    Returns (lines_added, new_offset). Reading only the delta keeps the poll
    cheap no matter how large the session grows, and stopping at the last
    newline means a half-written record is counted once it is complete.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return 0, offset
    if size <= offset:
        return 0, offset          # truncated or unchanged
    try:
        with open(path, "rb") as fh:
            fh.seek(offset)
            chunk = fh.read(size - offset)
    except OSError:
        return 0, offset
    cut = chunk.rfind(b"\n")
    if cut < 0:
        return 0, offset          # no complete line yet
    return chunk[:cut + 1].count(b"\n"), offset + cut + 1


def session_timestamp(name):
    """Session start time parsed from the log filename, e.g.
    "session_claude_20260728_193352.jsonl" -> "07-28 19:33".

    The file's mtime is when collection *ended* (and changes if the file is
    touched later), so the name is the more meaningful column. Returns None when
    the name does not carry a timestamp.
    """
    stem = os.path.basename(name)
    if stem.endswith(".jsonl"):
        stem = stem[:-len(".jsonl")]
    parts = stem.split("_")
    if len(parts) < 2:
        return None
    date, clock = parts[-2], parts[-1]
    if len(date) != 8 or len(clock) != 6 or not (date + clock).isdigit():
        return None
    return f"{date[4:6]}-{date[6:8]} {clock[0:2]}:{clock[2:4]}"


def format_elapsed(seconds):
    """Whole seconds as H:MM:SS."""
    seconds = int(seconds)
    return f"{seconds // 3600}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"


def cache_key(path):
    """Identity of a log file's *content* for verdict caching.

    A session's verdict can only change when the file changes, so (mtime, size)
    is enough to reuse a previous result and skip a multi-second re-analysis.
    """
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def fix_ownership(path):
    """Restore file/dir ownership to the real (non-root) user."""
    try:
        os.chown(path, REAL_UID, REAL_GID)
    except OSError:
        pass


def open_in_browser(path):
    """Open a file in the real user's browser, even when the GUI runs as root.

    `sudo -E` alone is not enough: it leaks root's HOME/XDG dirs into the
    child, so gio/dconf break and snap browsers (firefox) are not on sudo's
    secure PATH. Rebuild the real user's session environment explicitly.
    """
    url = f"file://{os.path.abspath(path)}"
    if not os.environ.get("SUDO_USER"):
        webbrowser.open(url)
        return

    info = pwd.getpwnam(REAL_USER)
    env = {
        "HOME": info.pw_dir,
        "USER": REAL_USER,
        "LOGNAME": REAL_USER,
        "DISPLAY": os.environ.get("DISPLAY", ":0"),
        "XDG_RUNTIME_DIR": f"/run/user/{info.pw_uid}",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{info.pw_uid}/bus",
        "PATH": "/usr/local/bin:/usr/bin:/bin:/snap/bin",
        # Without XDG_DATA_DIRS gio cannot see snap desktop entries
        # (/var/lib/snapd/desktop), so the firefox_firefox.desktop default
        # is unresolvable and gio falls back to Text Editor.
        "XDG_DATA_DIRS": os.environ.get(
            "XDG_DATA_DIRS",
            "/usr/share/ubuntu:/usr/share/gnome:/usr/local/share/"
            ":/usr/share/:/var/lib/snapd/desktop"),
    }
    # sudo strips XAUTHORITY / WAYLAND_DISPLAY from the GUI's environment,
    # so recover them from the real user's runtime dir instead of relying
    # on passthrough. Without one of these firefox cannot reach the display.
    run_dir = f"/run/user/{info.pw_uid}"
    if os.path.exists(f"{run_dir}/wayland-0"):
        env["WAYLAND_DISPLAY"] = "wayland-0"
    xauth = os.environ.get("XAUTHORITY")
    if not xauth:
        candidates = glob.glob(f"{run_dir}/.mutter-Xwaylandauth.*")
        xauth = candidates[0] if candidates else None
    if xauth:
        env["XAUTHORITY"] = xauth
    if os.environ.get("XDG_CURRENT_DESKTOP"):
        env["XDG_CURRENT_DESKTOP"] = os.environ["XDG_CURRENT_DESKTOP"]

    cmd = ["sudo", "-u", REAL_USER, "env"]
    cmd += [f"{k}={v}" for k, v in env.items()]
    cmd += ["xdg-open", os.path.abspath(path)]
    subprocess.Popen(cmd)


class SysGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SysGuard - AI Agent Boundary Auditor")
        self.root.geometry("760x600")
        self.root.minsize(640, 480)
        self.root.configure(bg="#f0f0f0")
        # "clam" is the only bundled theme that honours custom colours on Linux,
        # so the verdict tints and header styling render consistently.
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Treeview", rowheight=22, font=("DejaVu Sans", 9))
        style.configure("Treeview.Heading", font=("DejaVu Sans", 9, "bold"))
        self.proc = None
        self.current_log = None
        self._verdict_cache = {}
        self._scan_generation = 0
        self._rows = []
        self._live_events = 0
        self._live_offset = 0
        self._live_started = 0

        # Header
        hdr = tk.Frame(root, bg="#1a3a5c", pady=10)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="\U0001f6e1 SysGuard - AI Agent Boundary Auditor",
                 fg="white", bg="#1a3a5c", font=("Helvetica", 15, "bold")).pack()

        # Inputs
        inp = tk.Frame(root, bg="#f0f0f0", pady=6)
        inp.pack(fill=tk.X, padx=12)
        tk.Label(inp, text="Project Path:", bg="#f0f0f0", font=("Helvetica", 10)).grid(row=0, column=0, sticky="w")
        self.project_var = tk.StringVar(value=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        tk.Entry(inp, textvariable=self.project_var, width=50, font=("Helvetica", 10)).grid(row=0, column=1, padx=4)

        tk.Label(inp, text="Target Process:", bg="#f0f0f0", font=("Helvetica", 10)).grid(row=1, column=0, sticky="w")
        self.target_var = tk.StringVar(value="claude")
        tk.Entry(inp, textvariable=self.target_var, width=50, font=("Helvetica", 10)).grid(row=1, column=1, padx=4)


        # Buttons
        btn = tk.Frame(root, bg="#f0f0f0", pady=6)
        btn.pack(fill=tk.X, padx=12)

        self.btn_start = tk.Button(btn, text="\u25b6 Start Monitoring",
                                   command=self.start, bg="#28a745", fg="white",
                                   font=("Helvetica", 10, "bold"), width=18)
        self.btn_start.pack(side=tk.LEFT, padx=3)

        self.btn_stop = tk.Button(btn, text="\u25a0 Stop",
                                  command=self.stop, bg="#dc3545", fg="white",
                                  font=("Helvetica", 10, "bold"), width=10, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=3)

        tk.Button(btn, text="\U0001f504 Refresh", command=self.refresh_logs,
                  font=("Helvetica", 9), width=10).pack(side=tk.LEFT, padx=3)

        tk.Button(btn, text="\U0001f4c4 Open Report", command=self.open_report,
                  font=("Helvetica", 9), width=12).pack(side=tk.LEFT, padx=3)

        # Mode
        mode_f = tk.Frame(root, bg="#f0f0f0")
        mode_f.pack(fill=tk.X, padx=12)
        self.use_fake = tk.BooleanVar(value=True)
        tk.Checkbutton(mode_f, text="Use fake collector (no root needed)",
                       variable=self.use_fake, bg="#f0f0f0", font=("Helvetica", 9)).pack(anchor=tk.W)

        # Selected-session badge, mirroring the report's SAFE/REVIEW/UNSAFE badge.
        self.badge = tk.Label(root, text="No session selected", fg="white",
                              bg="#999999", font=("DejaVu Sans", 11, "bold"),
                              pady=6)
        self.badge.pack(fill=tk.X, padx=14, pady=(8, 0))

        # Log list
        tk.Label(root, text="Log Sessions:", bg="#f0f0f0",
                 font=("Helvetica", 10, "bold")).pack(anchor=tk.W, padx=14, pady=(8, 0))
        list_f = tk.Frame(root, bg="#f0f0f0")
        list_f.pack(fill=tk.BOTH, expand=True, padx=14, pady=4)
        self.tree = ttk.Treeview(list_f, columns=("time", "size", "verdict"),
                                 show="tree headings", height=14, selectmode="browse")
        self.tree.heading("#0", text="Session", command=lambda: self._sort_by("name"))
        self.tree.heading("time", text="Time", command=lambda: self._sort_by("time"))
        self.tree.heading("size", text="Size", command=lambda: self._sort_by("size"))
        self.tree.heading("verdict", text="Verdict", command=lambda: self._sort_by("verdict"))
        self.tree.column("#0", width=300, anchor="w")
        self.tree.column("time", width=110, anchor="center", stretch=False)
        self.tree.column("size", width=90, anchor="e", stretch=False)
        self.tree.column("verdict", width=140, anchor="center", stretch=False)
        for verdict, color in SAFETY_COLORS.items():
            self.tree.tag_configure(verdict, foreground=color)
        self.tree.tag_configure("PENDING", foreground="#999999")
        sb = ttk.Scrollbar(list_f, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        # Opening a report is the usual next step, so make it a double-click too.
        self.tree.bind("<Double-1>", lambda _e: self.open_report())
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._update_badge())
        self._sort_key = "name"
        self._sort_desc = True

        # Status
        self.status = tk.Label(root, text="Ready", bg="#e9ecef", anchor=tk.W, font=("Helvetica", 9))
        self.status.pack(fill=tk.X, side=tk.BOTTOM)

        os.makedirs(LOG_DIR, exist_ok=True)
        fix_ownership(LOG_DIR)
        # Defer the first scan: refresh_logs() may start a worker that calls
        # root.after() from a background thread, which Tkinter rejects until the
        # event loop is actually running.
        self.root.after(0, self.refresh_logs)

    def start(self):
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = self.target_var.get().strip() or "claude"
        log_path = os.path.join(LOG_DIR, f"session_{target}_{ts}.jsonl")
        self.current_log = log_path

        # Pre-create log file with real user ownership
        with open(log_path, "a") as f:
            pass
        fix_ownership(log_path)
        os.chmod(log_path, 0o644)

        args = [SYSGUARD_BIN]
        if self.use_fake.get():
            args.append("--fake")
        args += [
            "--agent-mode",
            "--target-comm", target,
            "--project-path", self.project_var.get().strip(),
            "--output", log_path,
        ]

        try:
            self.proc = subprocess.Popen(args, preexec_fn=os.setsid)
        except FileNotFoundError:
            messagebox.showerror("Error", f"Binary not found: {SYSGUARD_BIN}\nRun 'make' first.")
            return

        self._live_events = 0
        self._live_offset = 0
        self._live_started = time.time()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.status.config(text=f"\u25cf Monitoring  0 events  \u00b7  0:00:00"
                                f"  \u00b7  PID {self.proc.pid}")
        self.root.after(500, self._poll)

    def _poll(self):
        if self.proc and self.proc.poll() is not None:
            self._on_stop()
            return
        if not self.proc:
            return
        # Show the session growing: without this the window looks frozen for the
        # whole run. Only the bytes appended since the last tick are scanned.
        if self.current_log:
            added, self._live_offset = count_new_lines(self.current_log, self._live_offset)
            self._live_events += added
        self.status.config(
            text=f"\u25cf Monitoring  {self._live_events:,} events"
                 f"  \u00b7  {format_elapsed(time.time() - self._live_started)}"
                 f"  \u00b7  PID {self.proc.pid}")
        self.root.after(500, self._poll)

    def stop(self):
        if self.proc:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
                self.proc.wait(timeout=5)
            except Exception:
                pass
        self._on_stop()

    def _on_stop(self):
        self.proc = None
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        # Restore ownership of log file after root process exits
        if self.current_log and os.path.exists(self.current_log):
            fix_ownership(self.current_log)
            try:
                os.chmod(self.current_log, 0o644)
            except OSError:
                pass
        if self._live_started and self.current_log:
            # Records written between the last poll and exit (including any
            # flushed while handling SIGINT) would otherwise be missing.
            added, self._live_offset = count_new_lines(self.current_log, self._live_offset)
            self._live_events += added
        self.status.config(
            text=f"Stopped \u2014 {self._live_events:,} events in "
                 f"{format_elapsed(time.time() - self._live_started)}"
            if self._live_started else "Stopped")
        self.refresh_logs()

    def refresh_logs(self):
        """Redraw the session list immediately; compute verdicts in the background.

        Analysing a session is O(file size) and a large log takes seconds, so
        doing it inline froze the whole window — including at startup, since
        __init__ calls this before mainloop(). Rows are drawn at once using
        cached verdicts, and anything unknown is filled in as a worker finishes
        it. Results carry the generation they were requested in, so a refresh
        that lands mid-scan discards the stale ones.
        """
        files = glob.glob(os.path.join(LOG_DIR, "session_*.jsonl"))
        target = self.target_var.get().strip()
        project = self.project_var.get().strip()

        self._scan_generation += 1
        generation = self._scan_generation

        rows = []
        pending = []
        for path in files:
            key = cache_key(path)
            verdict = self._verdict_cache.get((path, key, target, project)) if key else None
            rows.append({
                "path": path,
                "name": os.path.basename(path),
                "size": key[1] if key else 0,
                "time": key[0] if key else 0,
                "verdict": verdict,
            })
            if verdict is None:
                pending.append((path, key))

        self._rows = rows
        self._redraw()

        if not pending:
            self.status.config(text=f"{len(rows)} session(s)")
            return

        self.status.config(text=f"{len(rows)} session(s) — analysing {len(pending)}…")
        threading.Thread(target=self._scan_worker,
                         args=(generation, pending, target, project),
                         daemon=True).start()

    # Sorting the verdict column by badge order (worst first) is more useful
    # than sorting it alphabetically.
    _VERDICT_ORDER = {"UNSAFE": 0, "REVIEW_NEEDED": 1, "UNKNOWN": 2, "SAFE": 3}

    def _sort_by(self, key):
        """Re-sort on a header click; clicking the active column flips direction."""
        if self._sort_key == key:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_key = key
            self._sort_desc = key in ("name", "time", "size")
        self._redraw()

    def _redraw(self):
        """Rebuild every row from self._rows. Must run on the Tk main thread."""
        key = self._sort_key

        def sort_value(row):
            if key == "verdict":
                return self._VERDICT_ORDER.get(row["verdict"], 9)
            return row[key]

        self._rows.sort(key=sort_value, reverse=self._sort_desc)
        selected = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        for row in self._rows:
            verdict = row["verdict"]
            stamp = (session_timestamp(row["name"])
                     or (time.strftime("%m-%d %H:%M", time.localtime(row["time"] / 1e9))
                         if row["time"] else "-"))
            self.tree.insert("", tk.END, iid=row["path"], text=row["name"],
                             values=(stamp, human_size(row["size"]),
                                     verdict or "analysing…"),
                             tags=(verdict or "PENDING",))
        for iid in selected:
            if self.tree.exists(iid):
                self.tree.selection_set(iid)

    def _scan_worker(self, generation, pending, target, project):
        """Compute verdicts off the UI thread; hand each result back via after()."""
        for path, key in pending:
            if generation != self._scan_generation:
                return                      # a newer refresh superseded this scan
            try:
                verdict = compute_session_safety(path, target_comm=target,
                                                 project_path=project)
            except Exception:
                # One unreadable/malformed session must not abort the scan.
                verdict = "UNKNOWN"
            self.root.after(0, self._apply_verdict,
                            generation, path, key, verdict, target, project)
        self.root.after(0, self._scan_done, generation)

    def _apply_verdict(self, generation, path, key, verdict, target, project):
        if generation != self._scan_generation:
            return
        if key:
            self._verdict_cache[(path, key, target, project)] = verdict
        for row in self._rows:
            if row["path"] == path:
                row["verdict"] = verdict
                break
        if self.tree.exists(path):
            values = list(self.tree.item(path, "values"))
            values[2] = verdict
            self.tree.item(path, values=values, tags=(verdict,))
            if path in self.tree.selection():
                self._update_badge()

    def _update_badge(self):
        sel = self.tree.selection()
        if not sel:
            self.badge.config(text="No session selected", bg="#999999")
            return
        path = sel[0]
        verdict = next((r["verdict"] for r in self._rows if r["path"] == path), None)
        self.badge.config(text=f"{os.path.basename(path)}  \u2014  "
                               f"{verdict or 'analysing…'}",
                          bg=SAFETY_COLORS.get(verdict, "#999999"))

    def _scan_done(self, generation):
        if generation == self._scan_generation:
            self.status.config(text=f"{len(self._rows)} session(s)")

    def open_report(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("No selection", "Select a log session first.")
            return
        jsonl_path = sel[0]      # the row's iid is the log path itself

        try:
            from report import generate_report
            html_path = generate_report(
                jsonl_path,
                target_comm=self.target_var.get().strip(),
                project_path=self.project_var.get().strip(),
            )
            fix_ownership(html_path)
            open_in_browser(html_path)
            self.status.config(text=f"Report: {os.path.basename(html_path)}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    SysGuardApp(root)
    root.mainloop()
