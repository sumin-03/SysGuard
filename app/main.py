#!/usr/bin/env python3
"""SysGuard GUI Wrapper - AI Agent Boundary Auditor."""

import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import glob
import webbrowser
import signal
import getpass
import pwd

SYSGUARD_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "sysguard")
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")
REAL_USER = os.environ.get("SUDO_USER", getpass.getuser())
REAL_UID = int(os.environ.get("SUDO_UID", os.getuid()))
REAL_GID = int(os.environ.get("SUDO_GID", os.getgid()))


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
        self.root.geometry("680x560")
        self.root.configure(bg="#f0f0f0")
        self.proc = None
        self.current_log = None

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

        # Log list
        tk.Label(root, text="Log Sessions:", bg="#f0f0f0",
                 font=("Helvetica", 10, "bold")).pack(anchor=tk.W, padx=14, pady=(8, 0))
        self.listbox = tk.Listbox(root, font=("Courier", 9), height=14)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=14, pady=4)

        # Status
        self.status = tk.Label(root, text="Ready", bg="#e9ecef", anchor=tk.W, font=("Helvetica", 9))
        self.status.pack(fill=tk.X, side=tk.BOTTOM)

        os.makedirs(LOG_DIR, exist_ok=True)
        fix_ownership(LOG_DIR)
        self.refresh_logs()

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

        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.status.config(text=f"Monitoring... PID={self.proc.pid}  Target={target}")
        self.root.after(500, self._poll)

    def _poll(self):
        if self.proc and self.proc.poll() is not None:
            self._on_stop()
            return
        if self.proc:
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
        self.status.config(text="Stopped")
        self.refresh_logs()

    def refresh_logs(self):
        self.listbox.delete(0, tk.END)
        files = sorted(glob.glob(os.path.join(LOG_DIR, "session_*.jsonl")), reverse=True)
        for f in files:
            sz = os.path.getsize(f)
            self.listbox.insert(tk.END, f"{os.path.basename(f)}  ({sz} bytes)")
        self.status.config(text=f"{len(files)} session(s) found")

    def open_report(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("No selection", "Select a log session first.")
            return
        entry = self.listbox.get(sel[0])
        fname = entry.split("  ")[0]
        jsonl_path = os.path.join(LOG_DIR, fname)

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
