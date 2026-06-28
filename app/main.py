#!/usr/bin/env python3
"""SysGuard GUI Wrapper — Tkinter-based monitor control & report viewer."""

import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import glob
import webbrowser
import signal
from report import jsonl_to_html

SYSGUARD_BIN = os.path.join(os.path.dirname(__file__), "..", "build", "sysguard")
LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")


class SysGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SysGuard Monitor")
        self.root.geometry("620x480")
        self.root.configure(bg="#f0f0f0")
        self.proc = None

        frame_top = tk.Frame(root, bg="#1a3a5c", pady=10)
        frame_top.pack(fill=tk.X)
        tk.Label(frame_top, text="🛡️ SysGuard Monitor",
                 fg="white", bg="#1a3a5c",
                 font=("Helvetica", 16, "bold")).pack()

        frame_btn = tk.Frame(root, bg="#f0f0f0", pady=8)
        frame_btn.pack(fill=tk.X, padx=10)

        self.btn_start = tk.Button(frame_btn, text="▶ Start Monitoring",
                                   command=self.start, bg="#28a745", fg="white",
                                   font=("Helvetica", 11, "bold"), width=18)
        self.btn_start.pack(side=tk.LEFT, padx=4)

        self.btn_stop = tk.Button(frame_btn, text="■ Stop",
                                  command=self.stop, bg="#dc3545", fg="white",
                                  font=("Helvetica", 11, "bold"), width=10,
                                  state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=4)

        self.btn_refresh = tk.Button(frame_btn, text="🔄 Refresh Logs",
                                     command=self.refresh_logs,
                                     font=("Helvetica", 10), width=14)
        self.btn_refresh.pack(side=tk.LEFT, padx=4)

        self.btn_report = tk.Button(frame_btn, text="📄 Open Report",
                                    command=self.open_report,
                                    font=("Helvetica", 10), width=14)
        self.btn_report.pack(side=tk.LEFT, padx=4)

        frame_mode = tk.Frame(root, bg="#f0f0f0")
        frame_mode.pack(fill=tk.X, padx=10)
        self.use_fake = tk.BooleanVar(value=True)
        tk.Checkbutton(frame_mode, text="Use fake collector (no root needed)",
                       variable=self.use_fake, bg="#f0f0f0",
                       font=("Helvetica", 9)).pack(anchor=tk.W)

        tk.Label(root, text="Log Sessions:", bg="#f0f0f0",
                 font=("Helvetica", 11, "bold")).pack(anchor=tk.W, padx=12, pady=(8, 0))

        self.listbox = tk.Listbox(root, font=("Courier", 10), height=14)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        self.status = tk.Label(root, text="Ready", bg="#e9ecef",
                               anchor=tk.W, font=("Helvetica", 9))
        self.status.pack(fill=tk.X, side=tk.BOTTOM)

        os.makedirs(LOG_DIR, exist_ok=True)
        self.refresh_logs()

    def start(self):
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = os.path.join(LOG_DIR, f"session_{ts}.jsonl")

        args = [SYSGUARD_BIN, "--output", log_path]
        if self.use_fake.get():
            args.insert(1, "--fake")

        try:
            self.proc = subprocess.Popen(args, preexec_fn=os.setsid)
        except FileNotFoundError:
            messagebox.showerror("Error",
                f"Binary not found: {SYSGUARD_BIN}\nRun 'make' first.")
            return

        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.status.config(text=f"Monitoring... PID={self.proc.pid}  Log={os.path.basename(log_path)}")

        self.root.after(500, self._poll_proc)

    def _poll_proc(self):
        if self.proc and self.proc.poll() is not None:
            self._on_stop()
            return
        if self.proc:
            self.root.after(500, self._poll_proc)

    def stop(self):
        if self.proc:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
            self.proc.wait()
        self._on_stop()

    def _on_stop(self):
        self.proc = None
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.status.config(text="Stopped")
        self.refresh_logs()

    def refresh_logs(self):
        self.listbox.delete(0, tk.END)
        files = sorted(glob.glob(os.path.join(LOG_DIR, "session_*.jsonl")), reverse=True)
        for f in files:
            size = os.path.getsize(f)
            self.listbox.insert(tk.END, f"{os.path.basename(f)}  ({size} bytes)")
        self.status.config(text=f"{len(files)} log session(s) found")

    def open_report(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("No selection", "Select a log session first.")
            return
        entry = self.listbox.get(sel[0])
        fname = entry.split("  ")[0]
        jsonl_path = os.path.join(LOG_DIR, fname)

        try:
            html_path = jsonl_to_html(jsonl_path)
            webbrowser.open(f"file://{os.path.abspath(html_path)}")
            self.status.config(text=f"Report opened: {os.path.basename(html_path)}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = SysGuardApp(root)
    root.mainloop()