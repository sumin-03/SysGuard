#!/usr/bin/env python3
"""SysGuard GUI Wrapper — AI Agent Boundary Auditor."""

import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import glob
import webbrowser
import signal

SYSGUARD_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "sysguard")
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "logs")


class SysGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SysGuard - AI Agent Boundary Auditor")
        self.root.geometry("680x560")
        self.root.configure(bg="#f0f0f0")
        self.proc = None

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
        self.refresh_logs()

    def start(self):
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = self.target_var.get().strip() or "claude"
        log_path = os.path.join(LOG_DIR, f"session_{target}_{ts}.jsonl")

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
            webbrowser.open(f"file://{os.path.abspath(html_path)}")
            self.status.config(text=f"Report: {os.path.basename(html_path)}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    SysGuardApp(root)
    root.mainloop()
