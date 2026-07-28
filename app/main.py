#!/usr/bin/env python3
"""SysGuard GUI Wrapper - AI Agent Boundary Auditor."""

import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import glob
import webbrowser
import signal
import errno
import getpass
import pwd
import stat

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


# Default trusted TMPDIR handed to the agent, under its own uid-scoped run root.
DEFAULT_TOOL_TMP = f"/tmp/claude-{REAL_UID}/tool-tmp"


def fix_ownership(path):
    """Restore file/dir ownership to the real (non-root) user."""
    try:
        os.chown(path, REAL_UID, REAL_GID)
    except OSError:
        pass


def prepare_tool_tmp(path):
    """Create/verify the trusted toolchain TMPDIR for the monitored user.

    `sysguard` refuses a root it cannot trust (not owned by the monitored user,
    not 0700, symlinked, trailing slash, ...), so the GUI — which may run under
    sudo — prepares it here. Returns (path, "") when it can be trusted, else
    (None, reason).

    Safety: the GUI runs as root, so this NEVER mutates anything until the path
    has been validated, and creation is confined to the monitored user's own
    run root. A typo such as "/etc" is rejected outright rather than chmod'ed.
    """
    if not path:
        return None, "empty path"
    # The collector refuses a trailing '/', so normalize before anything else.
    path = path.rstrip("/")
    if not path or not os.path.isabs(path):
        return None, "must be an absolute path"

    # sysguard refuses any --tool-tmp containing "." / ".." components, so the
    # GUI must not advertise such a path as active.
    if any(comp in (".", "..") for comp in path.split("/")):
        return None, "must not contain '.' or '..' components"

    run_root = f"/tmp/claude-{REAL_UID}"
    if path != run_root and not path.startswith(run_root + "/"):
        return None, (f"must be inside {run_root}/ "
                      "(use the sysguard --tool-tmp flag directly for other locations)")

    # Walk the chain through directory file descriptors with O_NOFOLLOW, and
    # mutate only through those fds (fchown/fchmod). Re-resolving pathnames
    # would be racy: the monitored user owns these directories and could swap a
    # component for a symlink between the check and the chown, making the root
    # GUI retarget an arbitrary file.
    fd = None
    try:
        try:
            fd = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY)
        except OSError as exc:
            return None, f"cannot open /tmp: {exc}"

        for comp in path[len("/tmp/"):].split("/"):
            child = None
            try:
                child = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=fd)
            except FileNotFoundError:
                try:
                    os.mkdir(comp, 0o700, dir_fd=fd)
                    child = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=fd)
                    # chown the fd we just opened, never the pathname.
                    os.fchown(child, REAL_UID, REAL_GID)
                except OSError as exc:
                    if child is not None:
                        os.close(child)
                    return None, f"cannot create {comp}: {exc}"
            except OSError as exc:
                # Linux reports ENOTDIR (not ELOOP) for O_NOFOLLOW|O_DIRECTORY on
                # a symlink, so distinguish the two for an accurate message. This
                # runs only on the rejection path — nothing is mutated after it.
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    try:
                        if stat.S_ISLNK(os.lstat(comp, dir_fd=fd).st_mode):
                            return None, f"{comp} is a symlink"
                    except OSError:
                        pass
                    return None, f"{comp} exists but is not a directory"
                return None, f"cannot open {comp}: {exc}"

            st = os.fstat(child)
            if not stat.S_ISDIR(st.st_mode):
                os.close(child)
                return None, f"{comp} is not a directory"
            if st.st_uid != REAL_UID:
                os.close(child)
                return None, f"{comp} is not owned by uid {REAL_UID}"

            os.close(fd)
            fd = child

        # `fd` is now the leaf, opened without following any symlink.
        if (os.fstat(fd).st_mode & 0o7777) != 0o700:
            try:
                os.fchmod(fd, 0o700)
            except OSError as exc:
                return None, f"cannot set mode 0700: {exc}"
    finally:
        if fd is not None:
            os.close(fd)
    return path, ""


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
        self.active_tool_tmp = None

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

        # Trusted toolchain TMPDIR: build tools (gcc, ...) write intermediates
        # under whatever TMPDIR the agent has. Naming that directory here lets
        # SysGuard classify those files as runtime bookkeeping instead of
        # outside-project writes — see README section 6.
        tk.Label(inp, text="Tool TMPDIR:", bg="#f0f0f0", font=("Helvetica", 10)).grid(row=2, column=0, sticky="w")
        self.tool_tmp_var = tk.StringVar(value=DEFAULT_TOOL_TMP)
        tk.Entry(inp, textvariable=self.tool_tmp_var, width=50,
                 font=("Helvetica", 10)).grid(row=2, column=1, padx=4)

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

        # Trusted toolchain TMPDIR. sysguard refuses a root it cannot trust, so
        # create it here (owned by the real user, 0700) and only pass it once it
        # validates. Leaving it blank simply keeps build temp files reportable.
        tool_tmp = self.tool_tmp_var.get().strip()
        self.active_tool_tmp = None
        if tool_tmp:
            prepared, reason = prepare_tool_tmp(tool_tmp)
            if prepared:
                args += ["--tool-tmp", prepared]
                self.active_tool_tmp = prepared
            else:
                messagebox.showwarning(
                    "Tool TMPDIR ignored",
                    f"Could not use '{tool_tmp}': {reason}.\n\n"
                    "Monitoring will start, but build toolchain temp files will "
                    "be reported as outside-project writes.")

        try:
            self.proc = subprocess.Popen(args, preexec_fn=os.setsid)
            if self.active_tool_tmp:
                # The agent is launched by the user, not by SysGuard, so the
                # TMPDIR only takes effect if they export it themselves.
                messagebox.showinfo(
                    "Start the agent with this TMPDIR",
                    "Monitoring started.\n\nLaunch the agent in a terminal with:\n\n"
                    f"    TMPDIR={self.active_tool_tmp} {target}\n\n"
                    "Build toolchain temp files created under that directory are "
                    "then classified as runtime bookkeeping instead of "
                    "outside-project writes.")
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
        target = self.target_var.get().strip()
        project = self.project_var.get().strip()
        for i, f in enumerate(files):
            # Per-file isolation: one missing/unreadable/malformed session must
            # not abort the whole refresh — it just shows [UNKNOWN].
            try:
                sz = os.path.getsize(f)
            except OSError:
                sz = 0
            verdict = compute_session_safety(f, target_comm=target, project_path=project)
            self.listbox.insert(tk.END, f"{os.path.basename(f)}  ({sz} bytes)  [{verdict}]")
            self.listbox.itemconfig(i, foreground=SAFETY_COLORS.get(verdict, "#666666"))
        self.status.config(text=f"{len(files)} session(s) found")

    def open_report(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("No selection", "Select a log session first.")
            return
        entry = self.listbox.get(sel[0])
        # The row is "<filename>  (<N> bytes)  [<VERDICT>]"; the filename is the
        # first double-space-delimited field. Bound the split so later suffix
        # changes cannot alter filename recovery.
        fname = entry.split("  ", 1)[0]
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
