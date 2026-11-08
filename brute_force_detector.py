#!/usr/bin/env python3
"""
Brute-Force Login Detector
----------------------------
Tails /var/log/auth.log in real time, tracks failed SSH login attempts
per source IP within a sliding time window, and flags any IP that
crosses your threshold as a likely brute-force attempt.

Requirements:
  - tkinter (usually pre-installed; if missing: sudo apt install python3-tk)
  - Read access to /var/log/auth.log. On Kali your user is often in the
    'adm' group already (try running without sudo first). If you get a
    permission error, either:
        sudo usermod -aG adm $USER      # then log out and back in
    or just run this app with sudo.

Optional blocking feature:
  - You can select a flagged IP and click "Block IP" to add a DROP rule
    via iptables. This requires root and asks for confirmation first —
    nothing is blocked automatically.
"""

import os
import re
import subprocess
import threading
import time
import queue
import tkinter as tk
from tkinter import ttk, messagebox
from collections import deque, defaultdict
from datetime import datetime
from pathlib import Path

LOG_PATHS = ["/var/log/auth.log", "/var/log/secure"]  # Debian/Kali, RHEL/CentOS
IS_ROOT = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)"
)
INVALID_USER_PATTERN = re.compile(
    r"Invalid user (\S+) from (\S+) port (\d+)"
)
ACCEPTED_PATTERN = re.compile(
    r"Accepted password for (\S+) from (\S+) port (\d+)"
)

BG_COLOR = "#1e1e1e"
FG_COLOR = "#00FF41"
WARN = "#ff4d4d"
GOOD = "#5cc26a"
UI_TEXT = "#dddddd"


def find_log_path():
    for path in LOG_PATHS:
        if Path(path).exists():
            return path
    return None


class LogTailThread(threading.Thread):
    """Tails the auth log file, parses new lines, and reports events via queue."""

    def __init__(self, log_path, event_queue, window_seconds, threshold):
        super().__init__(daemon=True)
        self.log_path = log_path
        self.event_queue = event_queue
        self.window_seconds = window_seconds
        self.threshold = threshold
        self._stop_flag = threading.Event()
        # ip -> deque of timestamps (failed attempts within window)
        self.attempts = defaultdict(deque)
        self.usernames = defaultdict(set)
        self.flagged = set()

    def stop(self):
        self._stop_flag.set()

    def run(self):
        try:
            f = open(self.log_path, "r")
        except PermissionError:
            self.event_queue.put(("error", f"Permission denied reading {self.log_path}. "
                                             f"Run with sudo, or add your user to the 'adm' group."))
            return
        except FileNotFoundError:
            self.event_queue.put(("error", f"Log file not found: {self.log_path}"))
            return

        f.seek(0, os.SEEK_END)  # start at the end — only watch new lines
        inode = os.fstat(f.fileno()).st_ino

        self.event_queue.put(("status", f"Watching {self.log_path} ..."))

        while not self._stop_flag.is_set():
            line = f.readline()
            if line:
                self._process_line(line)
                continue

            # No new line — check for log rotation, then wait briefly
            try:
                current_inode = os.stat(self.log_path).st_ino
                if current_inode != inode:
                    f.close()
                    f = open(self.log_path, "r")
                    inode = os.fstat(f.fileno()).st_ino
                    self.event_queue.put(("status", "Log file rotated — reopened."))
            except FileNotFoundError:
                pass

            time.sleep(0.5)

        f.close()

    def _process_line(self, line):
        now = time.time()

        m = FAILED_PATTERN.search(line) or INVALID_USER_PATTERN.search(line)
        if m:
            username, ip = m.group(1), m.group(2)
            self._prune(ip, now)
            self.attempts[ip].append(now)
            self.usernames[ip].add(username)

            count = len(self.attempts[ip])
            self.event_queue.put(("failed_attempt", {
                "ip": ip, "username": username, "count": count,
                "usernames": set(self.usernames[ip]), "time": now,
            }))

            if count >= self.threshold and ip not in self.flagged:
                self.flagged.add(ip)
                self.event_queue.put(("brute_force_detected", {
                    "ip": ip, "count": count, "usernames": set(self.usernames[ip]), "time": now,
                }))
            return

        m = ACCEPTED_PATTERN.search(line)
        if m:
            username, ip = m.group(1), m.group(2)
            self.event_queue.put(("successful_login", {"ip": ip, "username": username, "time": now}))

    def _prune(self, ip, now):
        dq = self.attempts[ip]
        while dq and now - dq[0] > self.window_seconds:
            dq.popleft()
        if not dq:
            self.flagged.discard(ip)
            self.usernames[ip].clear()


class BruteForceDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Brute-Force Login Detector")
        self.root.geometry("950x600")
        self.root.minsize(800, 480)
        self.root.configure(bg=BG_COLOR)

        self.event_queue = queue.Queue()
        self.tail_thread = None
        self.ip_rows = {}  # ip -> treeview item id
        self.ip_data = {}  # ip -> dict of latest info

        self._build_ui()
        self._poll_queue()

    # ---------------- UI ----------------

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG_COLOR, foreground=FG_COLOR, font=("Consolas", 10))
        style.configure("TFrame", background=BG_COLOR)
        style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR)
        style.configure("TButton", padding=5)

        controls = ttk.Frame(self.root, padding=10)
        controls.pack(fill="x")

        log_path = find_log_path()
        ttk.Label(controls, text=f"Log file: {log_path or 'NOT FOUND'}").grid(row=0, column=0, columnspan=2, sticky="w")

        ttk.Label(controls, text="Window (sec):").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.window_entry = ttk.Entry(controls, width=8)
        self.window_entry.insert(0, "60")
        self.window_entry.grid(row=1, column=1, sticky="w", pady=(8, 0), padx=(5, 20))

        ttk.Label(controls, text="Threshold (attempts):").grid(row=1, column=2, sticky="w", pady=(8, 0))
        self.threshold_entry = ttk.Entry(controls, width=8)
        self.threshold_entry.insert(0, "5")
        self.threshold_entry.grid(row=1, column=3, sticky="w", pady=(8, 0), padx=(5, 20))

        self.start_button = ttk.Button(controls, text="Start Watching", command=self.start)
        self.start_button.grid(row=1, column=4, padx=5, pady=(8, 0))
        self.stop_button = ttk.Button(controls, text="Stop", command=self.stop, state="disabled")
        self.stop_button.grid(row=1, column=5, padx=5, pady=(8, 0))

        self.block_button = ttk.Button(controls, text="Block Selected IP", command=self.block_selected_ip, state="disabled")
        self.block_button.grid(row=1, column=6, padx=5, pady=(8, 0))

        self.status_label = ttk.Label(self.root, text="Idle.", padding=(10, 5))
        self.status_label.pack(fill="x")

        if not IS_ROOT:
            warn = ttk.Label(
                self.root,
                text="⚠ Not running as root — blocking IPs won't work, and reading the log may fail "
                     "unless your user is in the 'adm' group.",
                foreground="#e0b356", padding=(10, 0)
            )
            warn.pack(fill="x")

        # Table of tracked IPs
        table_frame = ttk.Frame(self.root, padding=10)
        table_frame.pack(fill="both", expand=True)

        columns = ("ip", "count", "usernames", "first_seen", "last_seen", "status")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=12)
        for col, label, width in [
            ("ip", "Source IP", 140), ("count", "Attempts (window)", 130),
            ("usernames", "Usernames Tried", 220), ("first_seen", "First Seen", 100),
            ("last_seen", "Last Seen", 100), ("status", "Status", 140),
        ]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w")

        self.tree.tag_configure("flagged", background="#4a1414", foreground=WARN)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Log area
        log_frame = ttk.Frame(self.root, padding=10)
        log_frame.pack(fill="both", expand=False)
        ttk.Label(log_frame, text="Activity Log:").pack(anchor="w")
        self.log_text = tk.Text(log_frame, height=8, state="disabled", wrap="word", bg="#111", fg="#ddd")
        self.log_text.pack(fill="both", expand=True)

    # ---------------- Actions ----------------

    def start(self):
        log_path = find_log_path()
        if not log_path:
            messagebox.showerror("Log not found", f"Couldn't find any of: {', '.join(LOG_PATHS)}")
            return

        try:
            window_seconds = int(self.window_entry.get().strip())
            threshold = int(self.threshold_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid input", "Window and threshold must be whole numbers.")
            return

        self.tail_thread = LogTailThread(log_path, self.event_queue, window_seconds, threshold)
        self.tail_thread.start()

        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.window_entry.config(state="disabled")
        self.threshold_entry.config(state="disabled")
        self._log(f"Started watching {log_path} (window={window_seconds}s, threshold={threshold}).")

    def stop(self):
        if self.tail_thread:
            self.tail_thread.stop()
            self.tail_thread = None
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.window_entry.config(state="normal")
        self.threshold_entry.config(state="normal")
        self.status_label.config(text="Stopped.")
        self._log("Stopped watching.")

    def block_selected_ip(self):
        selection = self.tree.selection()
        if not selection:
            return
        ip = self.tree.item(selection[0], "values")[0]

        if not IS_ROOT:
            messagebox.showerror("Root required", "Blocking IPs requires root. Restart this app with sudo.")
            return

        confirm = messagebox.askyesno(
            "Confirm block",
            f"Add a firewall rule to drop all traffic from {ip}?\n\n"
            f"This runs: sudo iptables -A INPUT -s {ip} -j DROP"
        )
        if not confirm:
            return

        try:
            result = subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                                     capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self._log(f"Blocked {ip} via iptables.")
                messagebox.showinfo("Blocked", f"{ip} has been blocked.")
                if ip in self.ip_data:
                    self.ip_data[ip]["status"] = "BLOCKED"
                    self._refresh_row(ip)
            else:
                messagebox.showerror("iptables error", result.stderr.strip() or "Unknown error")
        except FileNotFoundError:
            messagebox.showerror("iptables not found", "iptables is not installed or not in PATH.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _on_select(self, event):
        selection = self.tree.selection()
        self.block_button.config(state="normal" if selection else "disabled")

    # ---------------- Queue polling ----------------

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.event_queue.get_nowait()

                if kind == "status":
                    self.status_label.config(text=payload)
                    self._log(payload)
                elif kind == "error":
                    self.status_label.config(text=f"Error: {payload}")
                    self._log(f"ERROR: {payload}")
                    messagebox.showerror("Error", payload)
                elif kind == "failed_attempt":
                    self._handle_failed_attempt(payload)
                elif kind == "brute_force_detected":
                    self._handle_brute_force(payload)
                elif kind == "successful_login":
                    self._log(f"Successful login: {payload['username']} from {payload['ip']}")

        except queue.Empty:
            pass

        self.root.after(300, self._poll_queue)

    # ---------------- Helpers ----------------

    def _handle_failed_attempt(self, payload):
        ip = payload["ip"]
        now_str = datetime.now().strftime("%H:%M:%S")

        if ip not in self.ip_data:
            self.ip_data[ip] = {
                "count": payload["count"], "usernames": payload["usernames"],
                "first_seen": now_str, "last_seen": now_str, "status": "Watching",
            }
        else:
            self.ip_data[ip]["count"] = payload["count"]
            self.ip_data[ip]["usernames"] = payload["usernames"]
            self.ip_data[ip]["last_seen"] = now_str

        self._refresh_row(ip)
        self._log(f"Failed login: user='{payload['username']}' from {ip} (attempt #{payload['count']} in window)")

    def _handle_brute_force(self, payload):
        ip = payload["ip"]
        if ip in self.ip_data:
            self.ip_data[ip]["status"] = "⚠ BRUTE FORCE"
            self._refresh_row(ip, flagged=True)

        self._log(f"⚠ BRUTE FORCE DETECTED from {ip} — {payload['count']} failed attempts, "
                   f"usernames tried: {', '.join(payload['usernames'])}")

        try:
            subprocess.run(["notify-send", "Brute-force attack detected!",
                             f"{ip} — {payload['count']} failed SSH attempts"], check=False, timeout=5)
        except Exception:
            pass

    def _refresh_row(self, ip, flagged=False):
        data = self.ip_data[ip]
        values = (ip, data["count"], ", ".join(sorted(data["usernames"])),
                  data["first_seen"], data["last_seen"], data["status"])
        tags = ("flagged",) if (flagged or data["status"] != "Watching") else ()

        if ip in self.ip_rows:
            self.tree.item(self.ip_rows[ip], values=values, tags=tags)
        else:
            item_id = self.tree.insert("", "end", values=values, tags=tags)
            self.ip_rows[ip] = item_id

    def _log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.config(state="disabled")


def main():
    root = tk.Tk()
    app = BruteForceDetectorApp(root)

    def on_close():
        if app.tail_thread:
            app.tail_thread.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
