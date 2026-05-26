"""
=============================================================
  VIRUS DETECTION SYSTEM WITH ADMIN LOGIN & REPORT GENERATOR
  Final Year Project | Python | Tkinter GUI
=============================================================
  Author  : Final Year Student
  Version : 2.0
  Description:
      A GUI-based antivirus simulation tool that allows an
      admin to log in, scan a folder for suspicious or
      infected files using hash-based and heuristic detection,
      generate a detailed scan report, and DELETE flagged files.
=============================================================
"""

import os
import hashlib
import csv
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime


# ─────────────────────────────────────────────
#  MODULE 1 — ADMIN AUTHENTICATION
# ─────────────────────────────────────────────

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "1234"


def authenticate(username: str, password: str) -> bool:
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD


# ─────────────────────────────────────────────
#  MODULE 2 — VIRUS SIGNATURE DATABASE
# ─────────────────────────────────────────────

VIRUS_SIGNATURES = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test Virus",
    "d41d8cd98f00b204e9800998ecf8427e": "Empty File Exploit",
    "098f6bcd4621d373cade4e832627b4f6": "TestMalware.A",
    "5d41402abc4b2a76b9719d911017c592": "FakeTrojan.B",
    "7215ee9c7d9dc229d2921a40e899ec5f": "Worm.Generic.X",
    "b14a7b8059d9c055954c92674ce60032": "Rootkit.Hidden.1",
}


def get_file_hash(file_path: str) -> str | None:
    hasher = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (PermissionError, OSError):
        return None


def check_signature(file_hash: str) -> str | None:
    return VIRUS_SIGNATURES.get(file_hash)


# ─────────────────────────────────────────────
#  MODULE 3 — HEURISTIC DETECTION
# ─────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".vbs", ".cmd", ".com", ".scr", ".pif", ".msi"}
MAX_SAFE_SIZE_MB = 50


def heuristic_check(file_path: str) -> str | None:
    _, ext = os.path.splitext(file_path)
    if ext.lower() in SUSPICIOUS_EXTENSIONS:
        return f"Suspicious extension ({ext})"
    try:
        size_mb = os.path.getsize(file_path) / (1024 * 1024)
        if size_mb > MAX_SAFE_SIZE_MB:
            return f"Unusual file size ({size_mb:.1f} MB)"
    except OSError:
        pass
    return None


# ─────────────────────────────────────────────
#  MODULE 4 — FILE SCANNER
# ─────────────────────────────────────────────

def scan_directory(folder_path: str, progress_callback=None) -> list[dict]:
    results = []
    all_files = []
    for root, _, files in os.walk(folder_path):
        for name in files:
            all_files.append(os.path.join(root, name))

    total = len(all_files)

    for index, file_path in enumerate(all_files):
        file_hash = get_file_hash(file_path)
        status = "SAFE"
        detail = "-"

        if file_hash is None:
            status = "ACCESS DENIED"
            detail = "Cannot read file"
        else:
            virus_name = check_signature(file_hash)
            if virus_name:
                status = "INFECTED"
                detail = virus_name
            else:
                reason = heuristic_check(file_path)
                if reason:
                    status = "SUSPICIOUS"
                    detail = reason

        results.append({
            "file": file_path,
            "hash": file_hash or "N/A",
            "status": status,
            "detail": detail,
            "deleted": False,          # ← NEW: track deletion state
        })

        if progress_callback:
            progress_callback(index + 1, total)

    return results


# ─────────────────────────────────────────────
#  MODULE 5 — REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_report(results: list[dict], output_path: str = "scan_report.csv") -> str:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total     = len(results)
    infected  = sum(1 for r in results if r["status"] == "INFECTED")
    suspicious= sum(1 for r in results if r["status"] == "SUSPICIOUS")
    safe      = sum(1 for r in results if r["status"] == "SAFE")
    deleted   = sum(1 for r in results if r.get("deleted"))

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["VIRUS DETECTION SYSTEM — SCAN REPORT"])
        writer.writerow(["Generated", timestamp])
        writer.writerow([])
        writer.writerow(["SUMMARY"])
        writer.writerow(["Total Files Scanned", total])
        writer.writerow(["Infected Files", infected])
        writer.writerow(["Suspicious Files", suspicious])
        writer.writerow(["Safe Files", safe])
        writer.writerow(["Deleted Files", deleted])       # ← NEW
        writer.writerow([])
        writer.writerow(["#", "File Path", "MD5 Hash", "Status", "Detail", "Deleted"])
        for i, r in enumerate(results, 1):
            writer.writerow([i, r["file"], r["hash"], r["status"],
                             r["detail"], "YES" if r.get("deleted") else "NO"])

    return os.path.abspath(output_path)


# ─────────────────────────────────────────────
#  MODULE 6 — TKINTER GUI
# ─────────────────────────────────────────────

class VirusDetectionApp:

    BG        = "#0d0f1a"
    PANEL     = "#141726"
    ACCENT    = "#00e5ff"
    DANGER    = "#ff3b3b"
    WARN      = "#ffb300"
    SAFE_CLR  = "#00e676"
    TEXT      = "#e0e6f0"
    MUTED     = "#5a6080"
    BORDER    = "#1e2540"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Virus Detection System")
        self.root.geometry("980x700")
        self.root.resizable(False, False)
        self.root.configure(bg=self.BG)

        self.scan_results: list[dict] = []
        # ── NEW: per-result checkbox variables (keyed by index) ──
        self._check_vars: dict[int, tk.BooleanVar] = {}

        self._build_login_screen()

    # ── SCREEN: Login ──────────────────────────────────────────

    def _build_login_screen(self):
        self._clear()

        outer = tk.Frame(self.root, bg=self.BG)
        outer.pack(expand=True)

        tk.Label(outer, text="🛡", font=("Segoe UI Emoji", 48),
                 bg=self.BG, fg=self.ACCENT).pack(pady=(0, 4))
        tk.Label(outer, text="VIRUS DETECTION SYSTEM",
                 font=("Courier New", 18, "bold"),
                 bg=self.BG, fg=self.ACCENT).pack()
        tk.Label(outer, text="Admin Access Portal",
                 font=("Courier New", 10),
                 bg=self.BG, fg=self.MUTED).pack(pady=(2, 28))

        card = tk.Frame(outer, bg=self.PANEL,
                        highlightbackground=self.BORDER,
                        highlightthickness=1)
        card.pack(ipadx=40, ipady=30)

        def field(label_text, show=""):
            tk.Label(card, text=label_text,
                     font=("Courier New", 9), bg=self.PANEL,
                     fg=self.MUTED, anchor="w").pack(fill="x", padx=20, pady=(12, 2))
            entry = tk.Entry(card, show=show,
                             font=("Courier New", 12),
                             bg="#0d0f1a", fg=self.TEXT,
                             insertbackground=self.ACCENT,
                             relief="flat",
                             highlightbackground=self.BORDER,
                             highlightthickness=1, bd=0)
            entry.pack(fill="x", padx=20, ipady=6)
            return entry

        self.username_entry = field("USERNAME")
        self.password_entry = field("PASSWORD", show="●")

        self.login_msg = tk.Label(card, text="",
                                  font=("Courier New", 9),
                                  bg=self.PANEL, fg=self.DANGER)
        self.login_msg.pack(pady=(8, 0))

        btn = tk.Button(card, text="LOGIN  →",
                        font=("Courier New", 11, "bold"),
                        bg=self.ACCENT, fg="#000",
                        activebackground="#00b8d4",
                        activeforeground="#000",
                        relief="flat", cursor="hand2",
                        command=self._attempt_login)
        btn.pack(fill="x", padx=20, pady=(18, 4), ipady=8)

        self.root.bind("<Return>", lambda e: self._attempt_login())

    def _attempt_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if authenticate(username, password):
            self.root.unbind("<Return>")
            self._build_dashboard()
        else:
            self.login_msg.config(text="⚠  Invalid credentials. Try again.")

    # ── SCREEN: Dashboard ──────────────────────────────────────

    def _build_dashboard(self):
        self._clear()

        # ── Top bar ──
        topbar = tk.Frame(self.root, bg=self.PANEL, height=52,
                          highlightbackground=self.BORDER,
                          highlightthickness=1)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        tk.Label(topbar, text="🛡  VIRUS DETECTION SYSTEM",
                 font=("Courier New", 13, "bold"),
                 bg=self.PANEL, fg=self.ACCENT).pack(side="left", padx=18)

        tk.Button(topbar, text="Logout",
                  font=("Courier New", 9),
                  bg=self.BORDER, fg=self.MUTED,
                  activebackground=self.DANGER,
                  activeforeground="#fff",
                  relief="flat", cursor="hand2",
                  command=self._logout).pack(side="right", padx=16, pady=12)

        # ── Body ──
        body = tk.Frame(self.root, bg=self.BG)
        body.pack(fill="both", expand=True, padx=18, pady=14)

        # ── Left panel — controls ──
        left = tk.Frame(body, bg=self.PANEL, width=240,
                        highlightbackground=self.BORDER,
                        highlightthickness=1)
        left.pack(side="left", fill="y", padx=(0, 12))
        left.pack_propagate(False)

        tk.Label(left, text="SCAN CONTROLS",
                 font=("Courier New", 9, "bold"),
                 bg=self.PANEL, fg=self.MUTED).pack(anchor="w", padx=16, pady=(16, 6))

        tk.Label(left, text="Target Directory",
                 font=("Courier New", 8),
                 bg=self.PANEL, fg=self.MUTED).pack(anchor="w", padx=16)

        path_frame = tk.Frame(left, bg=self.PANEL)
        path_frame.pack(fill="x", padx=16, pady=(4, 0))

        self.path_var = tk.StringVar()
        path_entry = tk.Entry(path_frame, textvariable=self.path_var,
                              font=("Courier New", 8),
                              bg=self.BG, fg=self.TEXT,
                              insertbackground=self.ACCENT,
                              relief="flat",
                              highlightbackground=self.BORDER,
                              highlightthickness=1, bd=0)
        path_entry.pack(side="left", fill="x", expand=True, ipady=5)

        tk.Button(path_frame, text="…",
                  font=("Courier New", 9, "bold"),
                  bg=self.ACCENT, fg="#000",
                  relief="flat", cursor="hand2",
                  command=self._browse_folder).pack(side="right", padx=(4, 0), ipady=5, ipadx=4)

        tk.Frame(left, bg=self.BORDER, height=1).pack(fill="x", padx=16, pady=16)

        self.scan_btn = tk.Button(left, text="▶  START SCAN",
                                  font=("Courier New", 11, "bold"),
                                  bg=self.ACCENT, fg="#000",
                                  activebackground="#00b8d4",
                                  relief="flat", cursor="hand2",
                                  command=self._start_scan)
        self.scan_btn.pack(fill="x", padx=16, ipady=10)

        tk.Label(left, text="Progress",
                 font=("Courier New", 8),
                 bg=self.PANEL, fg=self.MUTED).pack(anchor="w", padx=16, pady=(16, 4))

        self.progress_var = tk.DoubleVar()
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("cyber.Horizontal.TProgressbar",
                        troughcolor=self.BG,
                        background=self.ACCENT,
                        bordercolor=self.BORDER,
                        lightcolor=self.ACCENT,
                        darkcolor=self.ACCENT)

        self.progress_bar = ttk.Progressbar(left, variable=self.progress_var,
                                            maximum=100,
                                            style="cyber.Horizontal.TProgressbar")
        self.progress_bar.pack(fill="x", padx=16)

        self.progress_label = tk.Label(left, text="0 / 0 files",
                                       font=("Courier New", 8),
                                       bg=self.PANEL, fg=self.MUTED)
        self.progress_label.pack(anchor="w", padx=16, pady=2)

        tk.Frame(left, bg=self.BORDER, height=1).pack(fill="x", padx=16, pady=12)

        self.stat_total    = self._stat_row(left, "Total Scanned", "—")
        self.stat_infected = self._stat_row(left, "Infected",      "—", self.DANGER)
        self.stat_suspect  = self._stat_row(left, "Suspicious",    "—", self.WARN)
        self.stat_safe     = self._stat_row(left, "Safe",          "—", self.SAFE_CLR)
        self.stat_deleted  = self._stat_row(left, "Deleted",       "—", self.MUTED)   # ← NEW

        tk.Frame(left, bg=self.BORDER, height=1).pack(fill="x", padx=16, pady=12)

        # ── NEW: Delete selected button ──
        self.delete_btn = tk.Button(
            left,
            text="🗑  DELETE SELECTED",
            font=("Courier New", 10, "bold"),
            bg=self.BORDER, fg=self.MUTED,
            relief="flat", cursor="hand2",
            state="disabled",
            command=self._delete_selected
        )
        self.delete_btn.pack(fill="x", padx=16, ipady=8)

        tk.Frame(left, bg=self.BORDER, height=1).pack(fill="x", padx=16, pady=8)

        self.report_btn = tk.Button(left, text="📄  SAVE REPORT",
                                    font=("Courier New", 10, "bold"),
                                    bg=self.BORDER, fg=self.MUTED,
                                    relief="flat", cursor="hand2",
                                    state="disabled",
                                    command=self._save_report)
        self.report_btn.pack(fill="x", padx=16, ipady=8)

        # ── Right panel — results ──
        right = tk.Frame(body, bg=self.PANEL,
                         highlightbackground=self.BORDER,
                         highlightthickness=1)
        right.pack(side="right", fill="both", expand=True)

        # Header row with "Select All" checkbox
        header = tk.Frame(right, bg=self.PANEL)
        header.pack(fill="x", padx=14, pady=(12, 4))

        tk.Label(header, text="SCAN RESULTS",
                 font=("Courier New", 9, "bold"),
                 bg=self.PANEL, fg=self.MUTED).pack(side="left")

        # ── NEW: Select-all checkbox ──
        self._select_all_var = tk.BooleanVar(value=False)
        self._select_all_cb = tk.Checkbutton(
            header,
            text="Select All Threats",
            variable=self._select_all_var,
            font=("Courier New", 8),
            bg=self.PANEL, fg=self.WARN,
            selectcolor=self.BG,
            activebackground=self.PANEL,
            activeforeground=self.WARN,
            relief="flat",
            command=self._toggle_select_all,
            state="disabled"
        )
        self._select_all_cb.pack(side="right")

        # ── NEW: Scrollable frame for results (replaces ScrolledText) ──
        # We use a Canvas + inner Frame so we can embed real Checkbuttons.
        canvas_frame = tk.Frame(right, bg=self.BG)
        canvas_frame.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        self._canvas = tk.Canvas(canvas_frame, bg=self.BG,
                                 highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical",
                                  command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        self._results_frame = tk.Frame(self._canvas, bg=self.BG)
        self._canvas_window = self._canvas.create_window(
            (0, 0), window=self._results_frame, anchor="nw"
        )

        self._results_frame.bind("<Configure>", self._on_results_frame_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)
        # Mouse-wheel scrolling
        self._canvas.bind_all("<MouseWheel>",
                              lambda e: self._canvas.yview_scroll(-1 * (e.delta // 120), "units"))

    def _on_results_frame_configure(self, event):
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self._canvas.itemconfig(self._canvas_window, width=event.width)

    def _stat_row(self, parent, label, value, color=None):
        frame = tk.Frame(parent, bg=self.PANEL)
        frame.pack(fill="x", padx=16, pady=1)
        tk.Label(frame, text=label,
                 font=("Courier New", 8),
                 bg=self.PANEL, fg=self.MUTED).pack(side="left")
        val_label = tk.Label(frame, text=value,
                             font=("Courier New", 9, "bold"),
                             bg=self.PANEL, fg=color or self.TEXT)
        val_label.pack(side="right")
        return val_label

    # ── Actions ────────────────────────────────────────────────

    def _browse_folder(self):
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self.path_var.set(folder)

    def _start_scan(self):
        folder = self.path_var.get().strip()
        if not folder:
            messagebox.showwarning("No Path", "Please enter or select a folder path.")
            return
        if not os.path.isdir(folder):
            messagebox.showerror("Invalid Path", f"'{folder}' is not a valid directory.")
            return

        self.scan_btn.config(state="disabled")
        self.report_btn.config(state="disabled", bg=self.BORDER, fg=self.MUTED)
        self.delete_btn.config(state="disabled", bg=self.BORDER, fg=self.MUTED)
        self._select_all_cb.config(state="disabled")
        self.progress_var.set(0)
        self._check_vars.clear()
        self._clear_results_frame()

        self.scan_results = scan_directory(folder, self._update_progress)
        self._display_results()

    def _update_progress(self, done: int, total: int):
        pct = (done / total * 100) if total else 0
        self.progress_var.set(pct)
        self.progress_label.config(text=f"{done} / {total} files")
        self.root.update_idletasks()

    def _display_results(self):
        results = self.scan_results
        total      = len(results)
        infected   = sum(1 for r in results if r["status"] == "INFECTED")
        suspicious = sum(1 for r in results if r["status"] == "SUSPICIOUS")
        safe       = sum(1 for r in results if r["status"] == "SAFE")
        has_threats= infected + suspicious > 0

        COLOR_MAP = {
            "INFECTED":     self.DANGER,
            "SUSPICIOUS":   self.WARN,
            "SAFE":         self.SAFE_CLR,
            "ACCESS DENIED":self.MUTED,
        }
        ICON_MAP = {
            "INFECTED":     "🔴",
            "SUSPICIOUS":   "🟡",
            "SAFE":         "🟢",
            "ACCESS DENIED":"⚫",
        }

        for idx, r in enumerate(results):
            status = r["status"]
            color  = COLOR_MAP.get(status, self.TEXT)
            icon   = ICON_MAP.get(status, "⚫")
            is_threat = status in ("INFECTED", "SUSPICIOUS")

            row = tk.Frame(self._results_frame, bg=self.BG)
            row.pack(fill="x", padx=4, pady=1)

            # ── NEW: Checkbox (only for threats) ──
            var = tk.BooleanVar(value=False)
            self._check_vars[idx] = var

            cb = tk.Checkbutton(
                row,
                variable=var,
                bg=self.BG,
                activebackground=self.BG,
                selectcolor="#1a1f35",
                relief="flat",
                state="normal" if is_threat else "disabled",
                command=self._on_checkbox_change
            )
            cb.pack(side="left", padx=(2, 0))

            # Status icon + label
            tk.Label(row, text=f"{icon} [{status:<13}]",
                     font=("Courier New", 9, "bold"),
                     bg=self.BG, fg=color,
                     width=22, anchor="w").pack(side="left", padx=(4, 6))

            # File path (truncated with tooltip via wraplength)
            short = r["file"]
            if len(short) > 52:
                short = "…" + short[-52:]

            file_lbl = tk.Label(row, text=short,
                                font=("Courier New", 8),
                                bg=self.BG, fg=self.TEXT,
                                anchor="w")
            file_lbl.pack(side="left", fill="x", expand=True)

            # Detail badge for threats
            if is_threat:
                tk.Label(row, text=r["detail"],
                         font=("Courier New", 8),
                         bg="#1a0a0a" if status == "INFECTED" else "#1a1500",
                         fg=color,
                         padx=6, pady=2).pack(side="right", padx=8)

            # Store references for later strikethrough effect
            r["_row"]      = row
            r["_file_lbl"] = file_lbl

        # ── Summary row ──
        sep = tk.Frame(self._results_frame, bg=self.BORDER, height=1)
        sep.pack(fill="x", padx=4, pady=8)

        summary = tk.Frame(self._results_frame, bg=self.BG)
        summary.pack(fill="x", padx=8, pady=(0, 8))
        tk.Label(summary,
                 text=f"  Scan complete — {total} files  |  "
                      f"🔴 {infected} infected  |  🟡 {suspicious} suspicious  |  🟢 {safe} safe",
                 font=("Courier New", 9, "bold"),
                 bg=self.BG, fg=self.ACCENT).pack(anchor="w")

        # Update sidebar
        self.stat_total.config(text=str(total))
        self.stat_infected.config(text=str(infected))
        self.stat_suspect.config(text=str(suspicious))
        self.stat_safe.config(text=str(safe))
        self.stat_deleted.config(text="0")

        self.scan_btn.config(state="normal")
        if results:
            self.report_btn.config(state="normal", bg=self.ACCENT, fg="#000")
        if has_threats:
            self.delete_btn.config(state="normal", bg=self.DANGER, fg="#fff")
            self._select_all_cb.config(state="normal")

    # ── NEW: Select-all toggle ──────────────────────────────────

    def _toggle_select_all(self):
        select = self._select_all_var.get()
        for idx, r in enumerate(self.scan_results):
            if r["status"] in ("INFECTED", "SUSPICIOUS") and not r.get("deleted"):
                self._check_vars[idx].set(select)

    def _on_checkbox_change(self):
        # Keep "select all" in sync
        threat_indices = [
            idx for idx, r in enumerate(self.scan_results)
            if r["status"] in ("INFECTED", "SUSPICIOUS") and not r.get("deleted")
        ]
        all_checked = all(self._check_vars[i].get() for i in threat_indices) if threat_indices else False
        self._select_all_var.set(all_checked)

    # ── NEW: Delete selected files ──────────────────────────────

    def _delete_selected(self):
        to_delete = [
            (idx, r)
            for idx, r in enumerate(self.scan_results)
            if self._check_vars.get(idx, tk.BooleanVar()).get()
               and not r.get("deleted")
        ]

        if not to_delete:
            messagebox.showinfo("Nothing Selected",
                                "Please check the boxes next to files you want to delete.")
            return

        count = len(to_delete)
        confirm = messagebox.askyesno(
            "Confirm Deletion",
            f"⚠  You are about to permanently delete {count} file(s).\n\n"
            + "\n".join(f"  • {r['file']}" for _, r in to_delete[:10])
            + (f"\n  … and {count - 10} more" if count > 10 else "")
            + "\n\nThis action CANNOT be undone. Proceed?",
            icon="warning"
        )
        if not confirm:
            return

        deleted_ok = 0
        failed = []

        for idx, r in to_delete:
            try:
                os.remove(r["file"])
                r["deleted"] = True
                deleted_ok += 1
                # ── Visual feedback: strike-through style ──
                if "_file_lbl" in r:
                    r["_file_lbl"].config(
                        fg=self.MUTED,
                        font=("Courier New", 8, "overstrike")
                    )
                if "_row" in r:
                    r["_row"].config(bg="#0d0f1a")
                # Uncheck and disable checkbox
                self._check_vars[idx].set(False)
            except (PermissionError, OSError, FileNotFoundError) as e:
                failed.append((r["file"], str(e)))

        # Update deleted stat
        total_deleted = sum(1 for r in self.scan_results if r.get("deleted"))
        self.stat_deleted.config(text=str(total_deleted))

        # Re-evaluate delete button / select-all state
        remaining_threats = [
            idx for idx, r in enumerate(self.scan_results)
            if r["status"] in ("INFECTED", "SUSPICIOUS") and not r.get("deleted")
        ]
        if not remaining_threats:
            self.delete_btn.config(state="disabled", bg=self.BORDER, fg=self.MUTED)
            self._select_all_cb.config(state="disabled")
        self._select_all_var.set(False)

        # Summary popup
        if failed:
            fail_msg = "\n".join(f"  ✖ {f[0]}\n     ({f[1]})" for f in failed)
            messagebox.showwarning(
                "Partial Deletion",
                f"✔ {deleted_ok} file(s) deleted successfully.\n"
                f"✖ {len(failed)} file(s) could not be deleted:\n\n{fail_msg}"
            )
        else:
            messagebox.showinfo(
                "Deletion Complete",
                f"✔ {deleted_ok} file(s) deleted successfully."
            )

    # ── Other actions ──────────────────────────────────────────

    def _save_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="scan_report.csv",
            title="Save Scan Report"
        )
        if not path:
            return
        saved = generate_report(self.scan_results, output_path=path)
        messagebox.showinfo("Report Saved", f"Report saved to:\n{saved}")

    def _logout(self):
        self.scan_results = []
        self._check_vars.clear()
        self._build_login_screen()

    # ── Helpers ────────────────────────────────────────────────

    def _clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def _clear_results_frame(self):
        for widget in self._results_frame.winfo_children():
            widget.destroy()


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

def main():
    root = tk.Tk()
    app = VirusDetectionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
