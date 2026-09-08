from __future__ import annotations

import csv
import hashlib
import queue
import threading
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Callable
import tkinter as tk
from tkinter import filedialog, messagebox, ttk


# Educational signature entries. Add verified SHA-256 signatures here.
SIGNATURES: dict[str, str] = {}
SUSPICIOUS_EXTENSIONS = {".exe", ".bat", ".cmd", ".vbs", ".scr", ".com", ".pif", ".ps1"}
MAX_SIZE_MB = 100


@dataclass
class ScanResult:
    file: str
    sha256: str
    status: str
    detail: str


def file_sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def heuristic_check(path: Path) -> str | None:
    if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
        return f"Suspicious executable/script extension: {path.suffix}"
    try:
        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > MAX_SIZE_MB:
            return f"Unusually large file: {size_mb:.1f} MB"
    except OSError:
        return "Unable to inspect file metadata"
    return None


def scan_directory(folder: str, progress: Callable[[int, int], None] | None = None) -> list[ScanResult]:
    paths = [p for p in Path(folder).rglob("*") if p.is_file()]
    results: list[ScanResult] = []
    total = len(paths)

    for index, path in enumerate(paths, start=1):
        digest = file_sha256(path)
        if digest is None:
            result = ScanResult(str(path), "N/A", "ACCESS DENIED", "Cannot read file")
        elif digest in SIGNATURES:
            result = ScanResult(str(path), digest, "INFECTED", SIGNATURES[digest])
        else:
            reason = heuristic_check(path)
            result = ScanResult(str(path), digest, "SUSPICIOUS" if reason else "SAFE", reason or "-")

        results.append(result)
        if progress:
            progress(index, total)

    return results


def save_report(results: list[ScanResult], output: str) -> str:
    with open(output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["file", "sha256", "status", "detail"])
        writer.writeheader()
        writer.writerows(asdict(result) for result in results)
    return str(Path(output).resolve())


class VirusDetectionApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Virus Detection System")
        self.geometry("1000x650")
        self.minsize(850, 550)

        self.results: list[ScanResult] = []
        self.events: queue.Queue = queue.Queue()
        self.path_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Choose a folder to begin.")
        self.progress_var = tk.DoubleVar(value=0)

        self._build_ui()
        self.after(100, self._process_events)

    def _build_ui(self) -> None:
        controls = ttk.Frame(self, padding=12)
        controls.pack(fill="x")

        ttk.Label(controls, text="Target folder:").pack(side="left")
        ttk.Entry(controls, textvariable=self.path_var, width=70).pack(side="left", padx=8, fill="x", expand=True)
        ttk.Button(controls, text="Browse", command=self._browse).pack(side="left")
        self.scan_button = ttk.Button(controls, text="Start Scan", command=self._start_scan)
        self.scan_button.pack(side="left", padx=(8, 0))

        self.progress = ttk.Progressbar(self, variable=self.progress_var, maximum=100)
        self.progress.pack(fill="x", padx=12)
        ttk.Label(self, textvariable=self.status_var, padding=(12, 6)).pack(anchor="w")

        columns = ("file", "status", "detail", "sha256")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
        for column, width in (("file", 420), ("status", 120), ("detail", 220), ("sha256", 190)):
            self.tree.heading(column, text=column.upper())
            self.tree.column(column, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        bottom = ttk.Frame(self, padding=12)
        bottom.pack(fill="x")
        self.report_button = ttk.Button(bottom, text="Save CSV Report", command=self._save_report, state="disabled")
        self.report_button.pack(side="right")

    def _browse(self) -> None:
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self.path_var.set(folder)

    def _start_scan(self) -> None:
        folder = self.path_var.get().strip()
        if not folder or not Path(folder).is_dir():
            messagebox.showerror("Invalid folder", "Please select a valid folder.")
            return

        self.results.clear()
        self.tree.delete(*self.tree.get_children())
        self.progress_var.set(0)
        self.scan_button.config(state="disabled")
        self.report_button.config(state="disabled")
        self.status_var.set("Scanning...")

        threading.Thread(target=self._scan_worker, args=(folder,), daemon=True).start()

    def _scan_worker(self, folder: str) -> None:
        def progress(done: int, total: int) -> None:
            self.events.put(("progress", done, total))

        try:
            self.events.put(("complete", scan_directory(folder, progress)))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def _process_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "progress":
                    _, done, total = event
                    self.progress_var.set(100 if total == 0 else done * 100 / total)
                    self.status_var.set(f"Scanned {done} / {total} files")
                elif event[0] == "complete":
                    self.results = event[1]
                    for result in self.results:
                        self.tree.insert("", "end", values=(result.file, result.status, result.detail, result.sha256))
                    infected = sum(r.status == "INFECTED" for r in self.results)
                    suspicious = sum(r.status == "SUSPICIOUS" for r in self.results)
                    self.status_var.set(f"Scan complete: {len(self.results)} files | Infected: {infected} | Suspicious: {suspicious}")
                    self.scan_button.config(state="normal")
                    self.report_button.config(state="normal" if self.results else "disabled")
                elif event[0] == "error":
                    self.status_var.set("Scan failed.")
                    self.scan_button.config(state="normal")
                    messagebox.showerror("Scan error", event[1])
        except queue.Empty:
            pass
        self.after(100, self._process_events)

    def _save_report(self) -> None:
        if not self.results:
            return
        filename = f"scan_report_{datetime.now():%Y%m%d_%H%M%S}.csv"
        output = filedialog.asksaveasfilename(
            title="Save scan report",
            defaultextension=".csv",
            initialfile=filename,
            filetypes=[("CSV files", "*.csv")],
        )
        if output:
            try:
                save_report(self.results, output)
                messagebox.showinfo("Report saved", f"Saved to:\n{Path(output).resolve()}")
            except OSError as exc:
                messagebox.showerror("Report error", str(exc))


if __name__ == "__main__":
    VirusDetectionApp().mainloop()
