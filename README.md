# Virus Detection System

A Python-based antivirus-style desktop application built with Tkinter that scans directories, detects known test signatures, flags suspicious files using heuristics, and generates scan reports.

## Features

- Recursive folder scanning
- SHA-256 file hashing
- Signature-based detection for known test samples
- Heuristic suspicious-file detection
- Executable and script extension checks
- Large-file anomaly detection
- Access-denied handling
- Real-time scan progress
- Non-blocking background scanning
- CSV scan report generation
- Safe-by-default workflow with no automatic file deletion

## Tech Stack

- Python
- Tkinter
- hashlib
- pathlib
- CSV
- threading
- queue

## Project Structure

```text
Virus-Detection-System/
├── virus_detection.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Setup

### 1. Create a virtual environment

```powershell
python -m venv .venv
```

### 2. Activate it

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

No third-party packages are required. Tkinter is normally included with Python on Windows and many Linux distributions.

### 4. Run

```powershell
python virus_detection.py
```

## How It Works

```text
Select Folder
      ↓
Recursive File Discovery
      ↓
SHA-256 Hashing
      ↓
Signature Matching
      ↓
Heuristic Checks
      ↓
SAFE / SUSPICIOUS / INFECTED
      ↓
CSV Scan Report
```

## Detection Logic

The scanner first calculates a SHA-256 hash for each readable file and compares it with the project's test signature database. Files that do not match a known signature are evaluated with lightweight heuristics such as executable/script extensions and unusually large file sizes.

Heuristic matches are reported as **SUSPICIOUS**, not automatically classified as malware. This reduces false claims because an extension or file size alone cannot establish that a file is malicious.

## Safety

This project is intended for education and demonstration. It is not a replacement for professional antivirus or endpoint security software. The application does not automatically delete detected files.

## Resume Description

**Virus Detection System** — Built a Python/Tkinter antivirus-style scanner using SHA-256 signature matching and heuristic analysis to classify files, monitor scan progress asynchronously, handle restricted files, and generate CSV-based security reports.

## Future Improvements

- External threat-intelligence signature database
- Quarantine and restore workflow
- YARA rule integration
- PE file metadata analysis
- Digital-signature verification
- Unit and integration tests
- Machine-learning based malware classification
- Scheduled and background scans

## Dashboard Preview

Add a screenshot of the application here as `dashboard.png` to display a GitHub preview.
