# Virus Detection System

An educational Python project that scans a selected directory and classifies files using:

- SHA-256 signature matching
- Simple heuristic checks for executable/script extensions
- File-size anomaly checks
- A Tkinter desktop GUI
- CSV scan reports

> **Disclaimer:** This is an educational antivirus-style project, not a replacement for professional endpoint security software. Heuristic matches are not proof that a file is malicious.

## Features

- Select and recursively scan a folder
- SHA-256 hashing for readable files
- Signature-based detection
- Suspicious-file classification
- Access-denied handling
- Background scanning so the GUI remains responsive
- Progress tracking
- Export results to CSV

## Project Structure

```
Virus-Detection-System/
├── virus_detection.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Requirements

- Python 3.10 or newer
- Tkinter (usually included with Python)

No third-party packages are required.

## Run

```bash
python virus_detection.py
```

## Detection Logic

The scanner calculates a SHA-256 hash for each readable file and compares it with the project's signature database. Files that do not match a signature are checked using simple heuristics.

Because extensions and file sizes alone do not prove malware, heuristic matches are labeled **SUSPICIOUS**, not **INFECTED**.

## Safety

The application does not automatically delete files. Review suspicious results carefully before taking any action outside the application.

## Future Improvements

- External signature database
- File quarantine with restore support
- Digital-signature inspection
- Unit tests
- Better malware-classification models
- Scheduled scans

## License

Educational project.
