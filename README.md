<div align="center">

# 🛡️ Real-Time Process Virus Scanner

<img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/VirusTotal-API%20v3-394EFF?style=for-the-badge&logo=virustotal&logoColor=white"/>
<img src="https://img.shields.io/badge/psutil-cross--platform-orange?style=for-the-badge&logo=windows&logoColor=white"/>
<img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=for-the-badge"/>
<img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge"/>

**Scan every running process on your system against VirusTotal's multi-engine database — one by one, in real time.**

</div>

---

## 📌 Overview

**Real-Time Process Virus Scanner** is a Python-based security tool that enumerates all currently running processes on your machine, calculates their SHA-256 hashes, and checks them against the [VirusTotal API v3](https://developers.virustotal.com/reference/overview) — the world's largest aggregated antivirus database (70+ engines).

If a file is already known to VirusTotal, results are returned instantly. If not, the file is uploaded and scanned live. Detected threats are reported with full engine-level details, direct VirusTotal links, and an optional process termination prompt.

> ⚠️ **For legitimate security research and personal system protection only.**

---

## ✨ Features

### 🔍 Full Process Enumeration
- Uses `psutil` to list every running process with an accessible executable
- Gracefully skips protected, zombie, or unreachable processes

### 🧮 SHA-256 Hash Fingerprinting
- Calculates cryptographic SHA-256 hashes for all scanned binaries
- Enables fast database lookups — no unnecessary uploads

### 🌐 VirusTotal API v3 Integration
- **Hash lookup first** — checks the VT database before uploading
- **Auto-upload** if the file is new or unknown to VirusTotal
- Polls for analysis completion with configurable retry logic

### 📊 Engine-Level Detection Report
- Shows malicious/suspicious counts per file
- Lists the top 5 flagging AV engines and their verdict
- Provides a direct permalink to the full VirusTotal report

### 🚨 Threat Response System
- Prompts user action on each detected threat:
  - `1` — Keep process running
  - `2` — Terminate (with fallback force-kill via `SIGKILL`)
  - `3` — Manual investigation with VT link
- Graceful termination → escalates to force kill if needed

### ⏱️ Rate Limit Aware
- Automatically pauses every 4 requests to respect the free API limit (4 req/min)
- Configurable buffer between batches to prevent 429 errors

### 🖥️ Admin Privilege Detection (Windows)
- Warns if not running as Administrator via `ctypes`
- Ensures maximum process accessibility for system-level binaries

---

## 🛠️ Tech Stack

| Library | Purpose |
|---------|---------|
| `psutil` | Process enumeration and management |
| `requests` | VirusTotal API communication |
| `hashlib` | SHA-256 file fingerprinting |
| `os` / `sys` | System path and runtime control |
| `time` | Rate limiting and polling delays |

---

## 📂 Project Structure

```
📁 process-virus-scanner/
│
├── Run-Time-scaning.py           # Main scanner script
├── requirements.txt     # Python dependencies
└── README.md            # Documentation
```

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/process-virus-scanner.git
cd process-virus-scanner
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Get a VirusTotal API Key

1. Register at [virustotal.com](https://www.virustotal.com/gui/join-us)
2. Go to your profile → **API Key**
3. Copy your free API key

---

## ▶️ Running the Scanner

### Windows (Recommended: Run as Administrator)

```bash
# Right-click terminal → "Run as administrator", then:
python Run-Time-scaning.py
```

### Linux / macOS

```bash
sudo python3 Run-Time-scaning.py
```

> Running with elevated privileges ensures access to system-level processes. Without it, some executables may be skipped due to permission restrictions.

---

## 📋 requirements.txt

```
psutil>=5.9.0
requests>=2.28.0
```

---

## 🔄 How It Works

```
Start
  │
  ├─► Enumerate all running processes via psutil
  │
  ├─► For each process:
  │     ├─► Calculate SHA-256 hash of the executable
  │     ├─► Query VirusTotal (hash lookup)
  │     │
  │     ├─► [Found in DB] ──► Parse detection stats
  │     │                     └─► Flag if malicious > 0
  │     │
  │     └─► [Not Found]  ──► Upload file to VirusTotal
  │                          └─► Poll for analysis result
  │                              └─► Flag if malicious > 0
  │
  ├─► Rate limit: pause every 4 requests (free API)
  │
  └─► Final report: list flagged processes + action prompts
```

---

## 📊 Sample Output

```
============================================================
VIRUSTOTAL PROCESS SCANNER
Scanning running processes for viruses...
============================================================

[1] Gathering running processes...
Found 87 processes with executable files

[2] Starting virus scan (one by one)...

============================================================
[1/87] Analyzing: chrome.exe (PID: 4821)
Path: C:\Program Files\Google\Chrome\Application\chrome.exe
  Hash: 3a1f8c2d9b7e4f01...
  Checking VirusTotal database...
  ✓ Found in VirusTotal database
  Scan Results:
    - Malicious: 0
    - Suspicious: 0
    - Total Scanners: 72

  ✅ Clean - No viruses detected

============================================================
[12/87] Analyzing: suspicious.exe (PID: 9134)
Path: C:\Users\User\AppData\Roaming\suspicious.exe
  Hash: d4e9a7c2f1b83e56...
  Checking VirusTotal database...
  ✓ Found in VirusTotal database
  Scan Results:
    - Malicious: 34
    - Suspicious: 5
    - Total Scanners: 71
  Detected by:
      • Kaspersky: Trojan.Win32.Generic
      • Malwarebytes: Malware.Trojan.Agent
      • Windows Defender: Trojan:Win32/Wacatac.B!ml
      • BitDefender: Gen:Variant.Jaik.66048
      • ESET-NOD32: A Variant Of Win32/GenKryptik

  🚨 VIRUS DETECTED! 34 engines flagged this as malware!
  Details: https://www.virustotal.com/gui/file/d4e9a7c2f1b83e56...
```

---

## ⚙️ Configuration

You can adjust the following constants directly in `Run-Time-scaning.py`:

| Constant | Default | Description |
|----------|---------|-------------|
| `timeout` (check) | `30s` | HTTP request timeout for hash lookup |
| `timeout` (upload) | `60s` | File upload timeout |
| Poll attempts | `12` | Max retries waiting for analysis |
| Poll interval | `5s` | Seconds between each poll attempt |
| Rate limit batch | `4` | Requests before triggering pause |
| Rate limit wait | `16s` | Pause duration (free API buffer) |

---

## ⚠️ Limitations

| Limitation | Detail |
|------------|--------|
| **Free API Rate Limit** | 4 requests/minute — full scan may take 15–30 minutes |
| **File Size Cap** | VirusTotal free tier: 32MB max per upload |
| **Protected Processes** | Kernel/system processes require admin/root access |
| **False Positives** | Packed or obfuscated legitimate software may trigger AV detections |
| **Network Dependency** | All lookups and uploads require active internet |

---

## 🔒 Security & Privacy Notice

- **File uploads** are sent to VirusTotal and may be shared with partner AV vendors
- **Do not scan** files containing personal data or proprietary source code
- Use a **dedicated VM or analysis machine** when scanning unknown binaries
- This tool is intended for **personal/research use** — not a replacement for enterprise AV solutions
---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

<div align="center">

Built for defenders. 🛡️ Use responsibly.

</div>
