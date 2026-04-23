# ZeroTrace

An autonomous web penetration testing tool powered by local AI models via Ollama.

## Overview

ZeroTrace runs a 6-tool recon pipeline against a target, feeds the output to a fine-tuned vulnerability analysis model, generates exploit suggestions, and produces a full PDF report — all locally, no cloud required.

## Stack

- **Backend:** Node.js / Express (port 3000)
- **Frontend:** Vanilla HTML / CSS / JS
- **AI inference:** Ollama (local LLM)
- **PDF generation:** pdfkit

## AI Models

| Purpose | Model |
|---|---|
| Vulnerability analysis | `zerotrace-v2:latest` (Foundation-Sec 8B) |
| Exploit generation | `zerotrace-deepseek:latest` (DeepSeek Coder 6.7B) |
| Report generation | `mistral:7b-instruct-q8_0` |

## Recon Pipeline

Tools run sequentially in this order:

1. **Nmap** — port scan and service detection
2. **Nuclei** — CVE and vulnerability template scanning
3. **FFuf** — directory and endpoint fuzzing
4. **SQLMap** — SQL injection detection
5. **JWT Tool** — JWT capture and analysis
6. **Metasploit** — auxiliary HTTP scanners (via RPC)

Plus an **API Scanner** and a second **Nuclei (Auth)** pass using any captured JWT.

## Project Structure

```
AI_Pentest_Windows/
├── backend/
│   ├── server.js              # Express server, all API endpoints
│   ├── sessions.js            # File-based session management
│   ├── sqlmap_wrapper.py      # SQLMap subprocess wrapper
│   ├── ai.js                  # Ollama inference helpers
│   ├── recon/
│   │   ├── runner.js          # Orchestrates all recon tools
│   │   ├── nmap.js
│   │   ├── nuclei.js
│   │   ├── ffuf.js
│   │   ├── sqlmap.js
│   │   ├── jwt.js
│   │   ├── apiScanner.js
│   │   └── utils.js
│   ├── analysis/              # Vulnerability analysis logic
│   ├── exploits/              # Exploit generation logic
│   └── reports/               # Report generation logic
├── frontend/
│   ├── index.html
│   ├── vulnerability-analysis.html
│   ├── exploit-generation.html
│   ├── dashboards.html
│   ├── library.html
│   ├── script.js
│   └── styles.css
├── sessions/                  # Session JSON files
├── reports/                   # Generated MD and PDF reports
└── logs/                      # Recon output logs
```

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/start-session` | Create a new scan session |
| POST | `/api/run-scan` | Run the 6-tool recon pipeline |
| POST | `/api/run-analysis` | Analyse recon output with zerotrace-v2 |
| POST | `/api/generate-exploits` | Generate exploits with zerotrace-deepseek |
| POST | `/api/generate-vuln-report` | Generate vulnerability PDF report |
| POST | `/api/generate-exploit-report` | Generate exploit PDF report |
| POST | `/api/create-exploit-session` | Create exploit session from uploaded vuln file |
| GET | `/api/sessions` | List all sessions |
| GET | `/api/session/:id` | Get session details |
| DELETE | `/api/session/:id` | Delete a session |
| GET | `/api/download-report/:id` | Download markdown report |
| GET | `/api/download-pdf/:id` | Download PDF report |
| GET | `/api/dashboards` | Aggregate stats per target |
| GET | `/api/dashboard/:target` | Detailed target dashboard |

## Prerequisites

- [Node.js](https://nodejs.org/) 18+
- [Ollama](https://ollama.com/download)
- [Nmap](https://nmap.org/)
- [Nuclei](https://github.com/projectdiscovery/nuclei)
- [FFuf](https://github.com/ffuf/ffuf)
- [SQLMap](https://sqlmap.org/)
- [JWT Tool](https://github.com/ticarpi/jwt_tool)
- [Python 3](https://www.python.org/downloads/) (required for SQLMap and JWT Tool)
- [Metasploit Framework](https://www.metasploit.com/) (optional — msfrpcd must be running)

## Installation Guide

### 1. Nmap
1. Go to https://nmap.org/download.html
2. Download the **Windows self-installer** (.exe)
3. Run the installer and follow the steps
4. Verify: open Command Prompt and run `nmap --version`

### 2. Nuclei
1. Go to https://github.com/projectdiscovery/nuclei/releases
2. Download `nuclei_windows_amd64.zip`
3. Extract it and move `nuclei.exe` to `C:\Windows\System32\`
4. Verify: `nuclei --version`

### 3. FFuf
1. Go to https://github.com/ffuf/ffuf/releases
2. Download `ffuf_windows_amd64.zip`
3. Extract it and move `ffuf.exe` to `C:\Windows\System32\`
4. Verify: `ffuf --version`

### 4. SQLMap
1. Make sure Python 3 is installed: https://www.python.org/downloads/
2. Run: `pip install sqlmap`
3. Verify: `sqlmap --version`

### 5. JWT Tool
1. Make sure Python 3 is installed
2. Run:
   ```
   pip install requests termcolor pycryptodomex
   git clone https://github.com/ticarpi/jwt_tool
   ```
3. The tool runs as a Python script — ZeroTrace calls it directly, no PATH setup needed

### 6. Ollama + AI Models
1. Download and install Ollama from https://ollama.com/download
2. Pull the required models:
   ```
   ollama pull zerotrace-v2:latest
   ollama pull zerotrace-deepseek:latest
   ollama pull mistral:7b-instruct-q8_0
   ```

### 7. Node.js
1. Download Node.js 18+ from https://nodejs.org/
2. Run the installer
3. Verify: `node --version`

## Setup

```bash
npm install
node backend/server.js
```

Then open `http://localhost:3000` in your browser.

### Metasploit RPC (optional)

```bash
msfrpcd -P zerotrace123 -a 127.0.0.1 -f
```

Environment variables to override defaults:

| Variable | Default |
|---|---|
| `MSF_RPC_HOST` | `127.0.0.1` |
| `MSF_RPC_PORT` | `55553` |
| `MSF_RPC_PASS` | `zerotrace123` |
| `MSF_RPC_SSL` | `true` |

## Usage

1. Go to **Vulnerability Analysis** and enter a target URL.
2. Run the recon scan and wait for all 6 tools to complete.
3. Run AI analysis to identify vulnerabilities.
4. Optionally generate exploit suggestions and a PDF report.
5. View past scans on the **Dashboards** page or browse saved reports in **Library**.

## Legal

ZeroTrace is intended for authorized penetration testing and security research only. Only use against systems you own or have explicit written permission to test.
