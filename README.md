# 🔍 Port & Banner Grabber Scanner

A lightweight Python script that scans a given IP range for open TCP ports, grabs service banners, and saves the results as JSON and a styled HTML report.

> ⚠️ **Use only against hosts you own or have explicit permission to scan.** Unauthorized scanning may be illegal in your jurisdiction.

![Scan report screenshot](docs/html-report.png)

---

## Features

- **TCP connect scan** — multi-threaded, fast
- **Banner grabbing** — reads responses from SSH, HTTP, and other services
- **Service name guessing** — best-effort mapping for well-known ports (SSH, HTTP, RDP, MySQL, etc.)
- **JSON export** — machine-readable results
- **Styled HTML report** — dark-themed, easy to read
- **Auto-open report** — the HTML report opens automatically in your default browser when generated (`--no-open` to disable)
- **`--common` flag** — quickly scan the 27 most common ports instead of a full range

## Requirements

- Python 3.10+
- No external dependencies — uses only the Python standard library

## Installation

```bash
git clone https://github.com/umidguluzada/network-scanner.git
cd network-scanner
```

That's it — no `pip install` needed.

## Usage

```bash
# Single IP, port range
python3 port_scanner.py -t 192.168.1.10 -p 1-1024 -o results.json

# CIDR range + HTML report (opens in browser automatically)
python3 port_scanner.py -t 192.168.1.0/24 -p 1-1000 --html -o scan.json

# Quickly scan the most common ports
python3 port_scanner.py -t 192.168.1.10 --common --html -o scan.json

# Scan specific ports only
python3 port_scanner.py -t 192.168.1.10 -p 22,80,443 --html -o scan.json

# Scan a comma-separated list of targets
python3 port_scanner.py -t 192.168.1.10,192.168.1.20,10.0.0.5 --common -o scan.json

# Generate the HTML report but do NOT auto-open it in the browser
python3 port_scanner.py -t 192.168.1.10 --common --html -o scan.json --no-open

# Increase thread count for a faster scan on larger ranges
python3 port_scanner.py -t 192.168.1.0/24 --common -w 500 -o scan.json
```

## Arguments

| Flag | Description |
|---|---|
| `-t`, `--targets` | **(required)** IP, CIDR (`192.168.1.0/24`), or comma-separated list of targets |
| `-p`, `--ports` | Port range, e.g. `22,80,443` or `1-1000` (default: `1-1024`, ignored if `--common` is used) |
| `--common` | Scan only the 27 most common ports (SSH, HTTP, HTTPS, RDP, MySQL, etc.) instead of a range |
| `-o`, `--output` | Output JSON filename (default: `scan_results.json`) |
| `-w`, `--workers` | Number of parallel threads (default: `200`) |
| `--html` | Also generate a styled HTML report next to the JSON output |
| `--no-open` | Skip auto-opening the HTML report in the browser (only relevant with `--html`) |

## Example Output

```
[*] Starting scan: 1 host x 1024 port = 1024 tasks...
[+] 192.168.1.10:22 (SSH) OPEN  -> 'SSH-2.0-OpenSSH_10.3p1 Debian-5'
[+] 192.168.1.10:80 (HTTP) OPEN -> 'HTTP/1.1 200 OK ... Server: Apache/2.4.68'
[*] Results saved to: results.json
[*] HTML report saved to: results.html
[*] Opened report in browser: /home/kali/network-scanner/results.html

[✓] Scan complete. Found 2 open port(s).
```

## Project Structure

```
network-scanner/
├── port_scanner.py     # Main script — scan logic, JSON + HTML report generation
├── README.md            # This file
├── LICENSE               # MIT License
├── .gitignore            # Ignores scan output (*.json, *.html) and Python cache/venv files
└── docs/
    └── screenshot.png    # HTML report screenshot used above
```

> **Note:** Scan output files (`*.json`, `*.html`) are excluded from version control via `.gitignore` — each scan run generates fresh, host-specific data that shouldn't be committed.

## License

This project is licensed under the [MIT License](LICENSE) — free to use, modify, and distribute for personal or educational purposes.
