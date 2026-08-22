# Port & Banner Grabber Scanner

A lightweight Python script that scans a given IP range for open TCP ports, grabs service banners, and saves results as JSON and an HTML report.

⚠️ **Use only against hosts you own or have explicit permission to scan.**

## Features

- TCP connect scan (multi-threaded, fast)
- Banner grabbing (reads responses from SSH, HTTP, and other services)
- Best-effort service name guessing for well-known ports (SSH, HTTP, RDP, MySQL, etc.)
- JSON export
- Styled HTML report
- `--common` flag to quickly scan the 25 most common ports

## Requirements

Python 3.10+. No external dependencies — uses only the Python standard library.

## Usage

```bash
# Single IP, port range
python3 port_scanner.py -t 192.168.1.10 -p 1-1024 -o results.json

# CIDR range + HTML report
python3 port_scanner.py -t 192.168.1.0/24 -p 1-1000 --html -o scan.json

# Quickly scan the most common ports
python3 port_scanner.py -t 192.168.1.10 --common --html -o scan.json
```

## Arguments

| Flag | Description |
|------|-------------|
| `-t`, `--targets` | IP, CIDR (`192.168.1.0/24`), or comma-separated list |
| `-p`, `--ports` | Port range, e.g. `22,80,443` or `1-1000` (default: `1-1024`) |
| `--common` | Scan only the 25 most common ports |
| `-o`, `--output` | Output JSON file |
| `-w`, `--workers` | Number of parallel threads (default: 200) |
| `--html` | Also generate an HTML report |

## Example Output

```
[+] 192.168.1.10:22 (SSH) OPEN  -> 'SSH-2.0-OpenSSH_10.3p1 Debian-5'
[+] 192.168.1.10:80 (HTTP) OPEN -> 'HTTP/1.1 200 OK ... Server: Apache/2.4.68'
[✓] Scan complete. Found 2 open port(s).
```

## License

Personal / educational project.
