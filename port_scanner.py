#!/usr/bin/env python3
"""
Network Port & Banner Grabber Scanner
--------------------------------------
TCP connect scan + banner grabbing + JSON output + optional HTML report.
Use only against hosts you own or have explicit permission to scan.
"""

import socket
import json
import ipaddress
import argparse
import html
import os
import webbrowser
import concurrent.futures
from datetime import datetime

DEFAULT_TIMEOUT = 1.5   # socket connect timeout (seconds)
BANNER_TIMEOUT = 2.0    # extra wait time for reading the banner

# Well-known ports -> likely service name (best-effort guess, not authoritative)
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle DB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}


def guess_service(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")


def common_ports_list() -> list[int]:
    """Returns the well-known ports as a sorted list, for use with --common."""
    return sorted(COMMON_PORTS.keys())


def parse_ports(port_str: str) -> list[int]:
    """Supports formats like '22,80,443' or '1-1000'."""
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def parse_targets(target_str: str) -> list[str]:
    """Supports a single IP, CIDR (192.168.1.0/24), or a comma-separated list."""
    targets = []
    for part in target_str.split(","):
        part = part.strip()
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            targets.extend(str(ip) for ip in net.hosts())
        else:
            targets.append(part)
    return targets


def grab_banner(sock: socket.socket) -> str:
    """Tries to read a banner from an open port (including a probe for silent services like HTTP)."""
    try:
        sock.settimeout(BANNER_TIMEOUT)
        data = sock.recv(1024)
        if data:
            return data.decode(errors="replace").strip()
    except socket.timeout:
        pass
    except OSError:
        pass

    try:
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        sock.settimeout(BANNER_TIMEOUT)
        data = sock.recv(1024)
        return data.decode(errors="replace").strip()
    except OSError:
        return ""


def scan_port(ip: str, port: int) -> dict | None:
    """Scans a single (ip, port) pair. Returns a result dict if open, otherwise None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(DEFAULT_TIMEOUT)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(sock)
                return {
                    "ip": ip,
                    "port": port,
                    "state": "open",
                    "service": guess_service(port),
                    "banner": banner,
                }
    except (socket.gaierror, OSError):
        return None
    return None


def run_scan(targets: list[str], ports: list[int], max_workers: int = 200) -> list[dict]:
    results = []
    tasks = [(ip, port) for ip in targets for port in ports]
    print(f"[*] Starting scan: {len(targets)} host x {len(ports)} port = {len(tasks)} tasks...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port): (ip, port) for ip, port in tasks}
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            res = future.result()
            if res:
                print(f"[+] {res['ip']}:{res['port']} ({res['service']}) OPEN  -> {res['banner'][:80]!r}")
                results.append(res)
            if i % 500 == 0:
                print(f"    ... {i}/{len(tasks)} checked")

    # Sort for a nicer report: by IP, then port
    results.sort(key=lambda r: (socket.inet_aton(r["ip"]), r["port"]))
    return results


def save_json(results: list[dict], filename: str):
    output = {
        "scan_time": datetime.now().isoformat(),
        "total_open_ports": len(results),
        "results": results,
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"[*] Results saved to: {filename}")


def save_html(results: list[dict], filename: str, targets: list[str], ports: list[int]):
    """Renders the scan results as a simple standalone HTML report."""
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = ""
    if results:
        for r in results:
            banner_escaped = html.escape(r["banner"]) if r["banner"] else "<em>(no banner)</em>"
            rows += f"""
            <tr>
                <td>{html.escape(r['ip'])}</td>
                <td>{r['port']}</td>
                <td>{html.escape(r.get('service', 'unknown'))}</td>
                <td><span class="badge">OPEN</span></td>
                <td><code>{banner_escaped}</code></td>
            </tr>"""
    else:
        rows = '<tr><td colspan="5" class="empty">No open ports found.</td></tr>'

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Port Scan Report</title>
<style>
    body {{
        font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif;
        background: #0f1117;
        color: #e6e6e6;
        margin: 0;
        padding: 40px;
    }}
    .container {{ max-width: 900px; margin: 0 auto; }}
    h1 {{ font-size: 22px; margin-bottom: 4px; }}
    .meta {{ color: #9aa0a6; font-size: 13px; margin-bottom: 24px; }}
    table {{
        width: 100%;
        border-collapse: collapse;
        background: #171a21;
        border-radius: 8px;
        overflow: hidden;
    }}
    th, td {{
        text-align: left;
        padding: 10px 14px;
        border-bottom: 1px solid #262a33;
        font-size: 14px;
    }}
    th {{
        background: #1e2229;
        color: #9aa0a6;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 11px;
        letter-spacing: 0.5px;
    }}
    tr:last-child td {{ border-bottom: none; }}
    .badge {{
        background: #1e4620;
        color: #4ade80;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 600;
    }}
    code {{
        color: #93c5fd;
        font-size: 12px;
        word-break: break-all;
    }}
    .empty {{ text-align: center; color: #9aa0a6; padding: 24px; }}
    .summary {{
        display: flex;
        gap: 24px;
        margin-bottom: 20px;
    }}
    .summary div {{
        background: #171a21;
        border-radius: 8px;
        padding: 12px 20px;
    }}
    .summary .num {{ font-size: 22px; font-weight: 700; }}
    .summary .label {{ font-size: 12px; color: #9aa0a6; }}
</style>
</head>
<body>
<div class="container">
    <h1>🔍 Network Port Scan Report</h1>
    <div class="meta">
        Generated: {scan_time} &nbsp;|&nbsp;
        Targets: {len(targets)} host(s) &nbsp;|&nbsp;
        Ports scanned: {len(ports)}
    </div>

    <div class="summary">
        <div>
            <div class="num">{len(results)}</div>
            <div class="label">Open Ports Found</div>
        </div>
        <div>
            <div class="num">{len(targets)}</div>
            <div class="label">Hosts Scanned</div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>IP Address</th>
                <th>Port</th>
                <th>Service</th>
                <th>State</th>
                <th>Banner</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</div>
</body>
</html>"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(doc)
    print(f"[*] HTML report saved to: {filename}")


def open_in_browser(filename: str):
    """Opens the given HTML file in the system's default browser."""
    abs_path = os.path.abspath(filename)
    if not os.path.exists(abs_path):
        print(f"[!] Could not open report, file not found: {abs_path}")
        return

    try:
        opened = webbrowser.open(f"file://{abs_path}")
    except Exception as e:
        opened = False
        print(f"[!] Browser could not be launched: {e}")

    if opened:
        print(f"[*] Opened report in browser: {abs_path}")
    else:
        print(f"[i] Could not auto-open a browser (e.g. headless/SSH session).")
        print(f"    View the report manually at: {abs_path}")


def main():
    parser = argparse.ArgumentParser(description="TCP Connect Port & Banner Grabber Scanner")
    parser.add_argument("-t", "--targets", required=True,
                         help="IP, CIDR (192.168.1.0/24), or comma-separated list")
    parser.add_argument("-p", "--ports", default=None,
                         help="Port range, e.g. 22,80,443 or 1-1000 (default: 1-1024, unless --common is used)")
    parser.add_argument("-o", "--output", default="scan_results.json",
                         help="Output JSON file (default: scan_results.json)")
    parser.add_argument("-w", "--workers", type=int, default=200,
                         help="Number of parallel threads (default: 200)")
    parser.add_argument("--html", action="store_true",
                         help="Also generate an HTML report (report.html)")
    parser.add_argument("--no-open", action="store_true",
                         help="Do NOT auto-open the HTML report in the browser "
                              "(by default it opens automatically when --html is used)")
    parser.add_argument("--common", action="store_true",
                         help=f"Scan only the {len(COMMON_PORTS)} most common ports instead of a range "
                              "(fast preset: SSH, HTTP, HTTPS, RDP, MySQL, etc.)")
    args = parser.parse_args()

    targets = parse_targets(args.targets)

    if args.common:
        ports = common_ports_list()
    elif args.ports:
        ports = parse_ports(args.ports)
    else:
        ports = parse_ports("1-1024")

    results = run_scan(targets, ports, args.workers)
    save_json(results, args.output)

    if args.html:
        html_filename = args.output.rsplit(".", 1)[0] + ".html"
        save_html(results, html_filename, targets, ports)

        if not args.no_open:
            open_in_browser(html_filename)

    print(f"\n[✓] Scan complete. Found {len(results)} open port(s).")


if __name__ == "__main__":
    main()
