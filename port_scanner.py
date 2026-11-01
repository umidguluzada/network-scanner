#!/usr/bin/env python3
"""
Async TCP port scanner with banner grabbing and HTML reporting.

Use only against hosts you own or have explicit permission to scan.
Unauthorized scanning may be illegal in your jurisdiction.

Examples:
  python port_scanner.py -t 127.0.0.1 -p 22,80,443
  python port_scanner.py -t 192.168.1.10 -p 1-1024 -to 0.8 --html
  python port_scanner.py -t 192.168.1.10 --common --html --no-open
"""

from __future__ import annotations

import argparse
import asyncio
import html
import ipaddress
import json
import logging
import re
import socket
import ssl
import time
import webbrowser
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from string import Template

logger = logging.getLogger("port_scanner")

DEFAULT_TIMEOUT = 1.5
DEFAULT_CONCURRENCY = 300
MAX_HOSTS = 65536
MAX_CONCURRENCY = 2000
BANNER_LIMIT = 500

# Well-known ports -> likely service name. A banner match overrides this.
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    990: "FTPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP",
    8080: "HTTP",
    8443: "HTTPS",
    8888: "HTTP",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

CATEGORY_BY_SERVICE: dict[str, str] = {
    "FTP": "file",
    "FTPS": "file",
    "SSH": "remote",
    "Telnet": "remote",
    "SMTP": "mail",
    "SMTPS": "mail",
    "DNS": "infra",
    "HTTP": "web",
    "HTTPS": "web",
    "POP3": "mail",
    "POP3S": "mail",
    "RPCBind": "infra",
    "MSRPC": "infra",
    "NetBIOS": "file",
    "IMAP": "mail",
    "IMAPS": "mail",
    "SMB": "file",
    "MSSQL": "database",
    "Oracle DB": "database",
    "MySQL": "database",
    "MariaDB": "database",
    "RDP": "remote",
    "PostgreSQL": "database",
    "VNC": "remote",
    "Redis": "database",
    "Elasticsearch": "database",
    "MongoDB": "database",
    "Memcached": "database",
}

PLAIN_HTTP_PORTS = {80, 81, 3000, 5000, 5001, 7001, 8000, 8008, 8080, 8081, 8088, 8888, 9080, 9090}
TLS_PORTS = {443, 465, 990, 993, 995, 8443, 9443}
HTTP_TLS_PORTS = {443, 8443, 9443}
REDIS_PORTS = {6379}
FTP_PORTS = {21, 990}
MAIL_PORTS = {25, 465, 587}

_SSH_RE = re.compile(r"SSH-(?P<proto>\d+\.\d+)-(?P<software>\S+)(?:\s+(?P<comment>\S+))?")
_OPENSSH_RE = re.compile(r"(?i)openssh[_-](?P<ver>[0-9][\w.]*)")
_HTTP_STATUS_RE = re.compile(r"^HTTP/(?P<ver>\d\.\d)\s+(?P<code>\d{3})", re.MULTILINE)
_HEADER_RE = re.compile(r"^(?P<name>[A-Za-z0-9-]+):\s*(?P<value>\S.*?)\s*$", re.MULTILINE)
_REDIS_VERSION_RE = re.compile(r"redis_version:(?P<ver>[0-9][\w.]*)", re.IGNORECASE)
_PRODUCT_RE = re.compile(
    r"\b(?P<name>Dovecot|Cyrus|Courier|vsftpd|ProFTPD|Pure-FTPd|FileZilla Server|"
    r"Microsoft FTP Service|Exim|Postfix|Sendmail|Microsoft ESMTP)\b"
    r"(?:\s+(?P<ver>[0-9][\w.]*))?",
    re.IGNORECASE,
)

_FTP_VERSIONS = (
    ("vsftpd", re.compile(r"vsftpd\s+(?P<ver>[0-9][\w.]*)", re.IGNORECASE)),
    ("ProFTPD", re.compile(r"ProFTPD\s+(?P<ver>[0-9][\w.]*)", re.IGNORECASE)),
    ("FileZilla Server", re.compile(r"FileZilla Server(?:\s+(?P<ver>[0-9][\w.]*))?", re.IGNORECASE)),
    ("Pure-FTPd", re.compile(r"Pure-FTPd", re.IGNORECASE)),
    ("Microsoft FTP", re.compile(r"Microsoft FTP Service", re.IGNORECASE)),
)
_SMTP_VERSIONS = (
    ("Exim", re.compile(r"\bExim\s+(?P<ver>[0-9][\w.]*)", re.IGNORECASE)),
    ("Postfix", re.compile(r"\bPostfix\b", re.IGNORECASE)),
    ("Sendmail", re.compile(r"\bSendmail\b", re.IGNORECASE)),
    (
        "Microsoft ESMTP",
        re.compile(r"Microsoft ESMTP MAIL Service(?:\s+(?P<ver>[0-9][\w.]*))?", re.IGNORECASE),
    ),
)


@dataclass
class ServiceInfo:
    name: str
    product: str = ""
    version: str = ""
    detail: str = ""
    confidence: str = "low"
    category: str = "other"
    detection: str = "port"
    banner: str = ""


@dataclass
class PortResult:
    status: str
    record: dict | None = None
    detail: str = ""


@dataclass
class ScanStats:
    open: int = 0
    refused: int = 0
    timeout: int = 0
    errors: int = 0

    @property
    def total(self) -> int:
        return self.open + self.refused + self.timeout + self.errors


class ResolveError(Exception):
    """A hostname could not be resolved to an IPv4 address."""


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        force=True,
    )
    logger.setLevel(level)
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def common_ports_list() -> list[int]:
    return sorted(COMMON_PORTS)


def parse_ports(port_str: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' into a sorted unique port list."""
    if not port_str or not port_str.strip():
        raise ValueError("port list is empty")

    ports: set[int] = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-")
            if len(bounds) != 2 or not bounds[0].strip() or not bounds[1].strip():
                raise ValueError(f"invalid port range: {part}")
            try:
                start, end = int(bounds[0]), int(bounds[1])
            except ValueError as exc:
                raise ValueError(f"invalid port range: {part}") from exc
            if start > end:
                raise ValueError(f"port range goes backwards: {part}")
            if start < 1 or end > 65535:
                raise ValueError(f"ports must be between 1 and 65535: {part}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise ValueError(f"invalid port: {part}") from exc
            if not 1 <= port <= 65535:
                raise ValueError(f"ports must be between 1 and 65535: {part}")
            ports.add(port)

    if not ports:
        raise ValueError("port list is empty")
    return sorted(ports)


def parse_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number of seconds") from exc
    if timeout < 0.05:
        raise argparse.ArgumentTypeError("timeout must be at least 0.05 seconds")
    if timeout > 30:
        raise argparse.ArgumentTypeError("timeout must be 30 seconds or less")
    return timeout


def parse_workers(value: str) -> int:
    try:
        workers = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("concurrency must be an integer") from exc
    if workers < 1:
        raise argparse.ArgumentTypeError("concurrency must be at least 1")
    if workers > MAX_CONCURRENCY:
        raise argparse.ArgumentTypeError(f"concurrency must be {MAX_CONCURRENCY} or less")
    return workers


def _reject_ipv6(address: str) -> None:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return
    if parsed.version == 6:
        raise ValueError(f"IPv6 is not supported: {address}")


def parse_targets(target_str: str) -> list[str]:
    """Accept an IP, hostname, CIDR, or a comma-separated mix of those."""
    if not target_str or not target_str.strip():
        raise ValueError("target is empty")

    targets: list[str] = []
    seen: set[str] = set()
    for part in target_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "://" in part:
            raise ValueError(f"pass a host or IP, not a URL: {part}")
        if "/" in part:
            try:
                network = ipaddress.ip_network(part, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR target: {part}") from exc
            if network.version != 4:
                raise ValueError(f"IPv6 is not supported: {part}")
            hosts = [str(ip) for ip in network.hosts()]
            if not hosts and network.prefixlen == 32:
                hosts = [str(network.network_address)]
            if len(hosts) > MAX_HOSTS:
                raise ValueError(
                    f"CIDR {part} expands to {len(hosts)} hosts; the limit is {MAX_HOSTS}"
                )
            for host in hosts:
                if host not in seen:
                    seen.add(host)
                    targets.append(host)
            continue

        _reject_ipv6(part)
        if part not in seen:
            seen.add(part)
            targets.append(part)

    if not targets:
        raise ValueError("target is empty")
    return targets


def sanitize_banner(text: str, limit: int = BANNER_LIMIT) -> str:
    if not text:
        return ""
    text = text.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n")
    cleaned = []
    for char in text:
        if char == "\n" or char.isprintable():
            cleaned.append(char)
        else:
            cleaned.append(".")
    result = "".join(cleaned).strip()
    if len(result) > limit:
        return result[:limit] + "..."
    return result


def decode_banner(raw: bytes) -> str:
    if not raw:
        return ""
    return raw.decode("utf-8", errors="replace")


def guess_service(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")


def category_for(service: str) -> str:
    return CATEGORY_BY_SERVICE.get(service, "other")


def _service(
    name: str,
    product: str = "",
    version: str = "",
    detail: str = "",
    confidence: str = "low",
    detection: str = "port",
    banner: str = "",
) -> ServiceInfo:
    return ServiceInfo(
        name=name or "unknown",
        product=product.strip(),
        version=(version or "").strip(),
        detail=(detail or "").strip(),
        confidence=confidence,
        category=category_for(name or "unknown"),
        detection=detection,
        banner=banner,
    )


def _apply_tls_name(info: ServiceInfo, source: str) -> ServiceInfo:
    if source != "tls":
        return info
    renamed = {
        "HTTP": "HTTPS",
        "FTP": "FTPS",
        "SMTP": "SMTPS",
        "IMAP": "IMAPS",
        "POP3": "POP3S",
    }.get(info.name, info.name)
    info.name = renamed
    info.category = category_for(renamed)
    return info


def parse_mysql_handshake(raw: bytes) -> tuple[str, str] | None:
    """Read a MySQL/MariaDB greeting packet if the protocol signature matches."""
    if len(raw) < 6 or raw[4] != 0x0A:
        return None
    end = raw.find(b"\x00", 5)
    if end <= 5:
        return None
    text = raw[5:end].decode("utf-8", errors="replace")
    if not re.fullmatch(r"\d+\.\d+[\w.\-]*", text):
        return None
    if "mariadb" in text.lower():
        return "MariaDB", text
    return "MySQL", text


def split_server_header(value: str) -> tuple[str, str, str]:
    value = value.strip()
    if not value:
        return "", "", ""
    token, _, rest = value.partition(" ")
    detail = rest.strip().strip("()")
    if "/" in token:
        product, version = token.split("/", 1)
        return product, version, detail
    return token, "", detail


def parse_headers(banner: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for match in _HEADER_RE.finditer(banner):
        headers.setdefault(match.group("name").lower(), match.group("value").strip())
    return headers


def parse_http_banner(banner: str) -> tuple[str, str, str] | None:
    if not _HTTP_STATUS_RE.search(banner):
        return None
    headers = parse_headers(banner)
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server:
        product, version, detail = split_server_header(server)
        if powered and powered.lower() not in server.lower():
            detail = ", ".join(part for part in (detail, powered) if part)
        return product, version, detail
    if powered:
        return split_server_header(powered)
    return "", "", ""


def _named_product(patterns: tuple[tuple[str, re.Pattern[str]], ...], banner: str) -> tuple[str, str]:
    for name, pattern in patterns:
        match = pattern.search(banner)
        if not match:
            continue
        version = match.groupdict().get("ver") or ""
        return name, version
    return "", ""


def _software_hint(banner: str) -> tuple[str, str]:
    match = _PRODUCT_RE.search(banner)
    if not match:
        return "", ""
    return match.group("name"), match.group("ver") or ""


def identify_service(port: int, banner: str, raw: bytes, source: str) -> ServiceInfo:
    """Best-effort service and version guess from a port and its banner.

    Banner evidence wins over the port number. With no banner, the result is
    only a low-confidence guess from the well-known port table.
    """
    mysql = parse_mysql_handshake(raw)
    if mysql and (port in {3306, 3307, 33060} or not banner.startswith(("SSH-", "HTTP/", "+OK", "* OK", "+PONG", "220"))):
        product, version = mysql
        pretty = f"{product} protocol handshake {version}"
        info = _service(product, product, version, confidence="high", detection=source, banner=pretty)
        return _apply_tls_name(info, source)

    stripped = banner.lstrip()
    ssh_match = _SSH_RE.search(banner) if stripped.startswith("SSH-") or "SSH-" in banner[:40] else None
    if ssh_match and (stripped.startswith("SSH-") or "HTTP/" not in stripped[:8]):
        software = ssh_match.group("software")
        comment = ssh_match.group("comment") or ""
        openssh = _OPENSSH_RE.search(software)
        if openssh:
            product, version = "OpenSSH", openssh.group("ver")
        else:
            for separator in ("_", "-"):
                product, sep, version = software.partition(separator)
                if sep:
                    break
            else:
                product, version = software, ""
        info = _service("SSH", product, version, comment, confidence="high", detection=source, banner=banner)
        return _apply_tls_name(info, source)

    http = parse_http_banner(banner)
    if http is not None:
        product, version, detail = http
        name = "HTTPS" if source == "tls" or port in TLS_PORTS else "HTTP"
        info = _service(name, product, version, detail, confidence="high", detection=source, banner=banner)
        return _apply_tls_name(info, source)

    first = stripped.splitlines()[0] if stripped else ""
    lower = banner.lower()

    if first.startswith("+PONG") or first.startswith("-NOAUTH") or _REDIS_VERSION_RE.search(banner):
        version_match = _REDIS_VERSION_RE.search(banner)
        info = _service(
            "Redis",
            "Redis",
            version_match.group("ver") if version_match else "",
            confidence="high",
            detection=source,
            banner=banner,
        )
        return _apply_tls_name(info, source)

    if port in REDIS_PORTS and first.startswith("-ERR"):
        info = _service("Redis", "Redis", confidence="medium", detection=source, banner=banner)
        return _apply_tls_name(info, source)

    if first.startswith("220"):
        ftp_name, ftp_version = _named_product(_FTP_VERSIONS, banner)
        smtp_name, smtp_version = _named_product(_SMTP_VERSIONS, banner)
        ftp_hint = "ftp" in lower or ftp_name != "" or port in FTP_PORTS
        smtp_hint = any(token in lower for token in ("smtp", "esmtp")) or smtp_name != "" or port in MAIL_PORTS
        if ftp_name and not (smtp_hint and not ftp_hint):
            confidence = "high"
            info = _service("FTP", ftp_name, ftp_version, confidence=confidence, detection=source, banner=banner)
            return _apply_tls_name(info, source)
        if smtp_name and not (ftp_hint and port in FTP_PORTS and not smtp_hint):
            info = _service("SMTP", smtp_name, smtp_version, confidence="high", detection=source, banner=banner)
            return _apply_tls_name(info, source)
        if port in FTP_PORTS or "ftp" in lower:
            info = _service("FTP", confidence="high" if port in FTP_PORTS else "medium", detection=source, banner=banner)
            return _apply_tls_name(info, source)
        if port in MAIL_PORTS or smtp_hint:
            info = _service("SMTP", confidence="high" if port in MAIL_PORTS else "medium", detection=source, banner=banner)
            return _apply_tls_name(info, source)

    if first.startswith("+OK"):
        product, version = _software_hint(banner)
        confidence = "high" if port in {110, 995} or product else "medium"
        info = _service("POP3", product, version, confidence=confidence, detection=source, banner=banner)
        return _apply_tls_name(info, source)

    if first.startswith("* OK") or first.startswith("*OK"):
        product, version = _software_hint(banner)
        confidence = "high" if port in {143, 993} or product else "medium"
        info = _service("IMAP", product, version, confidence=confidence, detection=source, banner=banner)
        return _apply_tls_name(info, source)

    keyword_checks = (
        ("SSH", "remote", re.compile(r"openssh|\bssh-\d", re.IGNORECASE)),
        ("Redis", "database", re.compile(r"\bredis\b", re.IGNORECASE)),
        ("HTTP", "web", re.compile(r"^HTTP/\d|^\s*server:\s", re.IGNORECASE | re.MULTILINE)),
        ("FTP", "file", re.compile(r"\bftp\b|vsftpd|proftpd|pure-ftpd", re.IGNORECASE)),
        ("SMTP", "mail", re.compile(r"\besmtp\b|\bsmtp\b|\bpostfix\b|\bsendmail\b|\bexim\b", re.IGNORECASE)),
        ("IMAP", "mail", re.compile(r"\bimap4?\b|\bdovecot\b", re.IGNORECASE)),
        ("MySQL", "database", re.compile(r"\bmysql\b|\bmariadb\b", re.IGNORECASE)),
    )
    if banner:
        for name, _category, pattern in keyword_checks:
            if pattern.search(banner):
                product, version = _software_hint(banner)
                if name == "MySQL" and "mariadb" in lower:
                    name = "MariaDB"
                    product = product or "MariaDB"
                info = _service(
                    name,
                    product,
                    version,
                    confidence="medium",
                    detection=source if source != "port" else "banner",
                    banner=banner,
                )
                return _apply_tls_name(info, source)

    guessed = guess_service(port)
    if banner:
        detection = source if source != "port" else "banner"
        confidence = "medium"
    elif source == "tls":
        detection = "tls"
        confidence = "low"
    else:
        detection = "port"
        confidence = "low"
    info = _service(guessed, confidence=confidence, detection=detection, banner=banner)
    return _apply_tls_name(info, source)


def format_product(product: str, version: str, detail: str = "") -> str:
    core = " ".join(part for part in (product, version) if part).strip()
    if core and detail:
        return f"{core} ({detail})"
    return core or detail


def sort_key(record: dict) -> tuple:
    try:
        ip_key = tuple(int(octet) for octet in record["ip"].split("."))
    except ValueError:
        ip_key = (999,)
    return ip_key, record["port"]


def build_record(ip: str, port: int, raw: bytes, source: str) -> dict:
    text = sanitize_banner(decode_banner(raw))
    info = identify_service(port, text, raw, source)
    banner = sanitize_banner(info.banner or text)
    return {
        "ip": ip,
        "port": port,
        "state": "open",
        "service": info.name,
        "product": info.product,
        "version": info.version,
        "detail": info.detail,
        "confidence": info.confidence,
        "category": info.category,
        "detection": info.detection,
        "banner": banner,
    }


def classify_connect_error(exc: Exception) -> tuple[str, str]:
    """Map a connect failure to a scan outcome: refused, timeout, or error."""
    if isinstance(exc, TimeoutError):
        return "timeout", "timed out"
    if isinstance(exc, ConnectionRefusedError):
        return "refused", "connection refused"
    if isinstance(exc, socket.gaierror):
        return "error", f"name resolution failed: {exc}"
    if isinstance(exc, OSError):
        winerror = getattr(exc, "winerror", None)
        err = exc.errno
        if winerror in (10060, 121) or err in (110, 10060):
            return "timeout", "timed out"
        if winerror == 10061 or err in (111, 10061):
            return "refused", "connection refused"
        message = str(exc).strip() or exc.__class__.__name__
        return "error", message
    return "error", str(exc).strip() or exc.__class__.__name__


async def close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    transport = writer.transport
    writer.close()
    if transport is not None:
        transport.abort()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=0.05)
    except Exception:
        return


async def read_some(reader: asyncio.StreamReader, timeout: float, limit: int = 4096) -> bytes:
    """Read a banner, waiting up to `timeout` for the first bytes."""
    chunks: list[bytes] = []
    remaining = limit
    try:
        first = await asyncio.wait_for(reader.read(min(1024, remaining)), timeout=timeout)
    except TimeoutError:
        return b""
    if not first:
        return b""
    chunks.append(first)
    remaining -= len(first)
    while remaining > 0:
        try:
            more = await asyncio.wait_for(reader.read(remaining), timeout=0.15)
        except TimeoutError:
            break
        if not more:
            break
        chunks.append(more)
        remaining -= len(more)
    return b"".join(chunks)


def http_request(host: str, method: str) -> bytes:
    return (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: NetworkScanner/2.0\r\n"
        f"Accept: */*\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")


async def send_and_read(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    payload: bytes,
    timeout: float,
) -> bytes:
    try:
        writer.write(payload)
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        return await read_some(reader, timeout)
    except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError) as exc:
        logger.debug("Probe failed: %s", exc)
        return b""


async def collect_plain_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ip: str,
    port: int,
    timeout: float,
) -> tuple[bytes, str]:
    # Redis stays silent until the client speaks. PING only identifies it.
    if port in REDIS_PORTS:
        probed = await send_and_read(reader, writer, b"PING\r\n", timeout)
        return (probed, "probe") if probed else (b"", "port")

    # Known web ports, and ports outside the well-known set, get one HTTP probe.
    # Recognized services such as SSH and SMTP are left to speak first.
    if port in PLAIN_HTTP_PORTS or port not in COMMON_PORTS:
        probed = await send_and_read(reader, writer, http_request(ip, "HEAD"), timeout)
        if not probed and port in PLAIN_HTTP_PORTS:
            probed = await send_and_read(reader, writer, http_request(ip, "GET"), timeout)
        if probed:
            return probed, "probe"
        if port in PLAIN_HTTP_PORTS:
            return b"", "port"

    raw = await read_some(reader, timeout)
    return (raw, "banner") if raw else (b"", "port")


_TLS_CONTEXT: ssl.SSLContext | None = None


def tls_context() -> ssl.SSLContext:
    # Verification is off because this connection only identifies the service.
    global _TLS_CONTEXT
    if _TLS_CONTEXT is None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        _TLS_CONTEXT = context
    return _TLS_CONTEXT


async def collect_tls_banner(ip: str, port: int, timeout: float) -> tuple[bytes, str]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip,
                port,
                ssl=tls_context(),
                server_hostname=ip,
                ssl_handshake_timeout=timeout,
                family=socket.AF_INET,
            ),
            timeout=timeout,
        )
    except Exception as exc:
        logger.debug("TLS handshake failed on %s:%d: %s", ip, port, exc)
        return b"", "tls"

    try:
        if port in HTTP_TLS_PORTS:
            probed = await send_and_read(reader, writer, http_request(ip, "HEAD"), timeout)
            if not probed:
                probed = await send_and_read(reader, writer, http_request(ip, "GET"), timeout)
            return (probed, "tls") if probed else (b"", "tls")
        raw = await read_some(reader, timeout)
        return raw, "tls"
    except Exception as exc:
        logger.debug("TLS banner read failed on %s:%d: %s", ip, port, exc)
        return b"", "tls"
    finally:
        await close_writer(writer)


async def scan_port(ip: str, port: int, timeout: float) -> PortResult:
    """Connect to one TCP port. Open ports include a banner when the service sends one."""
    writer: asyncio.StreamWriter | None = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, family=socket.AF_INET),
            timeout=timeout,
        )
    except Exception as exc:
        status, detail = classify_connect_error(exc)
        if status == "error":
            logger.debug("Connect error on %s:%d: %s", ip, port, detail)
        return PortResult(status=status, detail=detail)

    try:
        if port in TLS_PORTS:
            raw, source = b"", "tls"
        else:
            try:
                raw, source = await collect_plain_banner(reader, writer, ip, port, timeout)
            except Exception as exc:
                logger.debug("Banner error on %s:%d: %s", ip, port, exc)
                raw, source = b"", "port"
    finally:
        await close_writer(writer)

    if port in TLS_PORTS:
        raw, source = await collect_tls_banner(ip, port, timeout)

    return PortResult(status="open", record=build_record(ip, port, raw, source))


def log_open(record: dict) -> None:
    label = format_product(record["product"], record["version"], record["detail"])
    service = " ".join(part for part in (record["service"], label) if part)
    preview = record["banner"].replace("\n", " ").strip()
    if len(preview) > 80:
        preview = preview[:77] + "..."
    suffix = f" - {preview}" if preview else ""
    logger.info("OPEN %s:%d %s%s", record["ip"], record["port"], service, suffix)


async def run_scan(
    hosts: list[str],
    ports: list[int],
    timeout: float,
    concurrency: int,
) -> tuple[list[dict], ScanStats]:
    stats = ScanStats()
    results: list[dict] = []
    jobs = [(ip, port) for ip in hosts for port in ports]
    total = len(jobs)
    if total == 0:
        return results, stats
    if total > 200_000:
        logger.warning(
            "Large scan: %d connection attempts. Lower the port range or concurrency if this is noisy.",
            total,
        )

    queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
    for job in jobs:
        queue.put_nowait(job)

    done = 0
    last_progress = time.perf_counter()

    async def worker() -> None:
        nonlocal done, last_progress
        while True:
            try:
                ip, port = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                outcome = await scan_port(ip, port, timeout)
            except Exception as exc:
                logger.warning("Unexpected failure on %s:%d: %s", ip, port, exc)
                outcome = PortResult(status="error", detail=str(exc))

            done += 1
            if outcome.status == "open" and outcome.record:
                stats.open += 1
                results.append(outcome.record)
                log_open(outcome.record)
            elif outcome.status == "refused":
                stats.refused += 1
                logger.debug("Connection refused %s:%d", ip, port)
            elif outcome.status == "timeout":
                stats.timeout += 1
                logger.debug("Timeout %s:%d", ip, port)
            else:
                stats.errors += 1
                message = outcome.detail or "unknown error"
                if stats.errors <= 5:
                    logger.warning("Error scanning %s:%d: %s", ip, port, message)
                else:
                    logger.debug("Error scanning %s:%d: %s", ip, port, message)

            now = time.perf_counter()
            if total >= 50 and done != total and now - last_progress >= 2:
                last_progress = now
                logger.info("Progress %d/%d (open %d)", done, total, stats.open)

    worker_count = min(max(concurrency, 1), total)
    logger.info(
        "Scanning %d host(s), %d port(s), timeout %.2fs, concurrency %d (%d checks)",
        len(hosts),
        len(ports),
        timeout,
        worker_count,
        total,
    )
    await asyncio.gather(*(worker() for _ in range(worker_count)))
    results.sort(key=sort_key)
    return results, stats


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


async def resolve_host(host: str) -> str:
    if is_ip_literal(host):
        parsed = ipaddress.ip_address(host)
        if parsed.version != 4:
            raise ResolveError(f"IPv6 is not supported: {host}")
        return host
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ResolveError(f"Could not resolve host '{host}': {exc}") from exc
    except OSError as exc:
        raise ResolveError(f"Could not resolve host '{host}': {exc}") from exc
    if not infos:
        raise ResolveError(f"Could not resolve host '{host}': no IPv4 address found")
    return str(infos[0][4][0])


async def resolve_all(hosts: list[str]) -> list[str]:
    resolved: list[str] = []
    failures = 0
    for host in hosts:
        try:
            ip = await resolve_host(host)
        except ResolveError as exc:
            failures += 1
            logger.error("%s", exc)
            continue
        if host == ip:
            logger.debug("Target %s", ip)
        else:
            logger.info("Resolved %s -> %s", host, ip)
        if ip not in resolved:
            resolved.append(ip)
    if failures:
        logger.warning("Skipped %d host(s) that could not be resolved", failures)
    return resolved


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, secs = divmod(seconds, 60)
    return f"{int(minutes)}m {secs:.1f}s"


def save_json(path: Path, payload: dict) -> bool:
    try:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        logger.error("Could not write JSON report %s: %s", path, exc)
        return False
    logger.info("JSON saved to %s", path)
    return True


def _stat_card(label: str, value: str, accent: str, subtitle: str = "") -> str:
    subtitle_html = (
        f'<div class="small text-secondary mt-1">{html.escape(subtitle)}</div>' if subtitle else ""
    )
    return (
        '<div class="col-6 col-md-3">'
        '<div class="card stat-card h-100"><div class="card-body">'
        f'<div class="text-secondary small text-uppercase">{html.escape(label)}</div>'
        f'<div class="fs-3 fw-semibold {accent}">{html.escape(value)}</div>'
        f"{subtitle_html}"
        "</div></div></div>"
    )


def _outcome_bar(stats: ScanStats) -> str:
    total = stats.total
    if total <= 0:
        return ""
    segments = (
        ("open", stats.open, "bg-success"),
        ("refused", stats.refused, "bg-secondary"),
        ("no response", stats.timeout, "bg-info"),
        ("errors", stats.errors, "bg-danger"),
    )
    bars = []
    legend = []
    for name, count, css in segments:
        pct = count / total * 100
        if count > 0:
            bars.append(
                f'<div class="progress-bar {css}" style="width: {pct:.4f}%" '
                f'aria-valuenow="{count}" aria-valuemin="0" aria-valuemax="{total}"></div>'
            )
        legend.append(
            f'<li class="list-inline-item me-3">'
            f'<span class="badge {css}">&nbsp;</span> {html.escape(name)} '
            f"{count} ({pct:.1f}%)</li>"
        )
    return (
        '<div class="progress mb-2" style="height: 0.85rem" role="progressbar" '
        'aria-label="Scan outcomes">'
        + "".join(bars)
        + '</div><ul class="list-inline small text-secondary mb-0">'
        + "".join(legend)
        + "</ul>"
    )


def _service_badges(results: list[dict]) -> str:
    if not results:
        return '<span class="text-secondary">No open services.</span>'
    counts = Counter(record["service"] for record in results)
    badges = []
    for name, count in counts.most_common():
        category = category_for(name)
        badges.append(
            f'<span class="badge badge-{html.escape(category)} me-1 mb-1">'
            f"{html.escape(name)} · {count}</span>"
        )
    return "".join(badges)


def _confidence_badge(confidence: str) -> str:
    css = {"high": "text-bg-success", "medium": "text-bg-warning", "low": "text-bg-secondary"}.get(
        confidence, "text-bg-secondary"
    )
    return f'<span class="badge {css}">{html.escape(confidence)}</span>'


def render_rows(results: list[dict]) -> str:
    if not results:
        return (
            '<tr><td colspan="7" class="text-center text-secondary py-4">'
            "No open ports found.</td></tr>"
        )
    rows = []
    for record in results:
        version = format_product(record["product"], record["version"], record["detail"])
        version_html = (
            html.escape(version) if version else '<span class="text-secondary">unknown</span>'
        )
        banner = record["banner"]
        banner_html = (
            f"<pre class=\"banner\">{html.escape(banner)}</pre>"
            if banner
            else '<span class="text-secondary">no banner</span>'
        )
        category = record.get("category") or "other"
        detection = record.get("detection") or "port"
        rows.append(
            f'<tr class="cat-{html.escape(category)}">'
            f"<td>{html.escape(record['ip'])}</td>"
            f"<td class=\"text-nowrap\">{record['port']}</td>"
            f'<td><span class="badge text-bg-success">OPEN</span></td>'
            f'<td><span class="badge badge-{html.escape(category)}">{html.escape(record["service"])}</span></td>'
            f"<td>{version_html}</td>"
            f"<td>{_confidence_badge(record['confidence'])}"
            f'<div class="small text-secondary mt-1">{html.escape(detection)}</div></td>'
            f"<td>{banner_html}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def summarize_hosts(hosts: list[str], limit: int = 8) -> str:
    safe = [html.escape(host) for host in hosts]
    if len(safe) <= limit:
        return ", ".join(safe)
    hidden = len(safe) - limit
    return ", ".join(safe[:limit]) + f", and {hidden} more"


HTML_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network scan report</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
  :root, [data-bs-theme="dark"] {
    color-scheme: dark;
    --bs-body-bg: #0b1120;
    --bs-body-color: #e5e7eb;
    --bs-secondary-color: #94a3b8;
    --bs-border-color: rgba(148, 163, 184, 0.18);
  }
  body {
    background:
      radial-gradient(900px 420px at 0% -10%, rgba(56, 189, 248, 0.08), transparent 55%),
      #0b1120;
    min-height: 100vh;
  }
  .stat-card, .panel {
    background: rgba(15, 23, 42, 0.92);
    border: 1px solid rgba(148, 163, 184, 0.16);
  }
  .table > :not(caption) > * > * { background: transparent; }
  tr.cat-remote td:first-child { box-shadow: inset 3px 0 0 #f59e0b; }
  tr.cat-web td:first-child { box-shadow: inset 3px 0 0 #38bdf8; }
  tr.cat-database td:first-child { box-shadow: inset 3px 0 0 #a78bfa; }
  tr.cat-mail td:first-child { box-shadow: inset 3px 0 0 #fb923c; }
  tr.cat-file td:first-child { box-shadow: inset 3px 0 0 #2dd4bf; }
  tr.cat-infra td:first-child { box-shadow: inset 3px 0 0 #94a3b8; }
  tr.cat-other td:first-child { box-shadow: inset 3px 0 0 #64748b; }
  .badge-remote { background: #b45309; }
  .badge-web { background: #0369a1; }
  .badge-database { background: #6d28d9; }
  .badge-mail { background: #c2410c; }
  .badge-file { background: #0f766e; }
  .badge-infra { background: #475569; }
  .badge-other { background: #334155; }
  .banner {
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 6.5rem;
    overflow: auto;
    margin: 0;
    color: #93c5fd;
    font-size: 0.78rem;
  }
  .swatch {
    display: inline-block;
    width: 0.7rem;
    height: 0.7rem;
    border-radius: 2px;
    margin-right: 0.3rem;
  }
  .swatch-remote { background: #f59e0b; }
  .swatch-web { background: #38bdf8; }
  .swatch-database { background: #a78bfa; }
  .swatch-mail { background: #fb923c; }
  .swatch-file { background: #2dd4bf; }
  .swatch-infra { background: #94a3b8; }
  .swatch-other { background: #64748b; }
</style>
</head>
<body>
<nav class="navbar border-bottom border-secondary-subtle mb-4">
  <div class="container">
    <span class="navbar-brand fw-semibold mb-0">Network Scanner</span>
    <span class="text-secondary small">TCP connect report</span>
  </div>
</nav>
<main class="container pb-5">
  <div class="d-flex flex-wrap justify-content-between align-items-end gap-3 mb-4">
    <div>
      <h1 class="h3 mb-1">Scan report</h1>
      <p class="text-secondary mb-0">$generated</p>
    </div>
    <div class="text-secondary small text-md-end">
      <div>Target <span class="text-light">$target</span></div>
      <div>Timeout ${timeout}s · concurrency $concurrency · $check_count checks</div>
    </div>
  </div>

  <div class="row g-3 mb-4">
    $cards
  </div>

  <div class="card panel mb-4">
    <div class="card-body">
      <h2 class="h6 text-secondary text-uppercase mb-3">Outcomes</h2>
      $outcome_bar
      <p class="small text-secondary mb-0 mt-3">Hosts: $host_summary</p>
    </div>
  </div>

  <div class="card panel mb-4">
    <div class="card-body">
      <h2 class="h6 text-secondary text-uppercase mb-3">Services</h2>
      <div>$service_badges</div>
    </div>
  </div>

  <div class="card panel">
    <div class="card-header bg-transparent">Open ports</div>
    <div class="table-responsive">
      <table class="table table-hover align-middle mb-0">
        <thead>
          <tr class="text-secondary small text-uppercase">
            <th>Host</th>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
            <th>Version</th>
            <th>Confidence</th>
            <th>Banner</th>
          </tr>
        </thead>
        <tbody>
          $rows
        </tbody>
      </table>
    </div>
  </div>

  <div class="d-flex flex-wrap gap-3 small text-secondary mt-3">
    <span><i class="swatch swatch-remote"></i>Remote access</span>
    <span><i class="swatch swatch-web"></i>Web</span>
    <span><i class="swatch swatch-database"></i>Database</span>
    <span><i class="swatch swatch-mail"></i>Mail</span>
    <span><i class="swatch swatch-file"></i>File sharing</span>
    <span><i class="swatch swatch-infra"></i>Infrastructure</span>
    <span><i class="swatch swatch-other"></i>Other</span>
  </div>
  <p class="small text-secondary mt-3 mb-0">
    Service names and versions are best-effort readings of port numbers and banners.
    They are not a vulnerability assessment.
  </p>
</main>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""")


def save_html(
    path: Path,
    results: list[dict],
    hosts: list[str],
    target_display: str,
    ports_count: int,
    timeout: float,
    concurrency: int,
    started: datetime,
    duration: float,
    stats: ScanStats,
) -> bool:
    hosts_with_open = sorted({record["ip"] for record in results}, key=lambda ip: sort_key({"ip": ip, "port": 0}))
    cards = "".join(
        (
            _stat_card("Open ports", str(len(results)), "text-success", f"{len(hosts_with_open)} host(s) with hits"),
            _stat_card("Hosts", str(len(hosts)), "text-info"),
            _stat_card("Ports scanned", str(ports_count), "text-light", f"{stats.total} checks"),
            _stat_card("Duration", format_duration(duration), "text-warning"),
        )
    )
    try:
        document = HTML_TEMPLATE.substitute(
            generated=html.escape(started.strftime("%Y-%m-%d %H:%M:%S")),
            target=html.escape(target_display),
            timeout=f"{timeout:.2f}",
            concurrency=str(concurrency),
            check_count=str(stats.total),
            cards=cards,
            outcome_bar=_outcome_bar(stats),
            host_summary=summarize_hosts(hosts),
            service_badges=_service_badges(results),
            rows=render_rows(results),
        )
        path.write_text(document, encoding="utf-8")
    except OSError as exc:
        logger.error("Could not write HTML report %s: %s", path, exc)
        return False
    logger.info("HTML report saved to %s", path)
    return True


def open_in_browser(filename: Path) -> None:
    path = filename.resolve()
    if not path.exists():
        logger.error("Could not open report, file not found: %s", path)
        return
    try:
        opened = webbrowser.open(path.as_uri())
    except OSError as exc:
        logger.error("Browser could not be launched: %s", exc)
        opened = False
    if opened:
        logger.info("Opened report in browser: %s", path)
    else:
        logger.info("Could not open a browser automatically. Report: %s", path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Async TCP connect scanner with banner grabbing, service hints, "
            "and an HTML report. Scan only hosts you are allowed to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python port_scanner.py -t 127.0.0.1 -p 22,80,443\n"
            "  python port_scanner.py -t 192.168.1.10 -p 1-1024 -to 0.8 --html\n"
            "  python port_scanner.py -t 192.168.1.10 --common --html --no-open\n"
            "  python port_scanner.py -t localhost -p 80 -to 2 -v\n"
        ),
    )
    parser.add_argument(
        "-t",
        "--target",
        "--targets",
        dest="target",
        required=True,
        help="IP, hostname, CIDR (192.168.1.0/24), or a comma-separated list",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=None,
        help="Ports, e.g. 22,80,443 or 1-1024 (default: 1-1024, unless --common)",
    )
    parser.add_argument(
        "-to",
        "--timeout",
        type=parse_timeout,
        default=DEFAULT_TIMEOUT,
        help=f"Per-connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="scan_results.json",
        help="JSON output path (default: scan_results.json)",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=parse_workers,
        default=DEFAULT_CONCURRENCY,
        help=f"Maximum concurrent connections (default: {DEFAULT_CONCURRENCY})",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        help="Also write a Bootstrap HTML report next to the JSON file",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the HTML report in a browser",
    )
    parser.add_argument(
        "--common",
        action="store_true",
        help=f"Scan {len(COMMON_PORTS)} well-known ports instead of a range",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Log timeouts, refused connections, and other debug detail",
    )
    return parser


def port_spec_label(args: argparse.Namespace, ports: list[int]) -> str:
    if args.ports:
        return args.ports
    if args.common:
        return "common"
    return "1-1024"


async def execute(args: argparse.Namespace, targets: list[str], ports: list[int]) -> int:
    started = datetime.now()
    hosts = await resolve_all(targets)
    if not hosts:
        logger.error("No targets could be resolved; scan aborted")
        return 1

    clock = time.perf_counter()
    results, stats = await run_scan(hosts, ports, args.timeout, args.workers)
    duration = time.perf_counter() - clock

    logger.info(
        "Scan complete in %s - %d open, %d connection refused, %d timed out, %d errors",
        format_duration(duration),
        stats.open,
        stats.refused,
        stats.timeout,
        stats.errors,
    )

    payload = {
        "scan_time": started.isoformat(timespec="seconds"),
        "duration_seconds": round(duration, 3),
        "target": args.target,
        "port_spec": port_spec_label(args, ports),
        "hosts": hosts,
        "ports_scanned": len(ports),
        "timeout_seconds": args.timeout,
        "concurrency": args.workers,
        "statistics": {
            "open": stats.open,
            "connection_refused": stats.refused,
            "timeout": stats.timeout,
            "errors": stats.errors,
            "checks": stats.total,
        },
        "total_open_ports": len(results),
        "results": results,
    }

    output = Path(args.output)
    ok = save_json(output, payload)
    if args.html:
        html_path = output.with_suffix(".html")
        html_ok = save_html(
            html_path,
            results,
            hosts,
            args.target,
            len(ports),
            args.timeout,
            args.workers,
            started,
            duration,
            stats,
        )
        ok = html_ok and ok
        if html_ok and not args.no_open:
            open_in_browser(html_path)
    return 0 if ok else 1


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)

    if args.common and args.ports:
        logger.warning("--ports was provided with --common; using the explicit port list")

    try:
        targets = parse_targets(args.target)
        if args.ports:
            ports = parse_ports(args.ports)
        elif args.common:
            ports = common_ports_list()
        else:
            ports = parse_ports("1-1024")
    except ValueError as exc:
        parser.error(str(exc))

    try:
        return asyncio.run(execute(args, targets, ports))
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
