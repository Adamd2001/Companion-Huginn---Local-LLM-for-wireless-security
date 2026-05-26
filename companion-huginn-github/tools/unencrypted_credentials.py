"""Deterministic cleartext credential / sensitive-data extraction for the
``live_unencrypted_scan`` and ``scan_unencrypted_traffic`` pipelines.

Extraction sources, in order of reliability:

  A. tshark field extraction - HTTP request metadata, POST bodies exposed as
     ``http.file_data`` (hex-encoded), ``urlencoded-form.key`` /
     ``urlencoded-form.value`` aggregated per packet, Authorization and
     Cookie headers, Content-Type.
  B. TCP follow-stream fallback (``-z follow,tcp,ascii,<N>``) - for POSTs
     where the dissector did not populate ``http.file_data``.
  C. Exported HTTP objects - scan text-like files (text/plain, text/html,
     JSON, XML, small UTF-8 blobs) for explicit ``username=``/``password=``/
     ``token=`` pairs. Skips validated binary media.

All extractors return dicts with the same schema and go through
``_dedupe_findings`` so a packet that was forwarded through the Pineapple
does not produce twice the rows.
"""
from __future__ import annotations

import base64
import binascii
import html
import json
import os
import re
import shlex
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, unquote_to_bytes


# ─────────────────────────── masking + cell helpers ──────────────────────────
def _md_cell(value: Any) -> str:
    s = "" if value is None else str(value)
    s = s.replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    return s.strip()


def _mask_secret(value: str) -> str:
    if value is None:
        return ""
    if len(value) <= 2:
        return "*" * len(value)
    if len(value) <= 6:
        return value[0] + "*" * (len(value) - 2) + value[-1]
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _show_secrets_default() -> bool:
    """Secrets shown in the report unless ``HUGINN_SHOW_SECRETS=0``."""
    return os.environ.get("HUGINN_SHOW_SECRETS", "1") == "1"


# ────────────────────── sensitive-name classification ────────────────────────
_SENSITIVE_FIELD_NAMES = {
    'password', 'pass', 'pwd', 'passwd', 'passw', 'password1', 'password2',
    'secret', 'client_secret', 'token', 'access_token', 'refresh_token',
    'id_token', 'auth_token', 'api_key', 'apikey', 'x-api-key',
    'session', 'sessionid', 'session_id', 'sid', 'auth', 'authorization',
    'jwt', 'bearer', 'csrf', 'xsrf', 'remember', 'remember_token',
    'otp', 'totp', 'mfa', 'pin',
}

_USER_FIELD_NAMES = {
    'username', 'user', 'userid', 'user_id', 'user_name', 'login', 'loginid',
    'email', 'e-mail', 'account', 'uid',
}

_SENSITIVE_COOKIE_NAMES = {
    'session', 'sid', 'token', 'auth', 'jwt', 'remember', 'remember_token',
    'csrf', 'xsrf', 'phpsessid', 'jsessionid', 'asp.net_sessionid',
    'connect.sid', 'laravel_session', 'ci_session', 'express:sess',
}


def classify_field_name(name: str) -> str:
    """Return the finding sensitivity for a field name.

    ``credential`` - password-like field
    ``username`` - identifying field (still sensitive when paired with
                      a credential in the same request)
    ``other`` - generic field, not surfaced as sensitive
    """
    if not name:
        return 'other'
    n = name.strip().lower()
    if n in _SENSITIVE_FIELD_NAMES:
        return 'credential'
    if n in _USER_FIELD_NAMES:
        return 'username'
    # Pattern-based - catch e.g. ``oauth_token``, ``signup_password``.
    if any(p in n for p in ('password', 'passwd', 'secret', 'token', 'apikey',
                             'api_key', 'jwt', 'bearer', 'authkey')):
        return 'credential'
    if any(p in n for p in ('username', 'userid', 'email')):
        return 'username'
    return 'other'


def classify_cookie_name(name: str) -> bool:
    if not name:
        return False
    n = name.strip().lower()
    if n in _SENSITIVE_COOKIE_NAMES:
        return True
    return any(p in n for p in ('session', 'token', 'auth', 'jwt', 'sid', 'csrf', 'xsrf'))


# ────────────────────────────── tshark runner ────────────────────────────────
def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)


def _iso_ts_from_epoch(epoch: str) -> str:
    if not epoch:
        return ''
    try:
        return datetime.fromtimestamp(float(epoch)).isoformat(timespec='seconds')
    except Exception:
        return str(epoch)


def _hex_to_bytes(hexstr: str) -> bytes:
    """Tolerant hex decode. tshark outputs lower-case hex with no separators."""
    if not hexstr:
        return b''
    s = re.sub(r'[^0-9a-fA-F]', '', hexstr)
    if len(s) % 2:
        s = s[:-1]
    try:
        return binascii.unhexlify(s)
    except Exception:
        return b''


# ───────────────────────── tshark-based primary extractor ────────────────────
_TSHARK_FIELDS = [
    'frame.number', 'frame.time_epoch',
    'ip.src', 'tcp.srcport', 'ip.dst', 'tcp.dstport', 'tcp.stream',
    'http.request.method', 'http.host', 'http.request.uri',
    'http.content_type', 'http.authorization', 'http.proxy_authorization',
    'http.cookie', 'http.set_cookie',
    'urlencoded-form.key', 'urlencoded-form.value',
    'http.file_data',
]


def _tshark_http_rows(pcap_path: str) -> list[dict[str, str]]:
    """One-shot tshark pass that pulls everything we need per HTTP packet."""
    field_args: list[str] = []
    for f in _TSHARK_FIELDS:
        field_args.extend(['-e', f])
    cmd = [
        'tshark', '-r', pcap_path,
        '-o', 'tcp.desegment_tcp_streams:TRUE',
        '-o', 'http.desegment_body:TRUE',
        '-o', 'http.decompress_body:TRUE',
        '-Y', 'http.request or http.response or http.authorization or '
              'http.cookie or urlencoded-form or http.file_data',
        '-T', 'fields',
    ] + field_args + [
        '-E', 'separator=\t',
        '-E', 'occurrence=a',
    ]
    try:
        proc = _run(cmd, timeout=180)
    except Exception:
        return []
    rows: list[dict[str, str]] = []
    for line in (proc.stdout or '').splitlines():
        parts = line.split('\t')
        if not any(p.strip() for p in parts):
            continue
        row: dict[str, str] = {}
        for i, f in enumerate(_TSHARK_FIELDS):
            row[f] = parts[i] if i < len(parts) else ''
        rows.append(row)
    return rows


def _split_aggregated(value: str) -> list[str]:
    """tshark's ``-E occurrence=a`` aggregates repeated fields with commas."""
    if value is None or value == '':
        return []
    return value.split(',')


def _finding_from_row_common(row: dict[str, str]) -> dict[str, Any]:
    """Common per-packet context for every finding derived from a tshark row."""
    return {
        'frame': row.get('frame.number', '').strip(),
        'time': _iso_ts_from_epoch(row.get('frame.time_epoch', '').strip()),
        'tcp_stream': row.get('tcp.stream', '').strip(),
        'src_ip': row.get('ip.src', '').strip(),
        'src_port': row.get('tcp.srcport', '').strip(),
        'dst_ip': row.get('ip.dst', '').strip(),
        'dst_port': row.get('tcp.dstport', '').strip(),
        'method': row.get('http.request.method', '').strip(),
        'host': row.get('http.host', '').strip(),
        'uri': row.get('http.request.uri', '').strip(),
        'content_type': row.get('http.content_type', '').strip(),
        'protocol': 'HTTP',
    }


def _mk_finding(
    *,
    base: dict[str, Any],
    kind: str,
    sensitivity: str,
    field: str,
    value: str,
    source: str,
    evidence: str | None = None,
) -> dict[str, Any]:
    finding = dict(base)
    finding['kind'] = kind
    finding['sensitivity'] = sensitivity
    finding['field'] = field
    finding['value'] = value
    finding['source'] = source
    if evidence is not None:
        finding['evidence'] = evidence[:400]
    return finding


# ─────────────────────── extractor: urlencoded-form (A) ──────────────────────
def _extract_urlencoded_form_from_row(row: dict[str, str]) -> list[dict[str, Any]]:
    keys = _split_aggregated(row.get('urlencoded-form.key', ''))
    vals = _split_aggregated(row.get('urlencoded-form.value', ''))
    if not keys:
        return []
    base = _finding_from_row_common(row)
    base['content_type'] = base.get('content_type') or 'application/x-www-form-urlencoded'
    out: list[dict[str, Any]] = []
    for i, k in enumerate(keys):
        k = (k or '').strip()
        if not k:
            continue
        v = (vals[i].strip() if i < len(vals) else '')
        sens = classify_field_name(k)
        if sens == 'other':
            # Still surface it if the value clearly looks credential-ish.
            if len(v) >= 8 and re.search(r'[A-Za-z]', v) and re.search(r'\d|[^A-Za-z0-9]', v):
                sens = 'other'  # keep as 'other' - do not infer
        out.append(_mk_finding(
            base=base,
            kind='http_form_field',
            sensitivity=sens,
            field=k,
            value=v,
            source='urlencoded_form',
            evidence=f'{k}={v[:120]}',
        ))
    return out


# ───────────────────── extractor: raw POST body (http.file_data) ─────────────
def _parse_urlencoded_body(body: bytes) -> list[tuple[str, str]]:
    """Decode ``key=value&key=value`` with keep_blank_values."""
    try:
        text = body.decode('utf-8')
    except UnicodeDecodeError:
        text = body.decode('latin-1', errors='replace')
    pairs: list[tuple[str, str]] = []
    try:
        parsed = parse_qs(text, keep_blank_values=True)
        # parse_qs groups duplicate keys; keep stable insertion order.
        for k, vs in parsed.items():
            for v in vs:
                pairs.append((k, v))
    except Exception:
        # Manual fallback.
        for chunk in text.split('&'):
            if '=' in chunk:
                k, _, v = chunk.partition('=')
                pairs.append((_unquote_plus(k), _unquote_plus(v)))
            elif chunk:
                pairs.append((_unquote_plus(chunk), ''))
    return pairs


def _unquote_plus(s: str) -> str:
    try:
        return unquote_to_bytes(s.replace('+', ' ')).decode('utf-8', errors='replace')
    except Exception:
        return s


def _parse_json_body(body: bytes) -> list[tuple[str, str]]:
    try:
        obj = json.loads(body.decode('utf-8', errors='replace'))
    except Exception:
        return []
    pairs: list[tuple[str, str]] = []

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for k, v in value.items():
                walk(f'{prefix}.{k}' if prefix else str(k), v)
        elif isinstance(value, list):
            for i, v in enumerate(value):
                walk(f'{prefix}[{i}]', v)
        else:
            pairs.append((prefix, '' if value is None else str(value)))

    walk('', obj)
    return pairs


def _extract_file_data_from_row(row: dict[str, str]) -> list[dict[str, Any]]:
    hexbody = (row.get('http.file_data', '') or '').strip()
    if not hexbody:
        return []
    body = _hex_to_bytes(hexbody)
    if not body:
        return []
    ct = (row.get('http.content_type', '') or '').lower()
    method = (row.get('http.request.method', '') or '').upper()
    base = _finding_from_row_common(row)
    # Binary or media bodies: do not scan - image / video / audio / compressed /
    # font streams are noise generators for a text-credential regex.
    if _is_binary_content_type(ct) or not _likely_text_bytes(body):
        return []
    if method and method not in ('POST', 'PUT', 'PATCH'):
        # Response body of a textual type - scan for inline credential pairs
        # (e.g. an error page that echoes the submitted password).
        return _scan_bytes_for_secret_pairs(
            body, base=base, source='http_response_body', kind='http_response_body',
        )
    # Try urlencoded first when the body looks form-shaped.
    if (b'=' in body[:512] and b'&' in body[:1024]) or 'x-www-form-urlencoded' in ct:
        pairs = _parse_urlencoded_body(body)
        out: list[dict[str, Any]] = []
        for k, v in pairs:
            if not k:
                continue
            sens = classify_field_name(k)
            out.append(_mk_finding(
                base=base,
                kind='http_form_field',
                sensitivity=sens,
                field=k,
                value=v,
                source='http_post_body',
                evidence=f'{k}={v[:120]}',
            ))
        if out:
            return out
    # JSON body - only surface sensitive-named keys.
    if 'json' in ct or body.lstrip().startswith((b'{', b'[')):
        pairs = _parse_json_body(body)
        out = []
        for k, v in pairs:
            sens = classify_field_name(k.rsplit('.', 1)[-1])
            if sens == 'other':
                continue
            out.append(_mk_finding(
                base=base,
                kind='http_json_field',
                sensitivity=sens,
                field=k,
                value=v,
                source='http_post_body',
                evidence=f'{k}={v[:120]}',
            ))
        if out:
            return out
    # Fallback heuristic scan for unlabeled key=value tokens.
    return _scan_bytes_for_secret_pairs(
        body, base=base, source='http_post_body', kind='http_form_field',
    )


# ──────────────────── extractor: HTTP Authorization header ───────────────────
def _extract_authorization_from_row(row: dict[str, str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    base = _finding_from_row_common(row)
    for header_field, header_name in (
        ('http.authorization', 'Authorization'),
        ('http.proxy_authorization', 'Proxy-Authorization'),
    ):
        raw = (row.get(header_field, '') or '').strip()
        if not raw:
            continue
        low = raw.lower()
        if low.startswith('basic '):
            b64 = raw.split(None, 1)[1].strip()
            try:
                decoded = base64.b64decode(b64, validate=False).decode('utf-8', errors='replace')
            except Exception:
                decoded = ''
            if ':' in decoded:
                user, _, pwd = decoded.partition(':')
                findings.append(_mk_finding(
                    base=base, kind='http_basic_auth', sensitivity='username',
                    field='username', value=user, source='http_authorization_header',
                    evidence=f'{header_name}: Basic (decoded)'))
                findings.append(_mk_finding(
                    base=base, kind='http_basic_auth', sensitivity='credential',
                    field='password', value=pwd, source='http_authorization_header',
                    evidence=f'{header_name}: Basic (decoded)'))
            else:
                findings.append(_mk_finding(
                    base=base, kind='http_basic_auth', sensitivity='credential',
                    field=header_name, value=raw, source='http_authorization_header',
                    evidence=raw[:200]))
        elif low.startswith('bearer '):
            token = raw.split(None, 1)[1].strip()
            findings.append(_mk_finding(
                base=base, kind='http_bearer_token', sensitivity='credential',
                field=header_name, value=token, source='http_authorization_header',
                evidence=f'{header_name}: Bearer ...'))
        else:
            # Some other auth scheme - still sensitive.
            findings.append(_mk_finding(
                base=base, kind='http_authorization', sensitivity='credential',
                field=header_name, value=raw, source='http_authorization_header',
                evidence=raw[:200]))
    return findings


# ────────────────────────── extractor: HTTP cookies ──────────────────────────
def _extract_cookies_from_row(row: dict[str, str]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    base = _finding_from_row_common(row)
    for hdr_field, kind, source in (
        ('http.cookie', 'http_cookie', 'http_cookie'),
        ('http.set_cookie', 'http_set_cookie', 'http_cookie'),
    ):
        raw = (row.get(hdr_field, '') or '').strip()
        if not raw:
            continue
        # tshark may aggregate multiple cookies into a single field with
        # commas; split by ';' first (proper cookie separator inside a header).
        for segment in raw.split(';'):
            seg = segment.strip()
            if not seg or '=' not in seg:
                continue
            name, _, value = seg.partition('=')
            name = name.strip()
            value = value.strip().strip('"')
            if not name:
                continue
            # Skip cookie attributes like Path, Domain, HttpOnly, Max-Age.
            if name.lower() in ('path', 'domain', 'expires', 'max-age', 'samesite',
                                'secure', 'httponly', 'priority'):
                continue
            sens = 'credential' if classify_cookie_name(name) else 'other'
            findings.append(_mk_finding(
                base=base, kind=kind, sensitivity=sens,
                field=name, value=value, source=source,
                evidence=f'{name}={value[:120]}'))
    return findings


# ─────────────── extractor: follow-stream fallback for POST bodies ───────────
_POST_PREFIX_RE = re.compile(
    rb'(?P<method>POST|PUT|PATCH)\s+(?P<uri>\S+)\s+HTTP/\d(?:\.\d)?\r\n',
    re.IGNORECASE,
)


def _follow_tcp_stream_raw(pcap_path: str, stream_id: str) -> bytes:
    """Return the raw reassembled bytes of one TCP stream.

    Uses ``-z follow,tcp,raw,<N>`` which emits ``<hex>`` lines prefixed by a
    tab for server→client segments. We normalize by stripping the tabs and
    decoding all hex. This preserves both directions but we parse forward - 
    POST requests travel client→server at the start of a connection, so the
    concatenated bytes still contain the full request header+body.
    """
    try:
        proc = _run([
            'tshark', '-r', pcap_path, '-q',
            '-z', f'follow,tcp,raw,{int(stream_id)}',
        ], timeout=60)
    except Exception:
        return b''
    out = proc.stdout or ''
    buf = bytearray()
    for line in out.splitlines():
        s = line.strip()
        # Skip headers like "Follow:", "Filter:", "Node 0:", "===" separators.
        if not s or not re.fullmatch(r'[0-9a-fA-F]+', s):
            continue
        buf += _hex_to_bytes(s)
    return bytes(buf)


def _split_http_messages(raw: bytes) -> list[tuple[bytes, bytes]]:
    """Very small parser: split request start → headers → body.

    Returns a list of ``(headers_bytes, body_bytes)`` tuples, one per request
    message found. Only messages starting with POST/PUT/PATCH are returned - 
    GETs have no body. Content-Length is honored when present; otherwise the
    remaining stream is the body.
    """
    messages: list[tuple[bytes, bytes]] = []
    pos = 0
    while pos < len(raw):
        m = _POST_PREFIX_RE.search(raw, pos)
        if not m:
            break
        start = m.start()
        header_end = raw.find(b'\r\n\r\n', start)
        if header_end < 0:
            break
        headers = raw[start:header_end + 2]
        body_start = header_end + 4
        # Parse Content-Length.
        cl = 0
        for line in headers.split(b'\r\n'):
            if line.lower().startswith(b'content-length:'):
                try:
                    cl = int(line.split(b':', 1)[1].strip())
                except Exception:
                    cl = 0
                break
        if cl > 0:
            body = raw[body_start:body_start + cl]
            pos = body_start + cl
        else:
            # Unknown length - take until next request preamble or end.
            next_m = _POST_PREFIX_RE.search(raw, body_start)
            body = raw[body_start:next_m.start() if next_m else len(raw)]
            pos = next_m.start() if next_m else len(raw)
        messages.append((headers, body))
    return messages


def _parse_http_headers_dict(header_block: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in header_block.split(b'\r\n'):
        if b':' not in line:
            continue
        k, _, v = line.partition(b':')
        out[k.decode('latin-1').strip().lower()] = v.decode('latin-1').strip()
    return out


def _findings_from_followed_stream(
    pcap_path: str,
    stream_id: str,
    fallback_base: dict[str, Any],
) -> list[dict[str, Any]]:
    raw = _follow_tcp_stream_raw(pcap_path, stream_id)
    if not raw:
        return []
    findings: list[dict[str, Any]] = []
    for headers, body in _split_http_messages(raw):
        hdrs = _parse_http_headers_dict(headers)
        ct = hdrs.get('content-type', '').lower()
        base = dict(fallback_base)
        base['tcp_stream'] = stream_id
        if hdrs.get('host'):
            base['host'] = hdrs['host']
        # First line has METHOD URI HTTP/1.x
        first = headers.split(b'\r\n', 1)[0].decode('latin-1', errors='replace')
        parts = first.split()
        if len(parts) >= 2:
            base['method'] = parts[0]
            base['uri'] = parts[1]
        base['content_type'] = ct
        if 'application/x-www-form-urlencoded' in ct or (b'=' in body[:512] and b'&' in body[:512]):
            for k, v in _parse_urlencoded_body(body):
                if not k:
                    continue
                sens = classify_field_name(k)
                findings.append(_mk_finding(
                    base=base, kind='http_form_field', sensitivity=sens,
                    field=k, value=v, source='tcp_follow_stream',
                    evidence=f'{k}={v[:120]}'))
        elif 'json' in ct or body.lstrip().startswith((b'{', b'[')):
            for k, v in _parse_json_body(body):
                sens = classify_field_name(k.rsplit('.', 1)[-1])
                if sens == 'other':
                    continue
                findings.append(_mk_finding(
                    base=base, kind='http_json_field', sensitivity=sens,
                    field=k, value=v, source='tcp_follow_stream',
                    evidence=f'{k}={v[:120]}'))
        else:
            findings.extend(_scan_bytes_for_secret_pairs(
                body, base=base, source='tcp_follow_stream', kind='http_form_field',
            ))
    return findings


# ────────────────────── heuristic byte-scan helper ───────────────────────────
_SECRET_PAIR_RE = re.compile(
    r'(?i)\b('
    r'username|user|user_name|userid|user_id|login|email|e-mail|account|'
    r'password|pass|pwd|passwd|passw|secret|token|api[_-]?key|apikey|'
    r'access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|'
    r'session|sessionid|session_id|sid|jwt|bearer|csrf|xsrf'
    r')\s*[:=]\s*'
    r'("([^"\n\r]{1,200})"|'
    r"'([^'\n\r]{1,200})'|"
    r'([^&\s,;<>\n\r\x00]{1,200}))'
)


def _scan_bytes_for_secret_pairs(
    body: bytes,
    *,
    base: dict[str, Any],
    source: str,
    kind: str,
) -> list[dict[str, Any]]:
    try:
        text = body.decode('utf-8')
    except UnicodeDecodeError:
        try:
            text = body.decode('latin-1', errors='replace')
        except Exception:
            return []
    # Strip HTML entities before matching.
    try:
        cleaned = html.unescape(text)
    except Exception:
        cleaned = text
    out: list[dict[str, Any]] = []
    for m in _SECRET_PAIR_RE.finditer(cleaned):
        key = m.group(1)
        value = m.group(3) or m.group(4) or m.group(5) or ''
        # Skip obviously-template placeholders.
        if value.lower() in ('', 'none', 'null', 'undefined', 'example', 'changeme',
                              '<password>', '<username>', '<email>'):
            continue
        sens = classify_field_name(key)
        out.append(_mk_finding(
            base=base, kind=kind, sensitivity=sens,
            field=key, value=value, source=source,
            evidence=m.group(0)[:200],
        ))
    return out


# ───────────────────── extractor: exported HTTP objects ──────────────────────
_TEXT_MIME_HINTS = (
    'text/', 'application/json', 'application/xml', 'application/x-www-form-urlencoded',
    'application/javascript', 'application/ld+json',
)


_BINARY_MIME_PREFIXES = (
    'image/', 'video/', 'audio/', 'font/',
)
_BINARY_MIME_EXACT = {
    'application/octet-stream', 'application/pdf', 'application/zip',
    'application/gzip', 'application/x-gzip', 'application/x-tar',
    'application/x-bzip2', 'application/x-7z-compressed',
    'application/x-rar-compressed', 'application/wasm',
    'application/vnd.ms-fontobject', 'application/x-font-ttf',
    'application/x-font-otf',
}


def _is_binary_content_type(ct: str) -> bool:
    c = (ct or '').split(';', 1)[0].strip().lower()
    if not c:
        return False
    if c in _BINARY_MIME_EXACT:
        return True
    return any(c.startswith(p) for p in _BINARY_MIME_PREFIXES)


def _likely_text_bytes(buf: bytes) -> bool:
    if not buf:
        return False
    if b'\x00' in buf[:4096]:
        return False
    try:
        buf[:4096].decode('utf-8')
        return True
    except UnicodeDecodeError:
        try:
            buf[:4096].decode('latin-1')
            return sum(1 for b in buf[:4096] if b < 9 or (13 < b < 32)) < 16
        except Exception:
            return False


def _scan_exported_objects(objects_dir: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if not objects_dir or not objects_dir.is_dir():
        return findings
    for path in sorted(objects_dir.iterdir()):
        try:
            if not path.is_file() or path.stat().st_size == 0:
                continue
            if path.stat().st_size > 2 * 1024 * 1024:  # 2 MB cap
                continue
            data = path.read_bytes()
        except Exception:
            continue
        if not _likely_text_bytes(data):
            continue
        base = {
            'protocol': 'HTTP',
            'frame': '',
            'time': '',
            'tcp_stream': '',
            'src_ip': '', 'src_port': '', 'dst_ip': '', 'dst_port': '',
            'method': '', 'host': '', 'uri': '', 'content_type': '',
            'artifact_path': str(path),
            'artifact_name': path.name,
        }
        parsed_form = False
        # Primary: urlencoded form inside the object (matches /login POST bodies).
        if b'=' in data[:256] and b'&' in data[:512]:
            for k, v in _parse_urlencoded_body(data):
                if not k:
                    continue
                sens = classify_field_name(k)
                findings.append(_mk_finding(
                    base=base, kind='http_form_field', sensitivity=sens,
                    field=k, value=v, source='exported_http_object',
                    evidence=f'{path.name}: {k}={v[:120]}',
                ))
                parsed_form = True
        # Secondary: heuristic pair scan only when the body was not a clean form.
        if not parsed_form:
            findings.extend(_scan_bytes_for_secret_pairs(
                data, base=base, source='exported_http_object',
                kind='http_form_field',
            ))
    return findings


# ───────────────────────────── deduplication ─────────────────────────────────
_SOURCE_PRIORITY = {
    'http_post_body': 0,
    'urlencoded_form': 1,
    'tcp_follow_stream': 2,
    'http_authorization_header': 3,
    'http_cookie': 4,
    'exported_http_object': 5,
    'http_response_body': 6,
}


def _dedupe_key(f: dict[str, Any]) -> tuple:
    """Stable deduplication key so Pineapple-forwarded duplicates collapse."""
    if f.get('source') == 'exported_http_object':
        # Exported objects with identical content should collapse into one row - 
        # ignore per-file artifact_path so login, login(1), login(2) dedupe.
        return (
            f.get('kind', ''), f.get('source', ''),
            (f.get('field') or '').strip().lower(),
            f.get('value', ''),
        )
    return (
        f.get('kind', ''), f.get('source', ''),
        # intentionally skip frame/tcp_stream/src_port - the same credential
        # seen on the Pineapple-forwarded packet would otherwise dup.
        f.get('host', ''), f.get('uri', ''),
        f.get('dst_ip', ''), f.get('dst_port', ''),
        (f.get('field') or '').strip().lower(),
        f.get('value', ''),
    )


def _dedupe_findings(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    # Pass 1: dedupe within each source.
    seen: dict[tuple, dict[str, Any]] = {}
    for f in findings:
        key = _dedupe_key(f)
        existing = seen.get(key)
        if existing is None:
            seen[key] = f
            continue
        if not existing.get('frame') and f.get('frame'):
            seen[key] = f
    collapsed = list(seen.values())

    # Pass 2: cross-source collapse - if the same (field_lower, value) already
    # appears with a higher-priority source, drop the lower-priority row.
    # This suppresses redundant exported_http_object rows when we already have
    # the packet-level evidence, and also drops duplicate response-body hits.
    by_identity: dict[tuple, dict[str, Any]] = {}
    for f in collapsed:
        identity = ((f.get('field') or '').strip().lower(), f.get('value', ''),
                    f.get('sensitivity', ''))
        prio = _SOURCE_PRIORITY.get(f.get('source', ''), 99)
        existing = by_identity.get(identity)
        if existing is None:
            by_identity[identity] = f
            continue
        existing_prio = _SOURCE_PRIORITY.get(existing.get('source', ''), 99)
        if prio < existing_prio:
            by_identity[identity] = f
    return list(by_identity.values())


def _mask_finding(f: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of f with the value masked. Only called when
    ``HUGINN_SHOW_SECRETS=0``.
    """
    if f.get('sensitivity') in ('credential', 'username'):
        out = dict(f)
        out['value'] = _mask_secret(str(f.get('value', '')))
        return out
    return f


# ──────────────────────────────── orchestrator ───────────────────────────────
def extract_cleartext_sensitive_data(
    pcap_path: str,
    exported_objects_dir: Path | None = None,
    show_secrets: bool | None = None,
) -> list[dict[str, Any]]:
    """Return the deduplicated list of sensitive findings.

    ``show_secrets``   Explicit override. When ``None``, consult the
                       ``HUGINN_SHOW_SECRETS`` env var (default shown).
    ``exported_objects_dir`` Directory created by ``tshark --export-objects``.
                       When provided, text-like files are scanned for
                       embedded username/password pairs.
    """
    if show_secrets is None:
        show_secrets = _show_secrets_default()

    if not pcap_path or not Path(pcap_path).exists():
        return []

    rows = _tshark_http_rows(pcap_path)

    findings: list[dict[str, Any]] = []

    # Per-packet extractors.
    seen_streams_with_post: set[str] = set()
    for row in rows:
        findings.extend(_extract_urlencoded_form_from_row(row))
        findings.extend(_extract_file_data_from_row(row))
        findings.extend(_extract_authorization_from_row(row))
        findings.extend(_extract_cookies_from_row(row))
        method = (row.get('http.request.method') or '').upper()
        if method in ('POST', 'PUT', 'PATCH'):
            stream = (row.get('tcp.stream') or '').strip()
            if stream and stream not in seen_streams_with_post:
                seen_streams_with_post.add(stream)

    # Follow-stream fallback only if the packet-level extractors produced no
    # body-based findings for a given stream.
    streams_covered = {f.get('tcp_stream') for f in findings if f.get('source') in
                       ('urlencoded_form', 'http_post_body')}
    for stream in seen_streams_with_post - streams_covered:
        fallback_base = {
            'protocol': 'HTTP', 'frame': '', 'time': '', 'tcp_stream': stream,
            'src_ip': '', 'src_port': '', 'dst_ip': '', 'dst_port': '',
            'method': 'POST', 'host': '', 'uri': '', 'content_type': '',
        }
        findings.extend(_findings_from_followed_stream(pcap_path, stream, fallback_base))

    # Exported objects.
    if exported_objects_dir is not None:
        findings.extend(_scan_exported_objects(Path(exported_objects_dir)))

    # Deduplicate.
    findings = _dedupe_findings(findings)

    # Mask if requested.
    if not show_secrets:
        findings = [_mask_finding(f) for f in findings]

    # Stable ordering: credentials first, then usernames, then others; then by frame.
    sens_rank = {'credential': 0, 'username': 1, 'other': 2}

    def _order(f: dict[str, Any]):
        try:
            frame_no = int(f.get('frame') or 0)
        except ValueError:
            frame_no = 0
        return (sens_rank.get(f.get('sensitivity', 'other'), 2), frame_no,
                f.get('host', ''), f.get('field', ''))

    findings.sort(key=_order)
    return findings


# ────────────────────────── report-renderer helpers ──────────────────────────
def render_credentials_markdown_section(findings: list[dict[str, Any]], show_secrets: bool) -> list[str]:
    """Return Markdown lines for the Credentials section.

    Callers still choose the section header. When ``findings`` is empty the
    block falls back to the legacy "no cleartext credentials" text.
    """
    lines: list[str] = []
    if not findings:
        lines.append('No cleartext credentials, cookies, or form fields were extracted from this capture.')
        return lines
    lines.append('Cleartext sensitive values were observed in HTTP traffic.')
    lines.append('')
    lines.append('| Type | Source | Frame | TCP Stream | Client | Server | Host | URI | Field | Value |')
    lines.append('|---|---|---:|---:|---|---|---|---|---|---|')
    for f in findings:
        client = f.get('src_ip', '') or ''
        if f.get('src_port'):
            client = f"{client}:{f['src_port']}" if client else f['src_port']
        server = f.get('dst_ip', '') or ''
        if f.get('dst_port'):
            server = f"{server}:{f['dst_port']}" if server else f['dst_port']
        lines.append(
            '| ' + ' | '.join([
                _md_cell(f.get('kind', '')),
                _md_cell(f.get('source', '')),
                _md_cell(f.get('frame', '')),
                _md_cell(f.get('tcp_stream', '')),
                _md_cell(client),
                _md_cell(server),
                _md_cell(f.get('host', '')),
                _md_cell(f.get('uri', '')),
                _md_cell(f.get('field', '')),
                _md_cell(f.get('value', '')),
            ]) + ' |'
        )
    lines.append('')
    lines.append('**Evidence notes**')
    lines.append('')
    lines.append('- The values above were transmitted over HTTP (not HTTPS).')
    lines.append('- Content-Type is recorded in the source row when observed.')
    lines.append('- Any passive or MITM observer on the traffic path could capture these values.')
    if show_secrets:
        lines.append('- Sensitive values are shown because this is a local authorized lab scan. '
                     'Set `HUGINN_SHOW_SECRETS=0` to mask values.')
    else:
        lines.append('- Sensitive values are masked (`HUGINN_SHOW_SECRETS=0`).')
    return lines


def render_credentials_html_section(findings: list[dict[str, Any]], show_secrets: bool) -> str:
    """Return the HTML fragment for the Credentials section (no <section> wrapper)."""
    if not findings:
        return '<p>No cleartext credentials, cookies, or form fields were extracted from this capture.</p>'
    parts: list[str] = []
    parts.append('<p>Cleartext sensitive values were observed in HTTP traffic.</p>')
    parts.append('<table><thead><tr>'
                 '<th>Type</th><th>Source</th><th>Frame</th><th>TCP Stream</th>'
                 '<th>Client</th><th>Server</th><th>Host</th><th>URI</th>'
                 '<th>Field</th><th>Value</th>'
                 '</tr></thead><tbody>')
    for f in findings:
        client = f.get('src_ip', '') or ''
        if f.get('src_port'):
            client = f"{client}:{f['src_port']}" if client else f['src_port']
        server = f.get('dst_ip', '') or ''
        if f.get('dst_port'):
            server = f"{server}:{f['dst_port']}" if server else f['dst_port']
        cells = [
            f.get('kind', ''), f.get('source', ''),
            f.get('frame', ''), f.get('tcp_stream', ''),
            client, server,
            f.get('host', ''), f.get('uri', ''),
            f.get('field', ''), f.get('value', ''),
        ]
        parts.append('<tr>' + ''.join(f'<td>{html.escape(str(c))}</td>' for c in cells) + '</tr>')
    parts.append('</tbody></table>')
    parts.append('<p><strong>Evidence notes:</strong></p><ul>')
    parts.append('<li>The values above were transmitted over HTTP (not HTTPS).</li>')
    parts.append('<li>Content-Type is recorded in the source row when observed.</li>')
    parts.append('<li>Any passive or MITM observer on the traffic path could capture these values.</li>')
    if show_secrets:
        parts.append('<li>Sensitive values are shown because this is a local authorized lab scan. '
                     'Set <code>HUGINN_SHOW_SECRETS=0</code> to mask values.</li>')
    else:
        parts.append('<li>Sensitive values are masked (<code>HUGINN_SHOW_SECRETS=0</code>).</li>')
    parts.append('</ul>')
    return '\n'.join(parts)
