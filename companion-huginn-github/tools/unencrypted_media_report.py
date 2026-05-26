"""HTTP-object classification and report rendering for live_unencrypted_scan.

Pure-Python module, no SSH, no capture side-effects.  Callable from
``tools.local_tools.live_unencrypted_scan`` after the PCAP has been
captured locally and ``tshark --export-objects http,<dir>`` has run.

Responsibilities:
  * Validate file signatures for images/videos - classify by real bytes,
    not just MIME or extension.
  * Copy validated media into per-scan ``images/`` / ``videos/`` / ``media/``.
  * Render Markdown and HTML reports with embedded previews.
"""

from __future__ import annotations

import hashlib
import html
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote


_IMAGE_EXT_HINT = {
    'jpeg': ('.jpg', '.jpeg', '.jfif'),
    'png':  ('.png',),
    'gif':  ('.gif',),
    'webp': ('.webp',),
    'bmp':  ('.bmp',),
    'svg':  ('.svg',),
}

_VIDEO_EXT_HINT = {
    'mp4':  ('.mp4', '.m4v'),
    'webm': ('.webm',),
    'ogg':  ('.ogv', '.ogg'),
    'mpeg': ('.mpeg', '.mpg'),
    'avi':  ('.avi',),
    'mov':  ('.mov', '.qt'),
}

_IMAGE_MIME_HINT = {
    'image/jpeg': 'jpeg', 'image/pjpeg': 'jpeg',
    'image/png':  'png',
    'image/gif':  'gif',
    'image/webp': 'webp',
    'image/bmp':  'bmp', 'image/x-ms-bmp': 'bmp',
    'image/svg+xml': 'svg',
}

_VIDEO_MIME_HINT = {
    'video/mp4':  'mp4',
    'video/webm': 'webm',
    'video/ogg':  'ogg', 'application/ogg': 'ogg',
    'video/mpeg': 'mpeg',
    'video/x-msvideo': 'avi',
    'video/quicktime': 'mov',
}


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _file_mime(path: Path) -> str:
    """Call `file --mime-type -b <path>`. Returns '' on any failure."""
    try:
        p = subprocess.run(
            ['file', '--mime-type', '-b', str(path)],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return (p.stdout or '').strip()
    except Exception:
        return ''


def _signature_match(head: bytes, full_small: bytes) -> tuple[str | None, str | None]:
    """Return (media_category, media_type) inferred purely from bytes.

    ``head`` is the first ~12 bytes; ``full_small`` is up to the first 2 KB,
    used for SVG text sniffing.  Either may be empty.
    """
    if len(head) >= 3 and head[0:3] == b'\xff\xd8\xff':
        return 'image', 'jpeg'
    if len(head) >= 8 and head[0:8] == b'\x89PNG\r\n\x1a\n':
        return 'image', 'png'
    if len(head) >= 6 and head[0:6] in (b'GIF87a', b'GIF89a'):
        return 'image', 'gif'
    # RIFF container - WebP / AVI differ in the 8-byte trailer.
    if len(head) >= 12 and head[0:4] == b'RIFF':
        trailer = head[8:12]
        if trailer == b'WEBP':
            return 'image', 'webp'
        if trailer == b'AVI ':
            return 'video', 'avi'
    if len(head) >= 2 and head[0:2] == b'BM':
        return 'image', 'bmp'
    # MP4 / MOV family - ``ftyp`` box at offset 4.
    if len(head) >= 8 and head[4:8] == b'ftyp':
        brand = head[8:12] if len(head) >= 12 else b''
        if brand[:2] == b'qt':
            return 'video', 'mov'
        return 'video', 'mp4'
    if len(head) >= 4 and head[0:4] == b'\x1a\x45\xdf\xa3':
        return 'video', 'webm'
    if len(head) >= 4 and head[0:4] == b'OggS':
        return 'video', 'ogg'
    if len(head) >= 4 and head[0:4] in (b'\x00\x00\x01\xba', b'\x00\x00\x01\xb3'):
        return 'video', 'mpeg'
    # SVG: text-based - look for the opening tag within the first 2 KB.
    if full_small:
        head_text = full_small[:2048].lstrip().lower()
        if head_text.startswith(b'<?xml') or head_text.startswith(b'<svg'):
            if b'<svg' in head_text[:1024]:
                return 'image', 'svg'
    return None, None


def _text_like_mime(mime: str) -> bool:
    mime = (mime or '').lower()
    return (
        mime.startswith('text/')
        or mime in ('application/javascript', 'application/json', 'application/xml')
    )


def classify_http_object(
    path: Path,
    content_type_hint: str | None = None,
    original_filename: str | None = None,
) -> dict[str, Any]:
    """Classify an exported HTTP object by file signature + MIME.

    Returns:
        {
          'mime_type': str,
          'media_category': 'image' | 'video' | 'other',
          'media_type': str | None,           # e.g. 'jpeg', 'mp4'
          'valid_media_signature': bool,
          'suspicious': bool,
          'notes': list[str],
        }

    A file is only flagged ``valid_media_signature=True`` when the real
    bytes match a known media signature. Claimed MIME/extension alone is
    never sufficient.
    """
    notes: list[str] = []
    fs_mime = _file_mime(path)
    # Prefer HTTP Content-Type when present, fall back to filesystem sniff.
    mime_type = (content_type_hint or '').split(';', 1)[0].strip().lower() or fs_mime
    if not mime_type:
        mime_type = 'application/octet-stream'

    try:
        with path.open('rb') as f:
            head = f.read(32)
            f.seek(0)
            full_small = f.read(4096)
    except Exception as exc:
        return {
            'mime_type': mime_type,
            'media_category': 'other',
            'media_type': None,
            'valid_media_signature': False,
            'suspicious': True,
            'notes': [f'Could not read bytes for classification: {exc}'],
        }

    sig_category, sig_type = _signature_match(head, full_small)

    # MIME-claimed media type
    mime_claimed: str | None = None
    mime_category: str | None = None
    for mime, mtype in _IMAGE_MIME_HINT.items():
        if mime_type == mime:
            mime_claimed = mtype
            mime_category = 'image'
            break
    if mime_claimed is None:
        for mime, mtype in _VIDEO_MIME_HINT.items():
            if mime_type == mime:
                mime_claimed = mtype
                mime_category = 'video'
                break

    # Extension-claimed media type
    ext = path.suffix.lower()
    ext_claimed: str | None = None
    ext_category: str | None = None
    for mtype, exts in _IMAGE_EXT_HINT.items():
        if ext in exts:
            ext_claimed = mtype
            ext_category = 'image'
            break
    if ext_claimed is None:
        for mtype, exts in _VIDEO_EXT_HINT.items():
            if ext in exts:
                ext_claimed = mtype
                ext_category = 'video'
                break
    # URL-encoded filenames (e.g. %2Ftest-image.jpg) from tshark.
    if ext_claimed is None and original_filename:
        try:
            decoded = unquote(original_filename)
            decoded_ext = Path(decoded).suffix.lower()
            for mtype, exts in _IMAGE_EXT_HINT.items():
                if decoded_ext in exts:
                    ext_claimed = mtype
                    ext_category = 'image'
                    break
            if ext_claimed is None:
                for mtype, exts in _VIDEO_EXT_HINT.items():
                    if decoded_ext in exts:
                        ext_claimed = mtype
                        ext_category = 'video'
                        break
        except Exception:
            pass

    # Decide final category / type / validity.
    valid_signature = False
    suspicious = False
    final_category: str
    final_type: str | None

    if sig_category and sig_type:
        final_category = sig_category
        final_type = sig_type
        valid_signature = True
        if mime_claimed and mime_claimed != sig_type:
            suspicious = True
            notes.append(
                f"MIME claimed {mime_type} ({mime_claimed}) but signature is {sig_type}."
            )
        if ext_claimed and ext_claimed != sig_type:
            suspicious = True
            notes.append(
                f"Extension {ext} implied {ext_claimed} but signature is {sig_type}."
            )
    elif mime_claimed or ext_claimed:
        # Claimed media but the bytes don't match any known signature.
        final_category = mime_category or ext_category or 'other'
        final_type = mime_claimed or ext_claimed
        valid_signature = False
        suspicious = True
        if mime_claimed:
            notes.append(
                f"MIME claims {mime_type} but file signature did not match a known {mime_claimed} signature."
            )
        elif ext_claimed:
            notes.append(
                f"Extension {ext} implies {ext_claimed} but signature did not match."
            )
    else:
        # Non-media: text/html, CSS, JS, JSON, binary blob, etc.
        final_category = 'other'
        final_type = None
        valid_signature = False

    if final_category == 'other' and _text_like_mime(mime_type):
        notes.append(f'Non-media text/data payload ({mime_type}) - stored but not previewed.')

    return {
        'mime_type': mime_type,
        'media_category': final_category,
        'media_type': final_type,
        'valid_media_signature': valid_signature,
        'suspicious': suspicious,
        'notes': notes,
    }


_UNSAFE_FNAME_CHARS = ('/', '\\', ':', '*', '?', '"', '<', '>', '|', '\x00')


def _sanitize_filename(name: str) -> str:
    """Collapse URL-encoding, strip directory components, remove unsafe chars."""
    if not name:
        return 'object'
    try:
        decoded = unquote(name)
    except Exception:
        decoded = name
    # Drop directory components tshark may have preserved.
    decoded = Path(decoded).name
    cleaned = decoded
    for bad in _UNSAFE_FNAME_CHARS:
        cleaned = cleaned.replace(bad, '_')
    cleaned = cleaned.strip(' .')
    if not cleaned:
        cleaned = 'object'
    # Keep lengths sane.
    if len(cleaned) > 120:
        p = Path(cleaned)
        cleaned = (p.stem[:100] + p.suffix) if p.suffix else p.stem[:120]
    return cleaned


def _unique_dest(dirpath: Path, filename: str, sha256: str) -> Path:
    """Return a non-colliding destination inside ``dirpath``.

    Strategy: use the sanitized ``filename`` as-is; if it already exists,
    append ``_1``, ``_2``, ...; if that too collides (shouldn't happen),
    fall back to ``<stem>_<sha256[:8]><suffix>``.
    """
    stem = Path(filename).stem
    suffix = Path(filename).suffix
    candidate = dirpath / filename
    if not candidate.exists():
        return candidate
    for i in range(1, 100):
        candidate = dirpath / f'{stem}_{i}{suffix}'
        if not candidate.exists():
            return candidate
    return dirpath / f'{stem}_{sha256[:8]}{suffix}'


def copy_into_media_dirs(
    src_path: Path,
    media_category: str,
    media_type: str | None,
    report_dir: Path,
    media_dir: Path,
    images_dir: Path,
    videos_dir: Path,
    sha256: str,
) -> dict[str, str]:
    """Copy a validated media file into ``images/`` or ``videos/`` and mirror
    it into ``media/``. Returns a dict with ``filename``, ``path``,
    ``relative_path`` (both relative to ``report_dir``).
    """
    safe_name = _sanitize_filename(src_path.name)
    # If the sanitized name lost its extension and we know the media_type,
    # append a sensible one so browsers recognize it.
    if media_type and not Path(safe_name).suffix:
        ext_fallback = {
            'jpeg': '.jpg', 'png': '.png', 'gif': '.gif', 'webp': '.webp',
            'bmp': '.bmp', 'svg': '.svg', 'mp4': '.mp4', 'webm': '.webm',
            'ogg': '.ogv', 'mpeg': '.mpeg', 'avi': '.avi', 'mov': '.mov',
        }.get(media_type, '')
        if ext_fallback:
            safe_name = safe_name + ext_fallback

    target_dir = images_dir if media_category == 'image' else videos_dir
    preview_dest = _unique_dest(target_dir, safe_name, sha256)
    shutil.copy2(src_path, preview_dest)
    media_dest = _unique_dest(media_dir, preview_dest.name, sha256)
    shutil.copy2(src_path, media_dest)

    rel_preview = preview_dest.relative_to(report_dir)
    rel_media = media_dest.relative_to(report_dir)
    return {
        'filename': preview_dest.name,
        'path': str(preview_dest),
        'relative_path': str(rel_preview),
        'media_copy_path': str(media_dest),
        'media_copy_relative_path': str(rel_media),
    }


def build_media_entry(
    src_path: Path,
    classification: dict[str, Any],
    report_dir: Path,
    media_dir: Path,
    images_dir: Path,
    videos_dir: Path,
    source_host: str | None = None,
    source_uri: str | None = None,
) -> dict[str, Any]:
    """Assemble a full ``extracted_media`` entry per the spec.

    The file is only copied into the preview directories when
    ``valid_media_signature`` is true.  ``source_uri`` / ``source_host``
    come from request/response correlation.
    """
    sha256 = _sha256_of(src_path)
    size_bytes = src_path.stat().st_size
    entry: dict[str, Any] = {
        'filename': src_path.name,
        'path': str(src_path),
        'relative_path': str(src_path.relative_to(report_dir)) if report_dir in src_path.parents else str(src_path),
        'size_bytes': size_bytes,
        'sha256': sha256,
        'mime_type': classification['mime_type'],
        'media_category': classification['media_category'],
        'media_type': classification['media_type'],
        'source_uri': source_uri,
        'source_host': source_host,
        'valid_media_signature': classification['valid_media_signature'],
        'suspicious': classification['suspicious'],
        'notes': list(classification.get('notes', [])),
    }
    if classification['valid_media_signature'] and classification['media_category'] in ('image', 'video'):
        copy_info = copy_into_media_dirs(
            src_path=src_path,
            media_category=classification['media_category'],
            media_type=classification['media_type'],
            report_dir=report_dir,
            media_dir=media_dir,
            images_dir=images_dir,
            videos_dir=videos_dir,
            sha256=sha256,
        )
        entry.update({
            'filename': copy_info['filename'],
            'path': copy_info['path'],
            'relative_path': copy_info['relative_path'],
            'media_copy_path': copy_info['media_copy_path'],
            'media_copy_relative_path': copy_info['media_copy_relative_path'],
        })
    return entry


def _fmt_size(size_bytes: int) -> str:
    if size_bytes >= 1024 * 1024:
        return f'{size_bytes / (1024 * 1024):.2f} MB'
    if size_bytes >= 1024:
        return f'{size_bytes / 1024:.1f} KB'
    return f'{size_bytes} B'


def _iso_ts_from_epoch(epoch: str | float | int | None) -> str:
    if not epoch:
        return ''
    try:
        return datetime.fromtimestamp(float(epoch)).isoformat(timespec='seconds')
    except Exception:
        return str(epoch)


def render_markdown_report(ctx: dict[str, Any]) -> str:
    """Render the scan report as Markdown.  All media paths are relative."""
    md: list[str] = []
    md.append('# Unencrypted Traffic Scan Report')
    md.append('')
    md.append(f'*Generated: {ctx.get("generated_at", datetime.now().isoformat(timespec="seconds"))}*')
    md.append('')

    # 1. Executive Summary
    md.append('## Executive Summary')
    md.append('')
    summary = ctx.get('summary', {}) or {}
    bullet_lines = [
        f'- Unencrypted traffic observed: **{"yes" if summary.get("unencrypted_observed") else "no"}**',
        f'- HTTP traffic observed: **{"yes" if summary.get("http_observed") else "no"}**',
        f'- Plaintext media extracted: **{"yes" if summary.get("media_extracted") else "no"}**',
        f'- HTTP requests: {summary.get("http_request_count", 0)}',
        f'- HTTP responses: {summary.get("http_response_count", 0)}',
        f'- HTTP objects exported: {summary.get("http_object_count", 0)}',
        f'- Images extracted: {summary.get("image_count", 0)}',
        f'- Videos extracted: {summary.get("video_count", 0)}',
        f'- Credentials / cookies / form fields: {summary.get("credential_count", 0)}',
    ]
    md.extend(bullet_lines)
    md.append('')

    # 2. Capture Details
    md.append('## Capture Details')
    md.append('')
    cap = ctx.get('capture', {}) or {}
    md.extend([
        f'- Capture mode: {cap.get("mode", "live")}',
        f'- Pineapple path: {"true" if cap.get("pineapple_path") else "false"}',
        f'- Interface: {cap.get("interface", "?")}',
        f'- Interface IP: {cap.get("interface_ip", "not determined")}',
        f'- Interface reason: {cap.get("interface_reason", "?")}',
        f'- Duration: {cap.get("duration", "?")} seconds',
        f'- PCAP: `{cap.get("pcap_path", "?")}`',
        f'- Report directory: `{cap.get("report_dir", "?")}`',
        f'- Packet count: {cap.get("packet_count", 0)}',
    ])
    if cap.get('start_time'):
        md.append(f'- Start: {cap["start_time"]}')
    if cap.get('end_time'):
        md.append(f'- End: {cap["end_time"]}')
    warnings = ctx.get('warnings') or []
    if warnings:
        md.append('- Warnings:')
        for w in warnings:
            md.append(f'  - {w}')
    md.append('')

    # 3. Plaintext Protocols Observed
    md.append('## Plaintext Protocols Observed')
    md.append('')
    protos = ctx.get('plaintext_protocols_observed') or []
    if protos:
        for p in protos:
            md.append(f'- {p}')
    else:
        md.append('- none')
    md.append('')

    # 4. HTTP Traffic Details
    md.append('## HTTP Traffic Details')
    md.append('')
    http_rows = ctx.get('http_requests') or []
    if http_rows:
        md.append('| Time | Src IP | Dst IP | Src port | Dst port | Method | Host | URI | Status | Content-Type | Content-Length | User-Agent | Notes |')
        md.append('|---|---|---|---|---|---|---|---|---|---|---|---|---|')
        for r in http_rows[:100]:
            md.append(
                '| ' + ' | '.join([
                    r.get('time', '') or '',
                    r.get('src_ip', '') or '',
                    r.get('dst_ip', '') or '',
                    str(r.get('src_port', '') or ''),
                    str(r.get('dst_port', '') or ''),
                    r.get('method', '') or '',
                    r.get('host', '') or '',
                    r.get('uri', '') or '',
                    str(r.get('response_code', '') or ''),
                    r.get('content_type', '') or '',
                    str(r.get('content_length', '') or ''),
                    (r.get('user_agent', '') or '')[:60],
                    r.get('notes', '') or '',
                ]) + ' |'
            )
    else:
        md.append('No HTTP requests observed.')
    md.append('')

    # 5. Extracted HTTP Objects
    md.append('## Extracted HTTP Objects')
    md.append('')
    objs = ctx.get('http_objects') or []
    if objs:
        md.append('| File | Path | Size | MIME | Source | SHA256 | Type | Notes |')
        md.append('|---|---|---|---|---|---|---|---|')
        for o in objs[:200]:
            source = ''
            if o.get('source_host'):
                source = o['source_host']
                if o.get('source_uri'):
                    source = f'{o["source_host"]}{o["source_uri"]}'
            md.append(
                '| ' + ' | '.join([
                    o.get('filename', '?'),
                    o.get('relative_path', ''),
                    _fmt_size(int(o.get('size_bytes', 0) or 0)),
                    o.get('mime_type', ''),
                    source,
                    (o.get('sha256', '') or '')[:16],
                    o.get('object_type', ''),
                    '; '.join(o.get('notes', []) or []),
                ]) + ' |'
            )
    else:
        md.append('No HTTP objects exported.')
    md.append('')

    # 6. Extracted Media (with preview links)
    md.append('## Extracted Media')
    md.append('')
    images = ctx.get('extracted_images') or []
    videos = ctx.get('extracted_videos') or []
    if images:
        md.append('### Images')
        md.append('')
        for m in images:
            md.append(f'#### {m.get("filename", "image")}')
            md.append('')
            md.append(f'![Extracted image]({m.get("relative_path", "")})')
            md.append('')
            md.append(f'- MIME: `{m.get("mime_type", "")}`')
            md.append(f'- Media type: {m.get("media_type", "")}')
            md.append(f'- Size: {_fmt_size(int(m.get("size_bytes", 0) or 0))}')
            md.append(f'- SHA256: `{m.get("sha256", "")}`')
            md.append(f'- Valid signature: {m.get("valid_media_signature")}')
            if m.get('source_host') or m.get('source_uri'):
                src = (m.get('source_host', '') or '') + (m.get('source_uri', '') or '')
                md.append(f'- Source: {src}')
            for n in m.get('notes', []) or []:
                md.append(f'- Note: {n}')
            md.append('')
    if videos:
        md.append('### Videos')
        md.append('')
        for m in videos:
            md.append(f'#### {m.get("filename", "video")}')
            md.append('')
            md.append(f'[Extracted video: {m.get("filename")}]({m.get("relative_path", "")})')
            md.append('')
            md.append(f'- MIME: `{m.get("mime_type", "")}`')
            md.append(f'- Media type: {m.get("media_type", "")}')
            md.append(f'- Size: {_fmt_size(int(m.get("size_bytes", 0) or 0))}')
            md.append(f'- SHA256: `{m.get("sha256", "")}`')
            md.append(f'- Valid signature: {m.get("valid_media_signature")}')
            if m.get('source_host') or m.get('source_uri'):
                src = (m.get('source_host', '') or '') + (m.get('source_uri', '') or '')
                md.append(f'- Source: {src}')
            for n in m.get('notes', []) or []:
                md.append(f'- Note: {n}')
            md.append('')
    if not images and not videos:
        md.append('No plaintext images or videos were reconstructed from the capture.')
        md.append('')

    # 7. Credentials and Sensitive Data
    md.append('## Credentials and Sensitive Data')
    md.append('')
    sensitive_findings = ctx.get('sensitive_findings') or []
    show_secrets = bool(ctx.get('show_secrets', True))
    creds = ctx.get('credentials') or []
    if sensitive_findings:
        # Defer to the credentials module renderer.
        from tools.unencrypted_credentials import render_credentials_markdown_section
        md.extend(render_credentials_markdown_section(sensitive_findings, show_secrets))
        # Include any FTP/Telnet/other non-HTTP credential lines surfaced by the
        # legacy extractor but not represented in sensitive_findings.
        legacy_extras = [
            c for c in creds
            if c.get('kind', '').startswith(('FTP', 'Telnet', 'POP', 'IMAP', 'SMTP', 'SNMP'))
        ]
        if legacy_extras:
            md.append('')
            md.append('### Other plaintext login material')
            md.append('')
            for c in legacy_extras:
                kind = c.get('kind', 'credential')
                md.append(f'- **{kind}**: {c.get("detail", "")}')
    elif creds:
        for c in creds:
            kind = c.get('kind', 'credential')
            md.append(f'- **{kind}**: {c.get("detail", "")}')
    else:
        md.append('- No HTTP Authorization headers observed.')
        md.append('- No cleartext cookies observed.')
        md.append('- No cleartext form fields observed.')
        md.append('- No FTP/Telnet/POP/IMAP login material observed.')
    md.append('')

    # 8. Limitations
    md.append('## Limitations')
    md.append('')
    lims = ctx.get('limitations') or []
    for lim in lims:
        md.append(f'- {lim}')
    md.append('')

    return '\n'.join(md)


def _html_escape(s: Any) -> str:
    return html.escape(str(s) if s is not None else '', quote=True)


def render_html_report(ctx: dict[str, Any]) -> str:
    """Render the scan report as a standalone HTML page.

    Images use ``<img src="images/...">`` and videos use
    ``<video controls><source src="videos/...">``. All paths are relative
    so the report directory can be moved or zipped as a unit.
    """
    summary = ctx.get('summary', {}) or {}
    cap = ctx.get('capture', {}) or {}
    http_rows = ctx.get('http_requests') or []
    objs = ctx.get('http_objects') or []
    images = ctx.get('extracted_images') or []
    videos = ctx.get('extracted_videos') or []
    creds = ctx.get('credentials') or []
    warnings = ctx.get('warnings') or []
    protos = ctx.get('plaintext_protocols_observed') or []
    lims = ctx.get('limitations') or []

    parts: list[str] = []
    parts.append('<!DOCTYPE html>')
    parts.append('<html lang="en"><head>')
    parts.append('<meta charset="utf-8">')
    parts.append(f'<title>Unencrypted Traffic Scan - {_html_escape(cap.get("report_ts", ""))}</title>')
    parts.append('<style>')
    parts.append(
        'body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:1100px;margin:24px auto;padding:0 18px;line-height:1.45;color:#222}'
        'h1{margin-bottom:4px}'
        'h2{border-bottom:1px solid #ccc;padding-bottom:4px;margin-top:28px}'
        'table{border-collapse:collapse;width:100%;font-size:13px;margin:8px 0}'
        'th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}'
        'th{background:#f4f4f4}'
        'code{background:#f6f6f6;padding:1px 4px;border-radius:3px}'
        'figure{margin:16px 0}'
        'figcaption{font-size:13px;color:#444;margin-top:6px}'
        '.ok{color:#185c37;font-weight:600}'
        '.no{color:#9a1f1f;font-weight:600}'
        '.warn{color:#8a5a00}'
        '.kv li{margin:2px 0}'
    )
    parts.append('</style>')
    parts.append('</head><body>')
    parts.append('<h1>Unencrypted Traffic Scan Report</h1>')
    parts.append(f'<p><em>Generated: {_html_escape(ctx.get("generated_at", datetime.now().isoformat(timespec="seconds")))}</em></p>')

    # 1. Executive Summary
    parts.append('<section id="executive-summary"><h2>Executive Summary</h2><ul class="kv">')

    def _yn(v: Any) -> str:
        return '<span class="ok">yes</span>' if v else '<span class="no">no</span>'

    parts.append(f'<li>Unencrypted traffic observed: {_yn(summary.get("unencrypted_observed"))}</li>')
    parts.append(f'<li>HTTP traffic observed: {_yn(summary.get("http_observed"))}</li>')
    parts.append(f'<li>Plaintext media extracted: {_yn(summary.get("media_extracted"))}</li>')
    parts.append(f'<li>HTTP requests: {summary.get("http_request_count", 0)}</li>')
    parts.append(f'<li>HTTP responses: {summary.get("http_response_count", 0)}</li>')
    parts.append(f'<li>HTTP objects exported: {summary.get("http_object_count", 0)}</li>')
    parts.append(f'<li>Images extracted: {summary.get("image_count", 0)}</li>')
    parts.append(f'<li>Videos extracted: {summary.get("video_count", 0)}</li>')
    parts.append(f'<li>Credentials / cookies / form fields: {summary.get("credential_count", 0)}</li>')
    parts.append('</ul></section>')

    # 2. Capture Details
    parts.append('<section id="capture-details"><h2>Capture Details</h2><ul class="kv">')
    parts.append(f'<li>Capture mode: {_html_escape(cap.get("mode", "live"))}</li>')
    parts.append(f'<li>Pineapple path: {"true" if cap.get("pineapple_path") else "false"}</li>')
    parts.append(f'<li>Interface: <code>{_html_escape(cap.get("interface", "?"))}</code></li>')
    parts.append(f'<li>Interface IP: {_html_escape(cap.get("interface_ip", "not determined"))}</li>')
    parts.append(f'<li>Interface reason: {_html_escape(cap.get("interface_reason", "?"))}</li>')
    parts.append(f'<li>Duration: {cap.get("duration", "?")} s</li>')
    parts.append(f'<li>PCAP: <code>{_html_escape(cap.get("pcap_path", "?"))}</code></li>')
    parts.append(f'<li>Report directory: <code>{_html_escape(cap.get("report_dir", "?"))}</code></li>')
    parts.append(f'<li>Packet count: {cap.get("packet_count", 0)}</li>')
    if cap.get('start_time'):
        parts.append(f'<li>Start: {_html_escape(cap["start_time"])}</li>')
    if cap.get('end_time'):
        parts.append(f'<li>End: {_html_escape(cap["end_time"])}</li>')
    parts.append('</ul>')
    if warnings:
        parts.append('<h3>Warnings</h3><ul>')
        for w in warnings:
            parts.append(f'<li class="warn">{_html_escape(w)}</li>')
        parts.append('</ul>')
    parts.append('</section>')

    # 3. Plaintext Protocols Observed
    parts.append('<section id="protocols"><h2>Plaintext Protocols Observed</h2>')
    if protos:
        parts.append('<ul>')
        for p in protos:
            parts.append(f'<li>{_html_escape(p)}</li>')
        parts.append('</ul>')
    else:
        parts.append('<p>none</p>')
    parts.append('</section>')

    # 4. HTTP Traffic Details
    parts.append('<section id="http-traffic"><h2>HTTP Traffic Details</h2>')
    if http_rows:
        parts.append('<table><thead><tr>'
                     '<th>Time</th><th>Src IP</th><th>Dst IP</th><th>Src:Port</th><th>Dst:Port</th>'
                     '<th>Method</th><th>Host</th><th>URI</th><th>Status</th>'
                     '<th>Content-Type</th><th>Content-Length</th><th>User-Agent</th><th>Notes</th>'
                     '</tr></thead><tbody>')
        for r in http_rows[:500]:
            parts.append('<tr>' + ''.join(
                f'<td>{_html_escape(v)}</td>' for v in [
                    r.get('time', ''),
                    r.get('src_ip', ''),
                    r.get('dst_ip', ''),
                    r.get('src_port', ''),
                    r.get('dst_port', ''),
                    r.get('method', ''),
                    r.get('host', ''),
                    r.get('uri', ''),
                    r.get('response_code', ''),
                    r.get('content_type', ''),
                    r.get('content_length', ''),
                    (r.get('user_agent', '') or '')[:80],
                    r.get('notes', ''),
                ]
            ) + '</tr>')
        parts.append('</tbody></table>')
    else:
        parts.append('<p>No HTTP requests observed.</p>')
    parts.append('</section>')

    # 5. Extracted HTTP Objects
    parts.append('<section id="http-objects"><h2>Extracted HTTP Objects</h2>')
    if objs:
        parts.append('<table><thead><tr>'
                     '<th>File</th><th>Path</th><th>Size</th><th>MIME</th>'
                     '<th>Source</th><th>SHA256</th><th>Type</th><th>Notes</th>'
                     '</tr></thead><tbody>')
        for o in objs[:500]:
            source = ''
            if o.get('source_host'):
                source = o['source_host']
                if o.get('source_uri'):
                    source = f'{o["source_host"]}{o["source_uri"]}'
            parts.append('<tr>' + ''.join(
                f'<td>{_html_escape(v)}</td>' for v in [
                    o.get('filename', ''),
                    o.get('relative_path', ''),
                    _fmt_size(int(o.get('size_bytes', 0) or 0)),
                    o.get('mime_type', ''),
                    source,
                    (o.get('sha256', '') or '')[:16],
                    o.get('object_type', ''),
                    '; '.join(o.get('notes', []) or []),
                ]
            ) + '</tr>')
        parts.append('</tbody></table>')
    else:
        parts.append('<p>No HTTP objects exported.</p>')
    parts.append('</section>')

    # 6. Extracted Media
    parts.append('<section id="extracted-media"><h2>Extracted Media</h2>')
    if images:
        parts.append('<h3>Images</h3>')
        for m in images:
            rel = _html_escape(m.get('relative_path', ''))
            caption_bits = []
            caption_bits.append(_html_escape(m.get('filename', '')))
            caption_bits.append(_html_escape(m.get('mime_type', '')))
            caption_bits.append(_fmt_size(int(m.get('size_bytes', 0) or 0)))
            if m.get('source_host') or m.get('source_uri'):
                src = (m.get('source_host', '') or '') + (m.get('source_uri', '') or '')
                caption_bits.append(f'source {_html_escape(src)}')
            caption_bits.append(f'sha256: {_html_escape((m.get("sha256", "") or "")[:16])}')
            caption = ' | '.join(caption_bits)
            parts.append(
                f'<figure><img src="{rel}" style="max-width:700px; border:1px solid #ccc; margin:10px 0;">'
                f'<figcaption>{caption}</figcaption></figure>'
            )
    if videos:
        parts.append('<h3>Videos</h3>')
        for m in videos:
            rel = _html_escape(m.get('relative_path', ''))
            mime = _html_escape(m.get('mime_type', 'video/mp4'))
            caption_bits = []
            caption_bits.append(_html_escape(m.get('filename', '')))
            caption_bits.append(_html_escape(m.get('mime_type', '')))
            caption_bits.append(_fmt_size(int(m.get('size_bytes', 0) or 0)))
            if m.get('source_host') or m.get('source_uri'):
                src = (m.get('source_host', '') or '') + (m.get('source_uri', '') or '')
                caption_bits.append(f'source {_html_escape(src)}')
            caption_bits.append(f'sha256: {_html_escape((m.get("sha256", "") or "")[:16])}')
            caption = ' | '.join(caption_bits)
            parts.append(
                f'<figure><video controls style="max-width:700px; border:1px solid #ccc; margin:10px 0;">'
                f'<source src="{rel}" type="{mime}">'
                'Your browser does not support the video tag.'
                '</video>'
                f'<figcaption>{caption}</figcaption></figure>'
            )
    if not images and not videos:
        parts.append('<p>No plaintext images or videos were reconstructed from the capture.</p>')
    parts.append('</section>')

    # 7. Credentials
    parts.append('<section id="credentials"><h2>Credentials and Sensitive Data</h2>')
    sensitive_findings = ctx.get('sensitive_findings') or []
    show_secrets = bool(ctx.get('show_secrets', True))
    if sensitive_findings:
        from tools.unencrypted_credentials import render_credentials_html_section
        parts.append(render_credentials_html_section(sensitive_findings, show_secrets))
        legacy_extras = [
            c for c in creds
            if c.get('kind', '').startswith(('FTP', 'Telnet', 'POP', 'IMAP', 'SMTP', 'SNMP'))
        ]
        if legacy_extras:
            parts.append('<h3>Other plaintext login material</h3><ul>')
            for c in legacy_extras:
                parts.append(f'<li><strong>{_html_escape(c.get("kind","credential"))}</strong>: {_html_escape(c.get("detail",""))}</li>')
            parts.append('</ul>')
    elif creds:
        parts.append('<ul>')
        for c in creds:
            parts.append(f'<li><strong>{_html_escape(c.get("kind", "credential"))}</strong>: {_html_escape(c.get("detail", ""))}</li>')
        parts.append('</ul>')
    else:
        parts.append('<ul>'
                     '<li>No HTTP Authorization headers observed.</li>'
                     '<li>No cleartext cookies observed.</li>'
                     '<li>No cleartext form fields observed.</li>'
                     '<li>No FTP/Telnet/POP/IMAP login material observed.</li>'
                     '</ul>')
    parts.append('</section>')

    # 8. Limitations
    parts.append('<section id="limitations"><h2>Limitations</h2><ul>')
    for lim in lims:
        parts.append(f'<li>{_html_escape(lim)}</li>')
    parts.append('</ul></section>')

    parts.append('</body></html>')
    return '\n'.join(parts)


def write_reports(report_dir: Path, ctx: dict[str, Any]) -> tuple[Path, Path]:
    """Write report.md and report.html into ``report_dir``. Returns paths."""
    md_path = report_dir / 'report.md'
    html_path = report_dir / 'report.html'
    md_text = render_markdown_report(ctx)
    html_text = render_html_report(ctx)
    md_path.write_text(md_text, encoding='utf-8')
    html_path.write_text(html_text, encoding='utf-8')
    return md_path, html_path
