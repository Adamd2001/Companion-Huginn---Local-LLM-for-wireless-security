from __future__ import annotations

import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


def _run(cmd: list[str], timeout: int = 90) -> str:
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
    stdout = (proc.stdout or '').strip()
    stderr = (proc.stderr or '').strip()
    warning = 'Running as user "root" and group "root". This could be dangerous.'
    if stderr:
        stderr = '\n'.join(line for line in stderr.splitlines() if warning not in line).strip()
    return (stdout or stderr)[-120000:]


def _parse_capinfos_value(text: str, label: str) -> str | None:
    for line in text.splitlines():
        if label.lower() in line.lower():
            parts = line.split(':', 1)
            if len(parts) == 2:
                return parts[1].strip()
    return None


def _parse_capinfos_packets(text: str) -> int | None:
    """Parse the packet count from `capinfos` output.

    capinfos's default output uses SI suffixes for large counts
    (`Number of packets:   1.5 k`, `1.2 M`, etc.). The previous parser only
    extracted the integer prefix, so 1500 packets came back as 1, 29000 as 29,
    and so on. We now honor the suffixes. Use `capinfos -M` for raw integers
    when possible - this parser is the fallback path.
    """
    raw = _parse_capinfos_value(text, 'Number of packets')
    if not raw:
        return None
    raw = raw.strip()
    m = re.search(r'(\d[\d,]*(?:\.\d+)?)\s*([kKmMgGtT]?)', raw)
    if not m:
        return None
    number_part = m.group(1).replace(',', '')
    suffix = (m.group(2) or '').lower()
    multipliers = {'': 1, 'k': 1_000, 'm': 1_000_000, 'g': 1_000_000_000, 't': 1_000_000_000_000}
    try:
        return int(round(float(number_part) * multipliers.get(suffix, 1)))
    except ValueError:
        return None


def _exact_packet_count_via_tshark(pcap: str) -> int | None:
    """Single source of truth for packet count.

    Uses `tshark -r <pcap> -T fields -e frame.number` and counts non-empty
    lines. This is exact (no SI rounding) and is the value used everywhere
    `packet_count` appears in the report. capinfos is only consulted as a
    fallback if tshark itself is unavailable.
    """
    try:
        proc = subprocess.run(
            ['tshark', '-r', pcap, '-T', 'fields', '-e', 'frame.number'],
            text=True, capture_output=True, timeout=120, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 and not proc.stdout:
        return None
    return sum(
        1 for ln in (proc.stdout or '').splitlines()
        if ln.strip() and not ln.strip().startswith('tshark:')
    )


def _traffic_activity(packet_count: int | None) -> str | None:
    if packet_count is None:
        return None
    if packet_count < 100:
        return 'very low'
    if packet_count < 1000:
        return 'low'
    if packet_count < 5000:
        return 'moderate'
    if packet_count < 20000:
        return 'high'
    return 'very high'


def _count_lines(cmd: list[str], timeout: int = 60) -> int:
    raw = _run(cmd, timeout=timeout)
    return len([x for x in raw.splitlines() if x.strip() and not x.strip().startswith('tshark:')])


def _count_field_values(cmd: list[str], timeout: int = 60) -> Counter[str]:
    raw = _run(cmd, timeout=timeout)
    counts: Counter[str] = Counter()
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith('tshark:'):
            counts[line] += 1
    return counts


def _top_records(counter: Counter[str], limit: int = 20, key_name: str = 'name') -> list[dict[str, Any]]:
    return [{key_name: name, 'count': count} for name, count in counter.most_common(limit)]


def _extract_protocol_activity(pcap: str) -> dict[str, Any]:
    protocols = {
        'arp': 'arp', 'dhcp': 'bootp || dhcp', 'dns': 'dns', 'mdns': 'mdns', 'nbns': 'nbns', 'ssdp': 'ssdp',
        'icmp': 'icmp', 'icmpv6': 'icmpv6', 'http': 'http', 'tls': 'tls', 'quic': 'quic', 'ftp': 'ftp',
        'telnet': 'telnet', 'smtp': 'smtp', 'pop': 'pop', 'imap': 'imap', 'ntp': 'ntp', 'rtp': 'rtp', 'sip': 'sip',
        'tcp': 'tcp', 'udp': 'udp',
    }
    counts: dict[str, int] = {}
    for name, filt in protocols.items():
        counts[name] = _count_lines(['tshark', '-r', pcap, '-Y', filt, '-T', 'fields', '-e', 'frame.number'])
    return {'protocol_counts': counts}


def _extract_dns_and_tls(pcap: str) -> dict[str, Any]:
    dns_counts = _count_field_values(['tshark', '-r', pcap, '-Y', 'dns.qry.name', '-T', 'fields', '-e', 'dns.qry.name'])
    sni_counts = _count_field_values(['tshark', '-r', pcap, '-Y', 'tls.handshake.extensions_server_name', '-T', 'fields', '-e', 'tls.handshake.extensions_server_name'])
    return {
        'top_dns_queries': _top_records(dns_counts, limit=25, key_name='name'),
        'top_tls_sni': _top_records(sni_counts, limit=25, key_name='name'),
    }


def _extract_port_activity(pcap: str) -> dict[str, Any]:
    # Use separate srcport/dstport fields to avoid "port1,port2" paired strings.
    tcp_src = _count_field_values(['tshark', '-r', pcap, '-Y', 'tcp', '-T', 'fields', '-e', 'tcp.srcport'])
    tcp_dst = _count_field_values(['tshark', '-r', pcap, '-Y', 'tcp', '-T', 'fields', '-e', 'tcp.dstport'])
    tcp_ports: Counter[str] = Counter()
    for port, count in tcp_src.items():
        tcp_ports[port] += count
    for port, count in tcp_dst.items():
        tcp_ports[port] += count

    udp_src = _count_field_values(['tshark', '-r', pcap, '-Y', 'udp', '-T', 'fields', '-e', 'udp.srcport'])
    udp_dst = _count_field_values(['tshark', '-r', pcap, '-Y', 'udp', '-T', 'fields', '-e', 'udp.dstport'])
    udp_ports: Counter[str] = Counter()
    for port, count in udp_src.items():
        udp_ports[port] += count
    for port, count in udp_dst.items():
        udp_ports[port] += count

    return {
        'top_tcp_ports': _top_records(tcp_ports, limit=20, key_name='port'),
        'top_udp_ports': _top_records(udp_ports, limit=20, key_name='port'),
    }


def _extract_ip_activity(pcap: str) -> dict[str, Any]:
    ip_src = _count_field_values(['tshark', '-r', pcap, '-Y', 'ip.src', '-T', 'fields', '-e', 'ip.src'])
    ip_dst = _count_field_values(['tshark', '-r', pcap, '-Y', 'ip.dst', '-T', 'fields', '-e', 'ip.dst'])
    return {
        'top_ip_sources': _top_records(ip_src, limit=20, key_name='ip'),
        'top_ip_destinations': _top_records(ip_dst, limit=20, key_name='ip'),
    }


def _extract_plaintext_indicators(pcap: str) -> dict[str, Any]:
    checks = [('http', 'http'), ('ftp', 'ftp'), ('telnet', 'telnet'), ('smtp', 'smtp'), ('pop', 'pop'), ('imap', 'imap')]
    hits: list[dict[str, Any]] = []
    for name, filt in checks:
        count = _count_lines(['tshark', '-r', pcap, '-Y', filt, '-T', 'fields', '-e', 'frame.number'])
        if count:
            hits.append({'protocol': name, 'count': count})
    auth_count = _count_lines(['tshark', '-r', pcap, '-Y', 'http.authorization || http.proxy_authorization', '-T', 'fields', '-e', 'frame.number'])
    return {
        'plaintext_protocols_observed': hits,
        'http_auth_headers_observed': [{'count': auth_count}] if auth_count else [],
        'unencrypted_traffic_observed': bool(hits or auth_count),
    }


def _extract_tcp_udp_conversations(pcap: str) -> dict[str, Any]:
    return {
        'tcp_conversations_text': _run(['tshark', '-r', pcap, '-q', '-z', 'conv,tcp']),
        'udp_conversations_text': _run(['tshark', '-r', pcap, '-q', '-z', 'conv,udp']),
    }


def _is_locally_administered(mac: str) -> bool:
    try:
        return bool(int(mac.split(':')[0], 16) & 0x02)
    except Exception:
        return False


def _is_multicast_or_broadcast(mac: str) -> bool:
    """Return True for broadcast, IPv4/IPv6 multicast, and other reserved MACs."""
    mac_lower = mac.lower().strip()
    if mac_lower in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
        return True
    try:
        first_octet = int(mac_lower.split(':')[0], 16)
        # Multicast bit is bit 0 of the first octet
        return bool(first_octet & 0x01)
    except Exception:
        return False


def _is_likely_sibling_radio(mac: str, focus_bssid: str) -> bool:
    """Return True when *mac* looks like a sibling radio of *focus_bssid*.

    Many consumer APs and enterprise controllers expose multiple BSSIDs that
    share the same OUI (first 3 octets) and differ only slightly in the last
    3 octets - e.g. AA:BB:CC:DD:EE:81 (2.4 GHz) vs AA:BB:CC:DD:EE:7D
    (5 GHz management radio). These siblings are infrastructure, not clients,
    but they may never appear as a wlan.bssid in the capture so the existing
    infrastructure_macs exclusion misses them.

    Heuristic: same OUI AND last-3-octet integer distance <= 16.
    """
    try:
        mac_parts = mac.lower().split(':')
        bssid_parts = focus_bssid.lower().split(':')
        if len(mac_parts) != 6 or len(bssid_parts) != 6:
            return False
        # Same OUI (first 3 octets)?
        if mac_parts[:3] != bssid_parts[:3]:
            return False
        # Integer distance of last 3 octets
        mac_tail = int(''.join(mac_parts[3:]), 16)
        bssid_tail = int(''.join(bssid_parts[3:]), 16)
        return abs(mac_tail - bssid_tail) <= 16
    except Exception:
        return False


def _extract_client_confidence(
    pcap: str,
    focus_bssid: str | None = None,
    exclude_macs: set[str] | None = None,
    infrastructure_macs: set[str] | None = None,
) -> dict[str, Any]:
    """Build confidence-rated client lists for the focus BSSID.

    Counting rules (correct as of this version):
    - Frames are filtered to `wlan.bssid == focus_bssid` so we only consider
      packets in this BSS.
    - For each frame, the four 802.11 address fields (sa/da/ta/ra) are folded
      into a SET, so a single frame contributes AT MOST 1 to a given MAC's
      `frames_seen`. The previous version incremented per-field, which meant
      one frame contributed 2-4 to the same client (because data frames have
      sa==ta or da==ra), inflating per-client counts beyond the total packet
      count.
    - Excludes:
        * the focus BSSID itself
        * broadcast / multicast / 00:00:00:00:00:00
        * any MAC bound to a Pineapple iface (`exclude_macs`)
        * any MAC that acts as a wlan.bssid anywhere in the capture
          (`infrastructure_macs`) - this catches sibling radios of the same
          physical AP and other infrastructure
    """
    # Lower-case all exclusion sets so comparisons match the lower-case
    # tshark output.
    excl_lower: set[str] = {m.lower() for m in (exclude_macs or set())}
    infra_lower: set[str] = {m.lower() for m in (infrastructure_macs or set())}

    # Auto-detect dominant BSSID if not provided.
    if not focus_bssid:
        raw_bssids = _run(
            ['tshark', '-r', pcap, '-T', 'fields', '-e', 'wlan.bssid'],
            timeout=60,
        )
        bssid_counts: Counter[str] = Counter()
        for line in raw_bssids.splitlines():
            b = line.strip().lower()
            if b and b != 'ff:ff:ff:ff:ff:ff' and re.match(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$', b):
                bssid_counts[b] += 1
        if bssid_counts:
            focus_bssid = bssid_counts.most_common(1)[0][0]

    if not focus_bssid:
        return {
            'confirmed_clients': [],
            'high_confidence_clients': [],
            'low_confidence_clients': [],
            'excluded_pineapple_macs': sorted(excl_lower),
            'excluded_infrastructure_macs': sorted(infra_lower),
        }

    focus_bssid = focus_bssid.lower()
    raw = _run([
        'tshark', '-r', pcap,
        '-Y', f'wlan.bssid == {focus_bssid}',
        '-T', 'fields',
        '-e', 'wlan.sa', '-e', 'wlan.da', '-e', 'wlan.ta', '-e', 'wlan.ra',
        '-e', 'wlan.fc.type', '-e', 'wlan.fc.type_subtype',
    ], timeout=120)

    score: Counter[str] = Counter()
    mgmt_score: Counter[str] = Counter()
    data_score: Counter[str] = Counter()
    total_focus_frames = 0

    def _mac_should_skip(mac: str) -> bool:
        if not mac:
            return True
        if mac == focus_bssid:
            return True
        if mac in excl_lower:
            return True
        if mac in infra_lower:
            return True
        if _is_multicast_or_broadcast(mac):
            return True
        return False

    # Track MACs that look like sibling radios - they get demoted, not
    # placed in confirmed/high/low client buckets.
    sibling_macs: set[str] = set()

    for line in raw.splitlines():
        parts = line.split('\t')
        if len(parts) < 6:
            continue
        total_focus_frames += 1
        sa, da, ta, ra, ftype, subtype = [(x or '').strip().lower() for x in parts[:6]]
        # Dedupe per-frame: one frame may carry the same MAC in multiple
        # address fields. Each MAC contributes at most 1 to frames_seen.
        unique_macs_this_frame = {sa, da, ta, ra}
        for mac in unique_macs_this_frame:
            if _mac_should_skip(mac):
                continue
            score[mac] += 1
            if ftype == '2':
                data_score[mac] += 1
            elif ftype == '0':
                mgmt_score[mac] += 1

    confirmed: list[dict[str, Any]] = []
    high: list[dict[str, Any]] = []
    low: list[dict[str, Any]] = []
    infra_suspects: list[dict[str, Any]] = []
    for mac, total in score.most_common(50):
        # Sanity clamp: a single MAC cannot have appeared in more frames than
        # the total number of frames we actually scanned for the focus BSSID.
        clamped_total = min(int(total), total_focus_frames)
        clamped_data = min(int(data_score.get(mac, 0)), clamped_total)
        clamped_mgmt = min(int(mgmt_score.get(mac, 0)), clamped_total)
        rec = {
            'mac': mac,
            'frames_seen': clamped_total,
            'data_frames': clamped_data,
            'mgmt_frames': clamped_mgmt,
            'locally_administered': _is_locally_administered(mac),
        }

        # Sibling-radio check: same OUI + small last-octet delta → almost
        # certainly infrastructure, not a real client. Demote to a separate
        # list so the operator can see them but they never get used for deauth.
        if focus_bssid and _is_likely_sibling_radio(mac, focus_bssid):
            rec['confidence'] = 'infrastructure_suspect'
            rec['sibling_suspect'] = True
            infra_suspects.append(rec)
            sibling_macs.add(mac)
            continue

        if clamped_data >= 4:
            rec['confidence'] = 'confirmed'
            confirmed.append(rec)
        elif clamped_data >= 2 or clamped_mgmt >= 4:
            rec['confidence'] = 'high'
            high.append(rec)
        else:
            rec['confidence'] = 'low'
            low.append(rec)
    return {
        'confirmed_clients': confirmed[:15],
        'high_confidence_clients': high[:20],
        'low_confidence_clients': low[:20],
        'infrastructure_suspects': infra_suspects[:10],
        'focus_bssid_frame_count': total_focus_frames,
        'excluded_pineapple_macs': sorted(excl_lower),
        'excluded_infrastructure_macs': sorted(infra_lower),
        'excluded_sibling_macs': sorted(sibling_macs),
    }


def quick_handshake_check(pcap_path: str) -> dict[str, Any]:
    """
    Quickly determine whether a PCAP contains a usable WPA handshake or PMKID.

    Uses hcxpcapngtool (preferred) or falls back to tshark EAPOL frame count.

    Returns:
        dict with ok, has_handshake, eapol_count, networks_found, method, and detail.
    """
    p = Path(pcap_path)
    if not p.exists():
        return {'ok': False, 'error': f'PCAP not found: {p}', 'has_handshake': False}

    # Try hcxpcapngtool first - writes to a temp file to avoid creating permanent files
    try:
        with tempfile.NamedTemporaryFile(suffix='.22000', delete=True) as _tf:
            proc = subprocess.run(
                ['hcxpcapngtool', '-o', _tf.name, str(p)],
                text=True, capture_output=True, timeout=60, check=False,
            )
        output = (proc.stdout or '') + '\n' + (proc.stderr or '')
        # hcxpcapngtool prints "written to ..." or "networks written: N"
        networks_match = re.search(r'networks? written[:\s]+(\d+)', output, re.IGNORECASE)
        hashes_match = re.search(r'(\d+)\s+(?:WPA|PMKID|hash)', output, re.IGNORECASE)
        networks_found = int(networks_match.group(1)) if networks_match else (
            int(hashes_match.group(1)) if hashes_match else None
        )
        if networks_found is not None:
            has_handshake = networks_found > 0
            return {
                'ok': True,
                'has_handshake': has_handshake,
                'networks_found': networks_found,
                'eapol_count': None,
                'method': 'hcxpcapngtool',
                'detail': output.strip()[-500:],
            }
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: tshark EAPOL count
    eapol_proc = subprocess.run(
        ['tshark', '-r', str(p), '-Y', 'eapol', '-T', 'fields', '-e', 'frame.number'],
        text=True, capture_output=True, timeout=60, check=False,
    )
    eapol_lines = [ln for ln in (eapol_proc.stdout or '').splitlines() if ln.strip()]
    eapol_count = len(eapol_lines)
    has_handshake = eapol_count >= 2
    return {
        'ok': True,
        'has_handshake': has_handshake,
        'networks_found': None,
        'eapol_count': eapol_count,
        'method': 'tshark_eapol',
        'detail': f'{eapol_count} EAPOL frame(s) found',
    }


def wifi_deep_report(
    pcap_path: str,
    focus_bssid: str | None = None,
    exclude_macs: set[str] | None = None,
) -> dict[str, Any]:
    """Build a passive analysis report for a captured PCAP.

    Args:
        pcap_path:    Path to the local PCAP/PCAPNG file.
        focus_bssid:  Optional BSSID to focus client/EAPOL analysis on. The
                      capture itself is not filtered; this only narrows the
                      per-client correlation step.
        exclude_macs: Optional set of MACs to exclude from observed_clients
                      lists. Used by the registry to remove the Pineapple's
                      own iface MACs from results.
    """
    p = Path(pcap_path)
    if not p.exists():
        raise FileNotFoundError(f'PCAP not found: {p}')

    # Authoritative packet count via tshark. capinfos is consulted only for
    # capture_duration and as a packet-count fallback if tshark itself failed.
    # The previous implementation used capinfos's default (SI-suffixed) output
    # and parsed "29 k" as 29, which made packet_count smaller than the EAPOL
    # frame count and the per-client frame totals.
    capinfos_text = _run(['capinfos', str(p)], timeout=45)
    capture_duration = _parse_capinfos_value(capinfos_text, 'Capture duration')

    tshark_packet_count = _exact_packet_count_via_tshark(str(p))
    capinfos_packet_count = _parse_capinfos_packets(capinfos_text)
    if tshark_packet_count is not None:
        packet_count: int | None = tshark_packet_count
        packet_count_source = 'tshark'
    else:
        packet_count = capinfos_packet_count
        packet_count_source = 'capinfos'

    bssid_counts = _count_field_values(['tshark', '-r', str(p), '-T', 'fields', '-e', 'wlan.bssid'], timeout=120)
    # Use wlan.ssid (corrected from deprecated wlan_mgt.ssid)
    ssid_counts = _count_field_values(['tshark', '-r', str(p), '-Y', 'wlan.ssid', '-T', 'fields', '-e', 'wlan.ssid'], timeout=120)
    deauth_frames = _count_lines(['tshark', '-r', str(p), '-Y', 'wlan.fc.type_subtype==0x0c', '-T', 'fields', '-e', 'frame.number'])
    disassoc_frames = _count_lines(['tshark', '-r', str(p), '-Y', 'wlan.fc.type_subtype==0x0a', '-T', 'fields', '-e', 'frame.number'])
    eapol_frames = _count_lines(['tshark', '-r', str(p), '-Y', 'eapol', '-T', 'fields', '-e', 'frame.number'])

    # Build the infrastructure-MAC exclusion set: any MAC that ever appeared
    # as a wlan.bssid in this capture is by definition an AP / infrastructure
    # device and must NOT be classified as a client. This catches sibling
    # radios from the same physical AP automatically.
    infrastructure_macs: set[str] = set()
    for raw_bssid in bssid_counts.keys():
        b = raw_bssid.strip().lower()
        if b and b != 'ff:ff:ff:ff:ff:ff' and re.match(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$', b):
            infrastructure_macs.add(b)

    protocol = _extract_protocol_activity(str(p))
    ports = _extract_port_activity(str(p))
    ips = _extract_ip_activity(str(p))
    dns_tls = _extract_dns_and_tls(str(p))
    plain = _extract_plaintext_indicators(str(p))
    convs = _extract_tcp_udp_conversations(str(p))
    clients = _extract_client_confidence(
        str(p),
        focus_bssid=focus_bssid,
        exclude_macs=exclude_macs,
        infrastructure_macs=infrastructure_macs,
    )

    all_clients = clients['confirmed_clients'] + clients['high_confidence_clients'] + clients['low_confidence_clients']

    # Reconciliation: every per-client frames_seen must be <= packet_count.
    # If anything still exceeds it (e.g. tshark count was unavailable and
    # capinfos under-reported), surface the inconsistency in the report
    # rather than silently passing it through.
    count_inconsistencies: list[str] = []
    if isinstance(packet_count, int):
        for c in all_clients:
            try:
                if int(c.get('frames_seen', 0)) > packet_count:
                    count_inconsistencies.append(
                        f"client {c.get('mac')} frames_seen={c['frames_seen']} > packet_count={packet_count}"
                    )
            except (TypeError, ValueError):
                pass
        if eapol_frames > packet_count:
            count_inconsistencies.append(
                f"eapol_frames_seen={eapol_frames} > packet_count={packet_count}"
            )

    report: dict[str, Any] = {
        'pcap_path': str(p.resolve()),
        'packet_count': packet_count,
        'packet_count_source': packet_count_source,
        'packet_count_capinfos_raw': capinfos_packet_count,
        'capture_duration': capture_duration,
        'traffic_activity': _traffic_activity(packet_count),
        'eapol_frames_seen': eapol_frames,
        'deauth_frames': deauth_frames,
        'disassoc_frames': disassoc_frames,
        'observed_ssids': [ssid for ssid, _ in ssid_counts.most_common(30)],
        'ssid_counts': dict(ssid_counts),
        'top_bssids': [b for b, _ in bssid_counts.most_common(20)],
        'bssid_counts': dict(bssid_counts),
        # All four client fields must agree.  The tier lists from
        # _extract_client_confidence are already individually capped
        # (15 / 20 / 20).  observed_clients and client_count are derived
        # from them so there is exactly one source of truth.
        'observed_clients': (clients['confirmed_clients']
                             + clients['high_confidence_clients']
                             + clients['low_confidence_clients']),
        'client_count': (len(clients['confirmed_clients'])
                         + len(clients['high_confidence_clients'])
                         + len(clients['low_confidence_clients'])),
        'confirmed_clients': clients['confirmed_clients'],
        'high_confidence_clients': clients['high_confidence_clients'],
        'low_confidence_clients': clients['low_confidence_clients'],
        'randomized_local_mac_count': sum(1 for c in all_clients if c.get('locally_administered')),
        'focus_bssid': focus_bssid,
        'focus_bssid_frame_count': clients.get('focus_bssid_frame_count', 0),
        'excluded_pineapple_macs': clients.get('excluded_pineapple_macs', []),
        'excluded_infrastructure_macs': clients.get('excluded_infrastructure_macs', []),
        'count_inconsistencies': count_inconsistencies,
        'observation_limits': [
            'This is a passive capture summary.',
            'Client confidence is derived from observed frame relationships and is not perfect.',
            'Pineapple-owned MACs and any MAC that acts as a wlan.bssid in this capture are excluded from observed_clients.',
            'On encrypted Wi-Fi, application payload visibility may be limited or absent without decodable traffic.',
            'No active authentication or cracking was performed by this report function.',
        ],
        'raw_text': '',
    }
    report.update(protocol)
    report.update(ports)
    report.update(ips)
    report.update(dns_tls)
    report.update(plain)
    report.update(convs)

    lines = [
        f'PCAP: {p.resolve()}', '', '=== capinfos ===', capinfos_text or '<no output>', '',
        '=== Disruption indicators ===', f'Deauth frames: {deauth_frames}', f'Disassoc frames: {disassoc_frames}', '',
        '=== WPA/EAPOL indicators ===', f'EAPOL frames: {eapol_frames}', '',
        '=== Top BSSIDs ==='
    ]
    if bssid_counts:
        for b, n in bssid_counts.most_common(20):
            lines.append(f'- {b} ({n})')
    else:
        lines.append('<none>')
    lines.extend(['', '=== Focused client confidence ==='])
    for bucket in ['confirmed_clients', 'high_confidence_clients', 'low_confidence_clients']:
        lines.append(f'{bucket}:')
        items = report[bucket]
        if items:
            for item in items[:15]:
                lines.append(f"- {item['mac']} | frames={item['frames_seen']} data={item['data_frames']} mgmt={item['mgmt_frames']} confidence={item['confidence']}")
        else:
            lines.append('<none>')
    lines.extend(['', '=== Protocol counts ==='])
    for proto_name, count in sorted(report['protocol_counts'].items(), key=lambda x: (-x[1], x[0])):
        lines.append(f'- {proto_name}: {count}')
    report['raw_text'] = '\n'.join(lines)
    return report
