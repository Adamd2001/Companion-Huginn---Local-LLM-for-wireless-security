from __future__ import annotations

import os
import re
from typing import Any, Callable

from tools.advanced_tools import generate_report, plan_audit, write_finding
from tools.latest_pcap import latest_pcap
from tools.local_tools import (
    crack_wifi_pcap,
    enable_ip_forwarding,
    extract_handshake_hash,
    live_unencrypted_scan,
    read_file,
    run_allowlisted_app,
    run_allowlisted_command,
    run_arpspoof,
    run_hashcat,
    run_john,
    run_nmap_scan,
    scan_unencrypted_traffic,
    stop_arpspoof,
)
from tools.pcap_summarize import summarize_pcap
from tools.pineapple import capture_pcap
from tools.pineapple_helpers import (
    _check_connectivity,
    _pine_cfg,
    enable_monitor_mode,
    get_pineapple_iface_macs,
    pineapple_analyze_ssid,
    pineapple_arpspoof,
    pineapple_connect,
    pineapple_deauth_and_capture,
    pineapple_deauth_and_capture_hcx,
    pineapple_logs,
    pineapple_nearby_ssids,
    pineapple_nmap_scan,
    pineapple_status,
    pineapple_stop_arpspoof,
    pineapple_subnet_map,
    pineapple_wifi_snapshot,
)
from tools.tshark_deep import deep_review_with_tshark
from tools.tshark_summarize import summarize_with_tshark
from tools.wifi_deep_report import quick_handshake_check, wifi_deep_report


_VALID_IFACE_RE = re.compile(r'^[A-Za-z0-9._\-]+$')


def _sanitize_iface(name: Any, default: str = 'wlan1mon') -> str:
    """Strip control / decoration chars and validate against the iface charset.

    Some firmwares + airmon-ng combinations can leak ANSI escapes or marker
    characters (e.g. '**') into interface name strings parsed from shell output.
    This guard guarantees we never pass a corrupted iface name into tcpdump,
    iw, or any error message.
    """
    if not name:
        return default
    cleaned = re.sub(r'[^A-Za-z0-9._\-]', '', str(name)).strip()
    if cleaned and _VALID_IFACE_RE.match(cleaned):
        return cleaned
    return default


def _require_confirmation(cfg: dict[str, Any]) -> None:
    policy = cfg['policy']
    # Default is False - confirmation NOT required unless explicitly configured.
    if not policy.get('execution', {}).get('require_confirmation_env', False):
        return
    env_var = policy.get('execution', {}).get('confirmation_env_var', 'HUGINN_CONFIRM')
    required_value = policy.get('execution', {}).get('confirmation_required_value', 'approved')
    if os.environ.get(env_var, '') != required_value:
        raise PermissionError(f'Controlled action blocked. Set {env_var}={required_value} to allow execution.')


def _looks_default_ssid(ssid: str) -> dict[str, Any]:
    lowered = (ssid or '').strip().lower()
    patterns = [
        r'^spectrumsetup[-_a-z0-9]+$', r'^myspectrumwifi[a-z0-9\-_]+$', r'^verizon[_\-a-z0-9]+$',
        r'^xfinity[a-z0-9\-_]*$', r'^att[a-z0-9\-_]*$', r'^linksys[a-z0-9\-_]*$', r'^netgear[a-z0-9\-_]*$',
        r'^orbi[a-z0-9\-_]*$', r'^tp-link[a-z0-9\-_]*$', r'^tmobile[a-z0-9\-_]*$', r'^default[a-z0-9\-_]*$',
    ]
    looks_isp_default = any(re.match(p, lowered) for p in patterns)
    has_serialish_suffix = bool(re.search(r'([a-f0-9]{4,}|[0-9]{4,})$', lowered))
    return {'looks_default': looks_isp_default or has_serialish_suffix, 'looks_isp_default': looks_isp_default, 'has_serialish_suffix': has_serialish_suffix}


def _heuristic_credential_risk(ssid: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    score = 0
    ssid_profile = _looks_default_ssid(ssid)
    if ssid_profile['looks_default']:
        score += 2
        reasons.append('default-style or ISP-style SSID naming pattern observed')
    security = str(snapshot.get('security', '')).upper()
    if 'OPEN' in security or 'NONE' in security:
        score += 4
        reasons.append('open or unencrypted network indication observed')
    elif 'WEP' in security:
        score += 4
        reasons.append('WEP observed')
    elif 'WPA2' in security and 'WPA3' not in security and 'SAE' not in security:
        score += 2
        reasons.append('WPA2-PSK without WPA3/SAE observed')
    elif 'WPA3' in security or 'SAE' in security:
        reasons.append('WPA3/SAE observed')
    if snapshot.get('wps_present') is True:
        score += 2
        reasons.append('WPS present')
    if snapshot.get('pmf_present') is False and ('WPA3' not in security and 'SAE' not in security):
        score += 1
        reasons.append('PMF not observed')
    return {
        'level': 'elevated' if score >= 5 else 'moderate' if score >= 3 else 'low',
        'reason': '; '.join(reasons) if reasons else 'insufficient passive indicators for a stronger heuristic',
        'ssid_profile': ssid_profile,
        'warning': 'Passive observation cannot verify the actual password or prove password strength.',
    }


def _merge_snapshot_with_report(ssid: str, snapshot: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    signal = snapshot.get('signal_dbm')
    assessment_notes: list[str] = []
    if isinstance(signal, (int, float)):
        if signal >= -45:
            assessment_notes.append('AP appears very close based on strong observed signal.')
        elif signal >= -67:
            assessment_notes.append('AP signal appears strong.')
        elif signal >= -75:
            assessment_notes.append('AP signal appears usable but not strong.')
        else:
            assessment_notes.append('AP signal appears weak or distant.')
    if snapshot.get('security'):
        assessment_notes.append(f"Passive security observation: {snapshot['security']}.")
    if isinstance(report.get('client_count'), int):
        assessment_notes.append(f"Observed {report['client_count']} client candidate(s) during the capture window.")
    if report.get('confirmed_clients'):
        assessment_notes.append(f"Confirmed client candidates: {len(report['confirmed_clients'])}.")
    elif report.get('high_confidence_clients'):
        assessment_notes.append(f"High-confidence client candidates: {len(report['high_confidence_clients'])}.")
    # Note: L3/L4 data (protocol counts, DNS, TLS, ports, IPs) is still
    # collected in the underlying report dict but is NOT surfaced by the
    # deep SSID analysis formatter. No channel-wide caveat is needed here.
    return {
        'ok': True,
        'ssid': snapshot.get('ssid', ssid), 'bssid': snapshot.get('bssid'), 'channel': snapshot.get('channel'), 'signal_dbm': snapshot.get('signal_dbm'),
        'security': snapshot.get('security'), 'wps_present': snapshot.get('wps_present'), 'pmf_present': snapshot.get('pmf_present'),
        'hidden_ssid': snapshot.get('hidden_ssid'), 'observed_clients': report.get('observed_clients', []), 'client_count': report.get('client_count'),
        'confirmed_clients': report.get('confirmed_clients', []), 'high_confidence_clients': report.get('high_confidence_clients', []), 'low_confidence_clients': report.get('low_confidence_clients', []),
        'traffic_activity': report.get('traffic_activity'), 'eapol_frames_seen': report.get('eapol_frames_seen'), 'handshake_like_activity_seen': bool(report.get('eapol_frames_seen', 0)),
        'observed_ssids': report.get('observed_ssids', []), 'ssid_counts': report.get('ssid_counts', {}), 'top_bssids': report.get('top_bssids', []), 'bssid_counts': report.get('bssid_counts', {}),
        'randomized_local_mac_count': report.get('randomized_local_mac_count'), 'protocol_counts': report.get('protocol_counts', {}), 'top_tcp_ports': report.get('top_tcp_ports', []),
        'top_udp_ports': report.get('top_udp_ports', []), 'top_ip_sources': report.get('top_ip_sources', []), 'top_ip_destinations': report.get('top_ip_destinations', []),
        'top_dns_queries': report.get('top_dns_queries', []), 'top_tls_sni': report.get('top_tls_sni', []), 'tcp_conversations_text': report.get('tcp_conversations_text', ''),
        'udp_conversations_text': report.get('udp_conversations_text', ''), 'plaintext_protocols_observed': report.get('plaintext_protocols_observed', []),
        'http_auth_headers_observed': report.get('http_auth_headers_observed', []), 'unencrypted_traffic_observed': report.get('unencrypted_traffic_observed', False),
        'credential_risk_estimate': _heuristic_credential_risk(ssid, snapshot), 'assessment_notes': assessment_notes,
        'observation_limits': report.get('observation_limits', []), 'packet_count': report.get('packet_count'), 'capture_duration': report.get('capture_duration'),
        'focus_bssid_packet_count': report.get('focus_bssid_frame_count', 0),
        'pcap_path': report.get('pcap_path'), 'pcap_report': report, 'snapshot': snapshot,
    }


def build_registry(cfg: dict[str, Any]) -> dict[str, Callable[[dict], dict]]:
    allowlist = cfg['allowlist']
    policy = cfg['policy']

    def action_latest_pcap(tool_call: dict) -> dict:
        return {'ok': True, 'pcap_path': latest_pcap()}

    def action_hashcat(tool_call: dict[str, Any]) -> dict[str, Any]:
        return run_hashcat(tool_call.get('args', []), custom_mask=tool_call.get('custom_mask'))

    def action_john(tool_call: dict[str, Any]) -> dict[str, Any]:
        return run_john(tool_call.get('args', []))

    def action_arpspoof(tool_call: dict[str, Any]) -> dict[str, Any]:
        return run_arpspoof(tool_call.get('target_ip'), tool_call.get('gateway_ip'), tool_call.get('interface', 'eth0'))

    def action_stop_arpspoof(tool_call: dict[str, Any]) -> dict[str, Any]:
        pid = tool_call.get('pid')
        return stop_arpspoof(int(pid) if pid else None)

    def action_pineapple_arpspoof(tool_call: dict[str, Any]) -> dict[str, Any]:
        return pineapple_arpspoof(
            tool_call.get('target_ip'),
            tool_call.get('gateway_ip') or tool_call.get('peer_ip'),
            cfg,
            interface=tool_call.get('interface'),
            peer_ip=tool_call.get('peer_ip'),
            mode=tool_call.get('mode'),
        )

    def action_pineapple_stop_arpspoof(tool_call: dict[str, Any]) -> dict[str, Any]:
        return pineapple_stop_arpspoof(cfg, kill_all=bool(tool_call.get('kill_all', False)))

    def _flatten_options(tool_call: dict[str, Any]) -> dict[str, Any]:
        """Defense-in-depth: tolerate model emissions like
        {"action":"crack_wifi_pcap","options":{"capture_file":"..."}} by
        flattening any nested ``options`` dict into the top level. Top-level
        keys still win when both are present.
        """
        if not isinstance(tool_call.get('options'), dict):
            return dict(tool_call)
        merged = dict(tool_call['options'])
        for key, value in tool_call.items():
            if key == 'options':
                continue
            merged[key] = value
        return merged

    def _resolve_pcap_path_from_call(tc: dict[str, Any]) -> str | None:
        """Accept all reasonable synonyms used by different model emissions."""
        return (
            tc.get('pcap_path')
            or tc.get('path')
            or tc.get('pcap_file')
            or tc.get('capture_file')
            or tc.get('pcapng')
            or tc.get('file')
        )

    def action_extract_handshake(tool_call: dict[str, Any]) -> dict[str, Any]:
        tc = _flatten_options(tool_call)
        pcap_path = _resolve_pcap_path_from_call(tc)
        return extract_handshake_hash(pcap_path, tc.get('output_hash_path'))

    def action_crack_wifi_pcap(tool_call: dict[str, Any]) -> dict[str, Any]:
        tc = _flatten_options(tool_call)
        pcap_path = _resolve_pcap_path_from_call(tc) or latest_pcap()
        return crack_wifi_pcap(
            pcap_path=pcap_path,
            wordlist=tc.get('wordlist'),
            output_hash_path=tc.get('output_hash_path'),
            hashcat_args=tc.get('hashcat_args'),
            blocking=True,
        )

    def action_pineapple_connect(tool_call: dict[str, Any]) -> dict[str, Any]:
        return pineapple_connect(tool_call.get('ssid'), tool_call.get('password'), cfg)

    def action_nmap_scan(tool_call: dict[str, Any]) -> dict[str, Any]:
        result = run_nmap_scan(tool_call.get('target'), tool_call.get('args', ['-F']))
        result['scan_origin'] = 'local_kali'
        return result

    def action_pineapple_nmap_scan(tool_call: dict[str, Any]) -> dict[str, Any]:
        return pineapple_nmap_scan(
            tool_call.get('target'),
            tool_call.get('args', ['-F']),
            cfg,
            interface=tool_call.get('interface'),
        )

    def action_pineapple_subnet_map(tool_call: dict[str, Any]) -> dict[str, Any]:
        raw_stages = tool_call.get('stages')
        if isinstance(raw_stages, str):
            stages = [raw_stages]
        elif isinstance(raw_stages, list):
            stages = [str(s) for s in raw_stages]
        else:
            stages = None
        return pineapple_subnet_map(
            target=tool_call.get('target'),
            cfg=cfg,
            interface=str(tool_call.get('interface') or 'wlan2'),
            stages=stages,
            aggressive=bool(tool_call.get('aggressive', False)),
        )

    def action_enable_monitor_mode(tool_call: dict[str, Any]) -> dict[str, Any]:
        interface = _sanitize_iface(tool_call.get('interface', 'wlan1mon'))
        return enable_monitor_mode(cfg, interface=interface)

    def action_pineapple_deauth_and_capture(tool_call: dict) -> dict:
        bssid = str(tool_call.get('bssid', '')).strip().upper()
        channel = tool_call.get('channel')
        capture_seconds = int(tool_call.get('capture_seconds', 120))
        deauth_bursts = int(tool_call.get('deauth_bursts', 24))

        # PMF pre-check: if the target BSSID was seen with PMF/802.11w in a prior scan,
        # warn the user - standard deauth will be silently dropped by PMF-enabled APs.
        # We check the scan cache via pineapple_analyze_ssid if we can derive the SSID,
        # but since we only have the BSSID here, look in the raw scan cache for pmf_present.
        try:
            from tools.pineapple_helpers import _SCAN_CACHE, _parse_scan_output
            cached_raw = (_SCAN_CACHE.get('result') or {}).get('stdout', '')
            if cached_raw:
                _, networks = _parse_scan_output(cached_raw)
                for net in networks:
                    if str(net.get('bssid', '')).upper() == bssid and net.get('pmf_present') is True:
                        return {
                            'ok': False,
                            'error': (
                                f'BSSID {bssid} has PMF (802.11w) enabled. '
                                'Standard aireplay-ng deauth frames will be silently discarded. '
                                'Use hcxdumptool_capture instead, which can capture PMKIDs without client disconnection.'
                            ),
                            'bssid': bssid,
                            'pmf_detected': True,
                            'suggestion': 'hcxdumptool_capture',
                        }
        except Exception:
            pass  # PMF check is best-effort; proceed with deauth regardless

        # Honor an explicit target_mac if the caller passed one. Only fall back
        # to broadcast if no real station is provided. Caller-side routing
        # (agent_cli._build_deauth_capture_tool_call_from_text) is responsible
        # for filling in a known confirmed/high-confidence client when one has
        # already been observed for this BSSID in the current session.
        raw_target = tool_call.get('target_mac')
        target_mac = str(raw_target).strip().upper() if raw_target else 'FF:FF:FF:FF:FF:FF'
        return pineapple_deauth_and_capture(
            bssid=bssid,
            channel=channel,
            target_mac=target_mac,
            cfg=cfg,
            capture_seconds=capture_seconds,
            deauth_bursts=deauth_bursts,
        )

    def action_hcxdumptool_capture(tool_call: dict[str, Any]) -> dict[str, Any]:
        bssid = str(tool_call.get('bssid', '')).strip().upper()
        channel = tool_call.get('channel')
        capture_seconds = int(tool_call.get('capture_seconds', 180))
        # hcxdumptool manages its own monitor mode - prefer the physical
        # interface (wlan1) rather than a virtual mon interface.
        raw_iface = tool_call.get('interface', 'wlan1')
        interface = _sanitize_iface(raw_iface)
        result = pineapple_deauth_and_capture_hcx(
            bssid=bssid,
            channel=channel,
            cfg=cfg,
            interface=interface,
            capture_seconds=capture_seconds,
        )

        # Auto-extract hash from capture - makes HCX a one-step pipeline.
        pcap_path = result.get('pcap_path')
        if pcap_path and result.get('capture_ok') and result.get('outcome') != 'empty_capture':
            extraction = extract_handshake_hash(pcap_path)
            result['extraction'] = extraction
            result['extraction_ok'] = extraction.get('ok', False)
            result['usable_hash_material'] = extraction.get('ok', False)
            result['hash_path'] = extraction.get('hash_path') if extraction.get('ok') else None
            result['hash_line_count'] = extraction.get('hash_line_count', 0)
            # Update top-level ok only if extraction actually found material
            if extraction.get('ok'):
                result['ok'] = True
                result['error'] = None
        else:
            result['extraction'] = None
            result['extraction_ok'] = False
            result['usable_hash_material'] = False
            result['hash_path'] = None

        return result

    def action_unencrypted_scan(tool_call: dict[str, Any]) -> dict[str, Any]:
        return scan_unencrypted_traffic(
            pcap_path=tool_call.get('pcap_path') or tool_call.get('path'),
            interface=tool_call.get('interface'),
            duration=int(tool_call.get('duration', 30)),
        )

    def action_live_unencrypted_scan(tool_call: dict[str, Any]) -> dict[str, Any]:
        return live_unencrypted_scan(
            interface=tool_call.get('interface'),
            duration=int(tool_call.get('duration', 180)),
            pineapple_path=bool(tool_call.get('pineapple_path', False)),
            cfg=cfg,
        )

    def action_pineapple_scan(tool_call: dict) -> dict:
        _require_confirmation(cfg)
        duration = int(tool_call.get('duration', 15))
        channel = tool_call.get('channel')
        if channel is not None:
            channel = int(channel)
        try:
            path = capture_pcap(duration=duration, cfg=cfg, channel=channel)
        except RuntimeError as exc:
            return {'ok': False, 'error': str(exc), 'duration': duration, 'channel': channel}
        return {'ok': True, 'pcap_path': path, 'duration': duration, 'channel': channel}

    def action_scan_and_analyze(tool_call: dict) -> dict:
        _require_confirmation(cfg)
        duration = int(tool_call.get('duration', 15))
        channel = tool_call.get('channel')
        if channel is not None:
            channel = int(channel)
        try:
            path = capture_pcap(duration=duration, cfg=cfg, channel=channel)
        except RuntimeError as exc:
            return {'ok': False, 'error': str(exc), 'duration': duration, 'channel': channel}
        report = wifi_deep_report(path)
        # Auto-detect dominant BSSID from capture for client correlation
        dominant_bssid = report.get('top_bssids', [None])[0] if report.get('top_bssids') else None
        if dominant_bssid:
            report = wifi_deep_report(path, focus_bssid=dominant_bssid)
        return {'ok': True, 'pcap_path': path, 'report': report, 'duration': duration, 'channel': channel}

    def action_pineapple_deep_analyze_ssid(tool_call: dict) -> dict:
        ssid = str(tool_call.get('ssid', '')).strip()
        # Deep analysis must dwell long enough for wifi_deep_report to populate
        # client confidence tiers and EAPOL indicators.
        # Default raised from 30 → 180 s; cap raised to 300 s.
        dwell_sec = max(30, min(int(tool_call.get('dwell_sec', 180)), 300))
        snapshot = pineapple_analyze_ssid(cfg, ssid=ssid) or {}
        if not snapshot.get('ok'):
            snapshot = pineapple_analyze_ssid(cfg, ssid=ssid, refresh=True)
            if not snapshot.get('ok'):
                return snapshot
        _require_confirmation(cfg)

        # Connectivity precheck before expensive capture
        conn = _check_connectivity(cfg)
        if not conn.get('ok'):
            return {'ok': False, 'error': conn['error'], 'failure_type': 'transport_failure', 'ssid': ssid}

        interface = _sanitize_iface(_pine_cfg(cfg).get('interface', 'wlan1mon'))
        channel = snapshot.get('channel')
        if channel is not None:
            channel = int(channel)
        bssid = snapshot.get('bssid')

        # Ensure monitor mode before passive capture - without this, tcpdump may
        # start on a managed-mode interface and capture 0 packets silently.
        mon_result = enable_monitor_mode(cfg, interface=interface)
        if not mon_result.get('ok'):
            return {
                'ok': False,
                'error': f'Could not confirm monitor mode on {interface}: {mon_result.get("stderr", "")[:300]}',
                'failure_type': 'monitor_mode_failure',
                'ssid': ssid,
            }

        # Use whichever interface enable_monitor_mode actually confirmed - 
        # airmon-ng may create e.g. wlan2mon instead of the requested wlan1mon.
        actual_interface = _sanitize_iface(mon_result.get('interface'), default=interface)

        # IMPORTANT: capture is UNFILTERED on the correct channel.
        #
        # Earlier versions passed `filter_bssid=bssid` into capture_pcap, which
        # installed an `ether host <bssid>` BPF filter on the remote tcpdump.
        # On a monitor/radiotap interface that BPF filter does not reliably
        # match 802.11 address fields and produced "0 packets captured / N
        # packets received by filter" results even when the AP was clearly
        # on-air (HCX on the same iface and channel succeeded). The fix is to
        # capture everything on the channel and let wifi_deep_report focus on
        # the target BSSID locally - the report code already supports
        # focus_bssid for client correlation.
        try:
            pcap_path = capture_pcap(
                duration=dwell_sec,
                cfg=cfg,
                channel=channel,
                interface=actual_interface,
            )
        except RuntimeError as exc:
            msg = str(exc)
            ftype = (
                'tcpdump_capture_failed' if msg.startswith('tcpdump_capture_failed:')
                else 'remote_capture_lifecycle_failure' if msg.startswith('remote_capture_lifecycle_failure:')
                else 'transport_failure' if msg.startswith('transport_failure:')
                else 'monitor_mode_failure' if msg.startswith('monitor_mode_failure:')
                else 'capture_failure'
            )
            # Make the error text reflect the new reality: this is a deep
            # analysis dwell on the AP's channel; if it fails, it is either a
            # tcpdump lifecycle / transport problem or a real on-air problem,
            # NOT a BPF filter mismatch.
            human_error = msg
            if ftype == 'tcpdump_capture_failed':
                human_error = (
                    f"Deep analysis capture on {actual_interface} channel {channel} "
                    f"produced an empty PCAP after {dwell_sec}s of unfiltered listening. "
                    "Monitor mode looked up but no 802.11 frames were written. "
                    "This is a tcpdump lifecycle / channel problem, not a BPF filter problem. "
                    f"Original error: {msg}"
                )
            return {
                'ok': False,
                'error': human_error,
                'failure_type': ftype,
                'ssid': ssid,
                'bssid': bssid,
                'interface': actual_interface,
                'channel': channel,
                'dwell_sec': dwell_sec,
            }

        # Local BSSID-focused analysis on the unfiltered capture.
        # Pineapple iface MACs are excluded so the AP's own radios cannot
        # appear in observed_clients lists.
        pineapple_macs = get_pineapple_iface_macs(cfg)
        report = wifi_deep_report(pcap_path, focus_bssid=bssid, exclude_macs=pineapple_macs)
        merged = _merge_snapshot_with_report(ssid=ssid, snapshot=snapshot, report=report)
        merged['dwell_sec'] = dwell_sec
        merged['capture_was_filtered'] = False
        merged['pineapple_excluded_macs'] = sorted(m.upper() for m in pineapple_macs)

        # Use the authoritative focus_bssid_frame_count from the report
        # (computed by _extract_client_confidence) rather than recomputing
        # from bssid_counts, which uses a different counting method and
        # can disagree.
        focus_packet_total = int(merged.get('focus_bssid_packet_count', 0) or 0)

        if focus_packet_total == 0:
            note = (
                f"Capture on channel {channel} succeeded ({report.get('packet_count', 0)} total packets) "
                f"but no frames involving BSSID {bssid} were observed during the {dwell_sec}s window. "
                "This means the AP was quiet or had no on-air activity for this BSSID during the dwell - "
                "it does NOT mean monitor mode failed."
            )
            existing_notes = merged.get('assessment_notes') or []
            existing_notes.append(note)
            merged['assessment_notes'] = existing_notes
        elif focus_packet_total < 50:
            note = (
                f"Only {focus_packet_total} frame(s) involving BSSID {bssid} were observed in the "
                f"{dwell_sec}s capture. Client confidence indicators are based on a small sample."
            )
            existing_notes = merged.get('assessment_notes') or []
            existing_notes.append(note)
            merged['assessment_notes'] = existing_notes

        return merged

    def action_pineapple_client_activity_report(tool_call: dict) -> dict:
        ssid = str(tool_call.get('ssid', '')).strip()
        # Default raised from 30 → 120 s; cap kept separate from deep analyze.
        dwell_sec = max(30, min(int(tool_call.get('dwell_sec', 120)), 240))
        snapshot = pineapple_analyze_ssid(cfg, ssid=ssid) or {}
        if not snapshot.get('ok'):
            snapshot = pineapple_analyze_ssid(cfg, ssid=ssid, refresh=True)
            if not snapshot.get('ok'):
                return snapshot
        _require_confirmation(cfg)

        # Connectivity precheck before expensive capture
        conn = _check_connectivity(cfg)
        if not conn.get('ok'):
            return {'ok': False, 'error': conn['error'], 'failure_type': 'transport_failure', 'ssid': ssid}

        interface = _sanitize_iface(_pine_cfg(cfg).get('interface', 'wlan1mon'))
        channel = snapshot.get('channel')
        if channel is not None:
            channel = int(channel)
        bssid = snapshot.get('bssid')

        # Ensure monitor mode before passive capture
        mon_result = enable_monitor_mode(cfg, interface=interface)
        if not mon_result.get('ok'):
            return {
                'ok': False,
                'error': f'Could not confirm monitor mode on {interface}: {mon_result.get("stderr", "")[:300]}',
                'failure_type': 'monitor_mode_failure',
                'ssid': ssid,
            }

        actual_interface = _sanitize_iface(mon_result.get('interface'), default=interface)

        # Capture is UNFILTERED on the AP's channel (see equivalent comment in
        # action_pineapple_deep_analyze_ssid). The remote BPF filter on the
        # monitor/radiotap interface was unreliable; we let wifi_deep_report
        # focus on the target BSSID locally instead.
        try:
            pcap_path = capture_pcap(
                duration=dwell_sec,
                cfg=cfg,
                channel=channel,
                interface=actual_interface,
            )
        except RuntimeError as exc:
            msg = str(exc)
            ftype = (
                'tcpdump_capture_failed' if msg.startswith('tcpdump_capture_failed:')
                else 'remote_capture_lifecycle_failure' if msg.startswith('remote_capture_lifecycle_failure:')
                else 'transport_failure' if msg.startswith('transport_failure:')
                else 'monitor_mode_failure' if msg.startswith('monitor_mode_failure:')
                else 'capture_failure'
            )
            human_error = msg
            if ftype == 'tcpdump_capture_failed':
                human_error = (
                    f"Client activity capture on {actual_interface} channel {channel} "
                    f"produced an empty PCAP after {dwell_sec}s of unfiltered listening. "
                    "Monitor mode looked up but no 802.11 frames were written. "
                    "This is a tcpdump lifecycle / channel problem, not a BPF filter problem. "
                    f"Original error: {msg}"
                )
            return {
                'ok': False,
                'error': human_error,
                'failure_type': ftype,
                'ssid': ssid,
                'bssid': bssid,
                'interface': actual_interface,
                'channel': channel,
                'dwell_sec': dwell_sec,
            }

        pineapple_macs = get_pineapple_iface_macs(cfg)
        report = wifi_deep_report(pcap_path, focus_bssid=bssid, exclude_macs=pineapple_macs)

        focus_packet_total = 0
        try:
            bssid_counts = report.get('bssid_counts') or {}
            if isinstance(bssid_counts, dict) and bssid:
                focus_packet_total = int(bssid_counts.get(str(bssid).lower(), 0) or 0)
        except (TypeError, ValueError):
            focus_packet_total = 0

        notes: list[str] = []
        if focus_packet_total == 0:
            notes.append(
                f"Capture on channel {channel} succeeded ({report.get('packet_count', 0)} total packets) "
                f"but no frames involving BSSID {bssid} were observed during the {dwell_sec}s window. "
                "The AP was quiet during the dwell - this is not a monitor-mode failure."
            )
        elif focus_packet_total < 50:
            notes.append(
                f"Only {focus_packet_total} frame(s) involving BSSID {bssid} were observed in the "
                f"{dwell_sec}s capture. Client indicators are based on a small sample."
            )

        return {
            'ok': True,
            'ssid': snapshot.get('ssid', ssid), 'bssid': bssid, 'channel': snapshot.get('channel'), 'security': snapshot.get('security'),
            'client_count': report.get('client_count', 0), 'observed_clients': report.get('observed_clients', []), 'confirmed_clients': report.get('confirmed_clients', []),
            'high_confidence_clients': report.get('high_confidence_clients', []), 'low_confidence_clients': report.get('low_confidence_clients', []),
            'traffic_activity': report.get('traffic_activity'), 'eapol_frames_seen': report.get('eapol_frames_seen', 0), 'handshake_like_activity_seen': bool(report.get('eapol_frames_seen', 0)),
            'deauth_frames': report.get('deauth_frames', 0), 'disassoc_frames': report.get('disassoc_frames', 0), 'randomized_local_mac_count': report.get('randomized_local_mac_count', 0),
            'protocol_counts': report.get('protocol_counts', {}), 'top_tcp_ports': report.get('top_tcp_ports', []), 'top_udp_ports': report.get('top_udp_ports', []),
            'unencrypted_traffic_observed': report.get('unencrypted_traffic_observed', False), 'plaintext_protocols_observed': report.get('plaintext_protocols_observed', []),
            'packet_count': report.get('packet_count'), 'focus_bssid_packet_count': focus_packet_total,
            'capture_was_filtered': False,
            'pineapple_excluded_macs': sorted(m.upper() for m in pineapple_macs),
            'count_inconsistencies': report.get('count_inconsistencies', []),
            'dwell_sec': dwell_sec, 'pcap_path': pcap_path, 'pcap_report': report, 'snapshot': snapshot,
            'observation_limits': report.get('observation_limits', []),
            'assessment_notes': notes,
        }

    def action_quick_handshake_check(tool_call: dict[str, Any]) -> dict[str, Any]:
        pcap_path = tool_call.get('pcap_path') or tool_call.get('path') or latest_pcap()
        return quick_handshake_check(pcap_path)

    return {
        'latest_pcap': action_latest_pcap,
        'hashcat': action_hashcat,
        'john': action_john,
        'arpspoof': action_arpspoof,
        'extract_handshake': action_extract_handshake,
        'crack_wifi_pcap': action_crack_wifi_pcap,
        'pineapple_connect': action_pineapple_connect,
        'pineapple_deauth_and_capture': action_pineapple_deauth_and_capture,
        'hcxdumptool_capture': action_hcxdumptool_capture,
        'enable_monitor_mode': action_enable_monitor_mode,
        'quick_handshake_check': action_quick_handshake_check,
        'nmap_scan': action_nmap_scan,
        'pineapple_nmap_scan': action_pineapple_nmap_scan,
        'pineapple_subnet_map': action_pineapple_subnet_map,
        'unencrypted_scan': action_unencrypted_scan,
        'live_unencrypted_scan': action_live_unencrypted_scan,
        'stop_arpspoof': action_stop_arpspoof,
        'pineapple_arpspoof': action_pineapple_arpspoof,
        'pineapple_stop_arpspoof': action_pineapple_stop_arpspoof,
        'enable_ip_forwarding': lambda _: enable_ip_forwarding(),
        'read_file': lambda tc: read_file(str(tc.get('path', '')).strip(), policy),
        'pineapple_status': lambda _: pineapple_status(cfg),
        'pineapple_wifi_snapshot': lambda _: pineapple_wifi_snapshot(cfg),
        'write_finding': lambda tc: write_finding(tc.get('finding_type'), tc.get('details', {})),
        'generate_report': lambda tc: generate_report(tc.get('title'), tc.get('summary')),
        'plan_audit': lambda tc: plan_audit(tc.get('target'), tc.get('objectives', [])),
        'summarize_pcap': lambda tc: {'ok': True, 'summary': summarize_pcap(tc.get('path', latest_pcap()))},
        'summarize_pcap_tshark': lambda tc: {'ok': True, 'summary': summarize_with_tshark(tc.get('path', latest_pcap()))},
        'tshark_deep_review': lambda tc: {'ok': True, 'summary': deep_review_with_tshark(tc.get('path', latest_pcap()))},
        'deep_review_latest': lambda _: {'ok': True, 'summary': deep_review_with_tshark(latest_pcap())},
        'pineapple_nearby_ssids': lambda tc: pineapple_nearby_ssids(cfg, limit=int(tc.get('limit', 10))),
        'pineapple_analyze_ssid': lambda tc: pineapple_analyze_ssid(cfg, tc.get('ssid'), refresh=bool(tc.get('refresh', False))),
        'pineapple_logs': lambda tc: pineapple_logs(cfg, lines=int(tc.get('lines', 200))),
        'run_app': lambda tc: run_allowlisted_app(tc.get('name'), allowlist),
        'run_command': lambda tc: run_allowlisted_command(tc.get('name'), allowlist),
        'pineapple_scan': action_pineapple_scan,
        'scan_and_analyze': action_scan_and_analyze,
        'pineapple_deep_analyze_ssid': action_pineapple_deep_analyze_ssid,
        'pineapple_client_activity_report': action_pineapple_client_activity_report,
    }
