from __future__ import annotations

import subprocess
from pathlib import Path


def _run(cmd: list[str], timeout: int = 90) -> str:
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    return out.strip()[-30000:]


def deep_review_with_tshark(pcap_path: str) -> str:
    p = Path(pcap_path)
    if not p.exists():
        raise FileNotFoundError(f"PCAP not found: {p}")

    report: list[str] = []
    report.append(f"PCAP: {p.resolve()}")
    report.append("")

    report.append("=== capinfos ===")
    report.append(_run(["capinfos", str(p)]) or "<no output>")
    report.append("")

    report.append("=== 802.11 type breakdown ===")
    report.append(
        _run([
            "tshark", "-r", str(p), "-q",
            "-z", "io,stat,0,wlan.fc.type==0,wlan.fc.type==1,wlan.fc.type==2",
        ]) or "<no output>"
    )
    report.append("")

    report.append("=== BSSID list (raw) ===")
    report.append(
        _run(["tshark", "-r", str(p), "-Y", "wlan.bssid", "-T", "fields", "-e", "wlan.bssid"])
        or "<none>"
    )
    report.append("")

    # FIXED: wlan_mgt.ssid (pre-2.x deprecated) → wlan.ssid
    report.append("=== SSID list (raw) ===")
    report.append(
        _run(["tshark", "-r", str(p), "-Y", "wlan.ssid", "-T", "fields", "-e", "wlan.ssid"])
        or "<none>"
    )
    report.append("")

    report.append("=== EAPOL frames ===")
    report.append(
        _run(["tshark", "-r", str(p), "-Y", "eapol", "-T", "fields", "-e", "frame.number"])
        or "<none>"
    )
    report.append("")

    # FIXED: wlan_mgt.reason_code → wlan.fixed.reason_code
    report.append("=== Deauth frames (time, SA, DA, TA, RA, reason) ===")
    report.append(
        _run([
            "tshark", "-r", str(p),
            "-Y", "wlan.fc.type_subtype==0x0c",
            "-T", "fields",
            "-e", "frame.time",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "wlan.ta",
            "-e", "wlan.ra",
            "-e", "wlan.fixed.reason_code",
        ]) or "<none>"
    )
    report.append("")

    report.append("=== IP Endpoints ===")
    report.append(
        _run(["tshark", "-r", str(p), "-q", "-z", "endpoints,ip"]) or "<none>"
    )
    report.append("")

    report.append("=== IP Conversations ===")
    report.append(
        _run(["tshark", "-r", str(p), "-q", "-z", "conv,ip"]) or "<none>"
    )
    report.append("")

    report.append("=== DNS ===")
    report.append(
        _run(["tshark", "-r", str(p), "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name"])
        or "<none>"
    )
    report.append("")

    report.append("=== TLS SNI ===")
    report.append(
        _run([
            "tshark", "-r", str(p),
            "-Y", "tls.handshake.extensions_server_name",
            "-T", "fields",
            "-e", "tls.handshake.extensions_server_name",
        ]) or "<none>"
    )

    return "\n".join(report)
