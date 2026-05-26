from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path


def _run(cmd: list[str], timeout: int = 90) -> str:
    proc = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
    return out.strip()[-30000:]


def _top_unique(raw: str, n: int = 25) -> str:
    vals = [x.strip() for x in raw.splitlines() if x.strip()]
    counts = Counter(vals)
    if not counts:
        return "<none>"
    return "\n".join([f"{value} ({count})" for value, count in counts.most_common(n)])


def summarize_with_tshark(pcap_path: str) -> str:
    p = Path(pcap_path)
    if not p.exists():
        raise FileNotFoundError(f"PCAP not found: {p}")

    report: list[str] = []
    report.append(f"PCAP: {p.resolve()}")
    report.append("")

    report.append("=== capinfos ===")
    report.append(_run(["capinfos", str(p)]) or "<no output>")
    report.append("")

    report.append("=== Protocol Hierarchy ===")
    report.append(_run(["tshark", "-r", str(p), "-q", "-z", "io,phs"]) or "<no output>")
    report.append("")

    report.append("=== IP Endpoints ===")
    report.append(_run(["tshark", "-r", str(p), "-q", "-z", "endpoints,ip"]) or "<no output>")
    report.append("")

    report.append("=== IP Conversations ===")
    report.append(_run(["tshark", "-r", str(p), "-q", "-z", "conv,ip"]) or "<no output>")
    report.append("")

    dns_raw = _run(["tshark", "-r", str(p), "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name"])
    report.append("=== DNS Query Names ===")
    report.append(_top_unique(dns_raw, n=25))
    report.append("")

    sni_raw = _run([
        "tshark", "-r", str(p),
        "-Y", "tls.handshake.extensions_server_name",
        "-T", "fields",
        "-e", "tls.handshake.extensions_server_name"
    ])
    report.append("=== TLS SNI ===")
    report.append(_top_unique(sni_raw, n=25))
    report.append("")

    http_raw = _run(["tshark", "-r", str(p), "-Y", "http.host", "-T", "fields", "-e", "http.host"])
    report.append("=== HTTP Host ===")
    report.append(_top_unique(http_raw, n=25))
    report.append("")

    eapol = _run(["tshark", "-r", str(p), "-Y", "eapol", "-T", "fields", "-e", "frame.number"])
    eapol_count = len([ln for ln in eapol.splitlines() if ln.strip()]) if eapol else 0
    report.append("=== WPA/EAPOL Indicators ===")
    report.append(f"EAPOL frames found: {eapol_count}")
    report.append("")

    deauth = _run(["tshark", "-r", str(p), "-Y", "wlan.fc.type_subtype == 0x0c", "-T", "fields", "-e", "frame.number"])
    deauth_count = len([ln for ln in deauth.splitlines() if ln.strip()]) if deauth else 0
    report.append("=== 802.11 Deauth Indicators ===")
    report.append(f"Deauth frames found: {deauth_count}")
    report.append("")

    return "\n".join(report)
