from __future__ import annotations

from pathlib import Path

from tools.tshark_summarize import summarize_with_tshark


def summarize_pcap(path: str, max_packets: int = 5000, sample_lines: int = 200) -> str:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f'PCAP not found: {p}')
    return summarize_with_tshark(str(p))
