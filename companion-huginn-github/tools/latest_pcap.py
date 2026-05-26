from __future__ import annotations

from pathlib import Path

from core.app_paths import captures_dir


def latest_pcap() -> str:
    cdir = captures_dir()
    files = sorted(
        [p for p in cdir.glob("*.pcap*") if p.is_file()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not files:
        raise FileNotFoundError(f"No PCAP files found under {cdir}")
    return str(files[0].resolve())
