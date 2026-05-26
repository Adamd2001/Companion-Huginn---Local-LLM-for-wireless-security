from __future__ import annotations

import re
import shlex
import subprocess
import time
from pathlib import Path

from core.app_paths import captures_dir as _captures_dir


def _pine_cfg(cfg: dict) -> dict:
    return cfg["pineapple"].get("pineapple", {})


def _ssh_base(cfg: dict) -> list[str]:
    p = _pine_cfg(cfg)
    host = str(p.get("host", "")).strip()
    user = str(p.get("user", "root")).strip()
    identity = str(p.get("identity_file", "")).strip()

    if not host:
        raise ValueError("Missing pineapple.host in config/pineapple.yaml")

    cmd = [
        "ssh",
        "-T",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=8",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
    ]
    if identity:
        cmd += ["-i", identity]
    cmd += [f"{user}@{host}"]
    return cmd


def _scp_base(cfg: dict) -> list[str]:
    p = _pine_cfg(cfg)
    identity = str(p.get("identity_file", "")).strip()
    cmd = [
        "scp",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=8",
    ]
    if identity:
        cmd += ["-i", identity]
    return cmd


def _run_ssh(cfg: dict, remote_cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            _ssh_base(cfg) + [remote_cmd],
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        r = subprocess.CompletedProcess(args=[], returncode=1)
        r.stdout = ""
        r.stderr = f"transport_failure: SSH timed out after {timeout}s"
        return r
    except Exception as exc:
        r = subprocess.CompletedProcess(args=[], returncode=1)
        r.stdout = ""
        r.stderr = f"transport_failure: {type(exc).__name__}: {exc}"
        return r


def capture_pcap(
    duration: int,
    cfg: dict,
    channel: int | None = None,
    filter_bssid: str | None = None,
    interface: str | None = None,
) -> str:
    """
    Capture 802.11 frames on the Pineapple for the given duration.

    Args:
        duration:     Capture duration in seconds (1-600).
        cfg:          Loaded configuration dict.
        channel:      Optional channel to tune to before capture.
        filter_bssid: Optional BSSID to filter traffic (ether host <mac>).
                      When provided, only frames involving this MAC are captured,
                      reducing PCAP size and noise significantly.

    Returns:
        Absolute local path to the downloaded PCAP file.

    Raises:
        ValueError:   Invalid duration.
        RuntimeError: SSH failure, channel set failure, tcpdump start failure,
                      or SCP failure.
    """
    if duration < 1 or duration > 600:
        raise ValueError("duration must be between 1 and 600 seconds")

    p = _pine_cfg(cfg)
    remote_dir = str(p.get("remote_capture_dir", "/root/captures")).strip()
    interface = str(interface or p.get("interface", "wlan1mon")).strip() or "wlan1mon"
    raw = str(p.get("local_capture_dir", "")).strip()
    local_dir = Path(raw).expanduser().resolve() if raw else _captures_dir()

    local_dir.mkdir(parents=True, exist_ok=True)

    ts = int(time.time())
    channel_suffix = f"_ch{channel}" if isinstance(channel, int) else ""
    filename = f"capture_{ts}{channel_suffix}.pcap"
    remote_path = f"{remote_dir}/{filename}"
    remote_log = f"{remote_dir}/tcpdump_{ts}.log"
    local_path = local_dir / filename

    # Build BPF filter / tcpdump argument string. When a target BSSID is known,
    # filter to only frames involving that MAC. 'ether host <bssid>' on a
    # monitor-mode interface matches any 802.11 address field.
    if filter_bssid:
        bpf = f"ether host {filter_bssid.lower()}"
        tcpdump_args = (
            f"-i {shlex.quote(interface)} -n -U -s 0 "
            f"-w {shlex.quote(remote_path)} {shlex.quote(bpf)}"
        )
    else:
        tcpdump_args = (
            f"-i {shlex.quote(interface)} -n -U -s 0 -w {shlex.quote(remote_path)}"
        )

    # Single-SSH-session lifecycle.
    #
    # Earlier versions of this function ran tcpdump in the background of one
    # SSH session and then opened a SECOND SSH session to kill it. That broke
    # because tcpdump received SIGHUP the moment SSH session #1 closed, so the
    # PCAP was always empty (24 B = pcap header only) and the failure was
    # misclassified as `monitor_mode_failure`. HCX and the deauth path do not
    # have this bug because they keep the entire lifecycle (start → sleep →
    # kill → wait → ls) inside one long-running `sh -lc '...'` SSH session.
    # capture_pcap now follows the same pattern.
    channel_block = ""
    if isinstance(channel, int):
        channel_block = (
            f"iw dev {shlex.quote(interface)} set channel {int(channel)} 2>&1 "
            f"|| {{ echo SENTINEL_ERR:channel_set_failed; exit 11; }}; "
        )

    remote_script = (
        "set -u; "
        f"mkdir -p {shlex.quote(remote_dir)} "
        f"|| {{ echo SENTINEL_ERR:mkdir_failed; exit 10; }}; "
        f"{channel_block}"
        f"LOG={shlex.quote(remote_log)}; "
        f"PCAP={shlex.quote(remote_path)}; "
        "echo SENTINEL_BEGIN; "
        f"( tcpdump {tcpdump_args} >\"$LOG\" 2>&1 ) & "
        "PID=$!; "
        "echo PID:$PID; "
        f"sleep {int(duration)}; "
        "kill -INT \"$PID\" 2>/dev/null || true; "
        "sleep 2; "
        "kill -TERM \"$PID\" 2>/dev/null || true; "
        "wait \"$PID\" 2>/dev/null || true; "
        "if [ -f \"$PCAP\" ]; then "
        "  ls -l \"$PCAP\"; "
        "  echo FILESIZE:$(wc -c < \"$PCAP\" 2>/dev/null || echo 0); "
        "else "
        "  echo FILESIZE:0; "
        "  echo SENTINEL_ERR:no_pcap_file; "
        "fi; "
        "echo TCPDUMP_LOG_BEGIN; "
        "cat \"$LOG\" 2>/dev/null || true; "
        "echo TCPDUMP_LOG_END; "
        "rm -f \"$LOG\"; "
        "echo SENTINEL_END"
    )

    result = _run_ssh(
        cfg,
        f"sh -lc {shlex.quote(remote_script)}",
        timeout=duration + 30,
    )

    out = ((result.stdout or "") + "\n" + (result.stderr or ""))

    if result.returncode != 0 and "SENTINEL_END" not in out:
        raise RuntimeError(
            "transport_failure: "
            + (
                result.stderr.strip()
                or "ssh transport failed before remote capture script finished"
            )
        )

    if "SENTINEL_ERR:channel_set_failed" in out:
        raise RuntimeError(
            f"remote_capture_lifecycle_failure: failed to set {interface} to channel {channel}"
        )
    if "SENTINEL_ERR:mkdir_failed" in out:
        raise RuntimeError(
            "remote_capture_lifecycle_failure: mkdir of remote_dir failed on the Pineapple"
        )

    pid_match = re.search(r"PID:(\d+)", out)
    if not pid_match:
        raise RuntimeError(
            "remote_capture_lifecycle_failure: tcpdump PID was not observed; "
            f"remote stdout tail: {out[-500:]}"
        )

    size_match = re.search(r"FILESIZE:(\d+)", out)
    file_size = int(size_match.group(1)) if size_match else 0

    log_match = re.search(
        r"TCPDUMP_LOG_BEGIN\n(.*?)\nTCPDUMP_LOG_END", out, re.DOTALL
    )
    tcpdump_diag = log_match.group(1).strip() if log_match else ""

    if file_size <= 24:
        raise RuntimeError(
            f"tcpdump_capture_failed: PCAP file size {file_size} B after {duration}s "
            f"on {interface} channel={channel} bssid_filter={filter_bssid or 'none'}. "
            f"tcpdump log: {tcpdump_diag or '(empty)'}"
        )

    host = str(p.get("host", "")).strip()
    user = str(p.get("user", "root")).strip()
    try:
        scp = subprocess.run(
            _scp_base(cfg) + [f"{user}@{host}:{remote_path}", str(local_path)],
            text=True,
            capture_output=True,
            timeout=90,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("transport_failure: SCP timed out copying capture from Pineapple")
    except Exception as exc:
        raise RuntimeError(f"transport_failure: SCP failed: {type(exc).__name__}: {exc}")
    if scp.returncode != 0:
        raise RuntimeError(
            "transport_failure: " + (scp.stderr.strip() or scp.stdout.strip()
            or "Failed to copy capture back to local host")
        )

    _run_ssh(cfg, f"rm -f {shlex.quote(remote_path)}", timeout=10)

    if not local_path.exists():
        raise RuntimeError(f"transport_failure: PCAP file was not created locally: {local_path}")

    return str(local_path.resolve())
