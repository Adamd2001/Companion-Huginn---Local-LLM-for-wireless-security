from __future__ import annotations

import os
from pathlib import Path


def app_home() -> Path:
    base = os.environ.get("HUGINN_HOME")
    if base:
        return Path(base).expanduser().resolve()
    return Path("/home/USER/Desktop/companion-huginn-github").resolve()


def config_dir() -> Path:
    return app_home() / "config"


def tools_dir() -> Path:
    return app_home() / "tools"


def captures_dir() -> Path:
    return app_home() / "captures"


def logs_dir() -> Path:
    return app_home() / "logs"


def memory_dir() -> Path:
    return app_home() / "memory"

def reports_dir() -> Path:
    return app_home() / "reports"

def ensure_runtime_dirs() -> None:
    for d in [config_dir(), tools_dir(), captures_dir(), logs_dir(), memory_dir(), reports_dir()]:
        d.mkdir(parents=True, exist_ok=True)


def get_log_path(name: str) -> Path:
    ensure_runtime_dirs()
    return logs_dir() / name
