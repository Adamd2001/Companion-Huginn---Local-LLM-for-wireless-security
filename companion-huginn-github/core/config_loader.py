from __future__ import annotations

from pathlib import Path
import yaml

from core.app_paths import config_dir


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Missing config file: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or {}


def load_all_config() -> dict:
    cfg = _load_yaml(config_dir() / "config.yaml")
    allow = _load_yaml(config_dir() / "allowlist.yaml")
    policy = _load_yaml(config_dir() / "policy.yaml")
    pineapple = _load_yaml(config_dir() / "pineapple.yaml")

    return {
        "config": cfg,
        "allowlist": allow,
        "policy": policy,
        "pineapple": pineapple,
    }
