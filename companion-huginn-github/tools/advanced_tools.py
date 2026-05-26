from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from core.app_paths import app_home, ensure_runtime_dirs, reports_dir


def _memory_file() -> Path:
    legacy = app_home() / "campaign_memory.json"
    if legacy.exists():
        return legacy
    return app_home() / "memory" / "campaign_memory.json"


def write_finding(finding_type: str, details: dict[str, Any]) -> dict[str, Any]:
    try:
        ensure_runtime_dirs()
        memory_file = _memory_file()
        memory_file.parent.mkdir(parents=True, exist_ok=True)

        if memory_file.exists():
            raw = json.loads(memory_file.read_text(encoding="utf-8") or "[]")
            memory = raw if isinstance(raw, list) else []
        else:
            memory = []

        entry = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "type": finding_type or "unspecified",
            "details": details or {},
        }
        memory.append(entry)
        memory_file.write_text(json.dumps(memory, indent=2), encoding="utf-8")
        return {"ok": True, "msg": f"Finding '{entry['type']}' saved.", "memory_file": str(memory_file)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def generate_report(title: str, summary: str) -> dict[str, Any]:
    try:
        ensure_runtime_dirs()
        report_dir = reports_dir()
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        memory_file = _memory_file()
        memory: list[dict[str, Any]] = []
        if memory_file.exists():
            raw = json.loads(memory_file.read_text(encoding="utf-8") or "[]")
            if isinstance(raw, list):
                memory = raw

        lines = [
            f"# {title or 'Audit Report'}",
            "",
            f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Executive Summary",
            summary or "No summary provided.",
            "",
            "## Detailed Findings",
        ]
        if memory:
            for item in memory:
                lines.append(
                    f"- **{item.get('timestamp', 'unknown')}** | "
                    f"{item.get('type', 'unspecified')}: {json.dumps(item.get('details', {}), ensure_ascii=False)}"
                )
        else:
            lines.append("No findings recorded in memory yet.")

        report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"ok": True, "report_path": str(report_path)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def plan_audit(target: str, objectives: list[str]) -> dict[str, Any]:
    plan = {
        "target": target,
        "status": "planned",
        "steps": [
            {"step": i + 1, "objective": obj, "status": "pending"}
            for i, obj in enumerate(objectives or [])
        ],
    }
    return {
        "ok": True,
        "plan": plan,
        "instruction": "Execute these steps sequentially and record outcomes with write_finding.",
    }
