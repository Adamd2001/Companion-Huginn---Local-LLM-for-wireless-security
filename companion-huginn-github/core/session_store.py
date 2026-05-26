from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.app_paths import ensure_runtime_dirs, memory_dir


class SessionStore:
    def __init__(self) -> None:
        ensure_runtime_dirs()

    def _session_path(self, session_id: str) -> Path:
        return memory_dir() / f"{session_id}.json"

    def _load(self, session_id: str) -> list[dict[str, Any]]:
        path = self._session_path(session_id)
        if not path.exists():
            return []
        return json.loads(path.read_text(encoding="utf-8"))

    def _save(self, session_id: str, items: list[dict[str, Any]]) -> None:
        path = self._session_path(session_id)
        path.write_text(json.dumps(items, indent=2, ensure_ascii=False), encoding="utf-8")

    def items(self, session_id: str) -> list[dict[str, Any]]:
        return self._load(session_id)

    def append_message(self, session_id: str, role: str, content: str) -> None:
        items = self._load(session_id)
        items.append({"type": "message", "role": role, "content": content})
        self._save(session_id, items)

    def append_tool_result(self, session_id: str, tool_call: dict[str, Any], result: dict[str, Any]) -> None:
        items = self._load(session_id)
        items.append({"type": "tool", "tool_call": tool_call, "result": result})
        self._save(session_id, items)

    def set_context(self, session_id: str, key: str, value: Any) -> None:
        items = self._load(session_id)
        items.append({"type": "context", "key": str(key), "value": value})
        self._save(session_id, items)

    def get_context(self, session_id: str, key: str) -> Any | None:
        for item in reversed(self._load(session_id)):
            if item.get("type") == "context" and item.get("key") == key:
                return item.get("value")
        return None

    def clear_session(self, session_id: str) -> None:
        path = self._session_path(session_id)
        if path.exists():
            path.unlink()

    def render_for_prompt(self, session_id: str, max_items: int = 24) -> str:
        items = self._load(session_id)
        rendered: list[str] = []

        for item in items[-max_items:]:
            item_type = item.get("type")
            if item_type == "message":
                role = str(item.get("role", "assistant")).capitalize()
                rendered.append(f"{role}: {item.get('content', '')}")
            elif item_type == "tool":
                rendered.append(f"Action: {json.dumps(item.get('tool_call', {}), ensure_ascii=False)}")
                rendered.append(f"Observation: {json.dumps(item.get('result', {}), ensure_ascii=False)}")
            elif item_type == "context":
                rendered.append(f"Context: {item.get('key')}={json.dumps(item.get('value'), ensure_ascii=False)}")

        return "\n".join(rendered)
