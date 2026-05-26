#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from typing import Any

from core.app_paths import get_log_path
from core.tool_registry import build_registry


def _log_action(record: dict[str, Any]) -> None:
    log_path = get_log_path("action_log.jsonl")
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _balanced_json_objects(text: str) -> list[dict[str, Any]]:
    """
    Extract all valid JSON objects from text using balanced-brace scanning.
    Correctly handles prose mixed with JSON - avoids the greedy-match failure
    of a simple r"\\{.*\\}" regex with DOTALL.
    """
    results: list[dict[str, Any]] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "{":
            depth = 0
            j = i
            while j < n:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = text[i : j + 1]
                        try:
                            obj = json.loads(candidate)
                            if isinstance(obj, dict):
                                results.append(obj)
                        except json.JSONDecodeError:
                            pass
                        i = j
                        break
                j += 1
        i += 1
    return results


def extract_json_tool_call(text: str | None) -> dict[str, Any] | None:
    """
    Extract a valid tool-call JSON object from model output.

    Priority order:
    1. Entire reply is exactly one JSON object (strict / best-case path)
    2. JSON object inside a code fence (```json ... ``` or ``` ... ```)
    3. Balanced-brace scan - finds first valid JSON object containing 'action'

    Safety:
    - Returns None for non-string / empty input.
    - Never raises; JSON parse errors are caught silently.
    """
    if not isinstance(text, str):
        return None

    text = text.strip()
    if not text:
        return None

    # Best case: the whole reply is exactly one JSON object.
    if text.startswith("{") and text.endswith("}"):
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict) and "action" in obj:
            return obj

    # Recovery from fenced JSON: ```json { ... } ``` or ``` { ... } ```
    for fenced_match in re.finditer(
        r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.DOTALL | re.IGNORECASE
    ):
        candidate = fenced_match.group(1).strip()
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "action" in obj:
            return obj

    # Balanced-brace scan: robust extraction from mixed text.
    # Returns first valid JSON object that has an 'action' key.
    for obj in _balanced_json_objects(text):
        if "action" in obj:
            return obj

    return None


def execute_tool_call(tool_call: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    registry = build_registry(cfg)
    action = str(tool_call.get("action", "")).strip()

    if not action:
        result = {"ok": False, "error": "Missing action"}
        _log_action({"action": action, "tool_call": tool_call, "result": result})
        return result

    if action not in registry:
        result = {"ok": False, "error": f"Unknown action: {action}"}
        _log_action({"action": action, "tool_call": tool_call, "result": result})
        return result

    handler = registry[action]
    try:
        result = handler(tool_call)
        if not isinstance(result, dict):
            result = {
                "ok": False,
                "error": (
                    f"Tool '{action}' returned a non-dict result "
                    f"of type {type(result).__name__}"
                ),
            }
    except Exception as exc:
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    _log_action({"action": action, "tool_call": tool_call, "result": result})
    return result
