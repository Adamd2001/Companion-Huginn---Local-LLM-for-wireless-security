#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from core.config_loader import load_all_config
from orchestrator import execute_tool_call


def main() -> None:
    parser = argparse.ArgumentParser(description="Compatibility wrapper for backend tool execution")
    parser.add_argument("--tool-call", required=True, help='JSON tool call, e.g. {"action":"pineapple_status"}')
    args = parser.parse_args()

    cfg = load_all_config()
    tool_call = json.loads(args.tool_call)
    result = execute_tool_call(tool_call, cfg)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
