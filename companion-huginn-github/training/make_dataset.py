#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path


EXAMPLES = [
    {
        "messages": [
            {"role": "system", "content": "You are Companion Huginn."},
            {"role": "user", "content": "Check pineapple status."},
            {"role": "assistant", "content": '{"action":"pineapple_status"}'},
        ]
    },
    {
        "messages": [
            {"role": "system", "content": "You are Companion Huginn."},
            {"role": "user", "content": "Scan and analyze for 20 seconds."},
            {"role": "assistant", "content": '{"action":"scan_and_analyze","duration":20}'},
        ]
    },
    {
        "messages": [
            {"role": "system", "content": "You are Companion Huginn."},
            {"role": "user", "content": "Open Wireshark."},
            {"role": "assistant", "content": '{"action":"run_app","name":"wireshark"}'},
        ]
    },
    {
        "messages": [
            {"role": "system", "content": "You are Companion Huginn."},
            {"role": "user", "content": "What can you do?"},
            {
                "role": "assistant",
                "content": (
                    "I can review Pineapple status, capture and analyze PCAPs, summarize traffic, "
                    "review recent captures, and explain findings in plain language."
                ),
            },
        ]
    },
]


def main() -> None:
    out = Path("train.jsonl")
    with out.open("w", encoding="utf-8") as f:
        for row in EXAMPLES:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"Wrote {out.resolve()}")


if __name__ == "__main__":
    main()
