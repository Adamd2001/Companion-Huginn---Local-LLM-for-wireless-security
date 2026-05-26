from __future__ import annotations

import requests


def ask_ollama(
    prompt: str,
    model_name: str,
    ollama_url: str,
    temperature: float,
    top_p: float,
    num_predict: int,
    timeout: int,
) -> str:
    response = requests.post(
        ollama_url,
        json={
            "model": model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "top_p": top_p,
                "repeat_penalty": 1.1,
                "num_predict": num_predict,
            },
        },
        timeout=timeout,
    )
    response.raise_for_status()
    return (response.json().get("response") or "").strip()
