"""
modules/agent/backends.py
AI backend adapters: Ollama (local) and Anthropic Claude (API).
Both return objects with a .choices[0].message interface so callers
don't need to branch on which backend is active.
"""
import json
from types import SimpleNamespace

from .constants import OLLAMA_API_TIMEOUT


def _ollama_chat_completion(
    model: str,
    messages: list,
    tools: list | None = None,
    tool_choice: str | None = None,
    temperature: float = 0.05,
    max_tokens: int | None = None,
    timeout: int | None = None,
):
    """
    Call Ollama's local OpenAI-compatible chat endpoint.
    Returns a SimpleNamespace that mirrors the anthropic Message shape so the
    agent loop can treat both backends the same way.
    """
    import requests

    payload: dict = {
        "model":       model,
        "messages":    messages,
        "temperature": temperature,
        "stream":      False,
        "keep_alive":  -1,
        "options":     {"num_ctx": 4096, "num_gpu": 99},
    }
    if tools is not None:
        payload["tools"] = tools
    if tool_choice:
        payload["tool_choice"] = tool_choice
    if max_tokens:
        payload["max_tokens"] = max_tokens

    resp = requests.post(
        "http://127.0.0.1:11434/v1/chat/completions",
        json=payload,
        timeout=timeout or OLLAMA_API_TIMEOUT,
    )
    resp.raise_for_status()
    data    = resp.json()
    raw_msg = data["choices"][0].get("message", {})

    tool_calls = []
    for i, tc in enumerate(raw_msg.get("tool_calls") or []):
        fn   = tc.get("function") or {}
        args = fn.get("arguments", "")
        if not isinstance(args, str):
            args = json.dumps(args)
        tool_calls.append(
            SimpleNamespace(
                id=tc.get("id") or f"call_{i}",
                type=tc.get("type", "function"),
                function=SimpleNamespace(
                    name=fn.get("name", ""),
                    arguments=args,
                ),
            )
        )

    msg = SimpleNamespace(
        content=raw_msg.get("content") or "",
        tool_calls=tool_calls,
    )
    return SimpleNamespace(choices=[SimpleNamespace(message=msg)])
