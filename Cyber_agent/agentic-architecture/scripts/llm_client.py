#!/usr/bin/env python3
import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List


def _make_ssl_context(verify: bool = True) -> ssl.SSLContext:
    """
    Contexte SSL robuste : TLS 1.2+, vérification des certificats via le store système.
    Si verify=False : désactive la vérification (utile derrière un proxy d'inspection SSL).
    """
    if verify:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def load_llm_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def _headers_from_config(config: Dict[str, Any]) -> Dict[str, str]:
    api_key_env = config.get("api_key_env", "")
    api_key = config.get("api_key") or os.environ.get(api_key_env, "")
    if not api_key:
        raise RuntimeError(f"Missing API key in env var {api_key_env}")

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    }

    extra = config.get("extra_headers", {})
    if isinstance(extra, dict):
        for k, v in extra.items():
            if isinstance(k, str) and isinstance(v, str):
                headers[k] = v

    return headers


def call_chat(messages: List[Dict[str, str]], config: Dict[str, Any]) -> str:
    provider = str(config.get("provider", "openrouter")).lower()
    api_base = config.get("api_base")
    if not api_base:
        raise RuntimeError("Missing api_base in LLM config")

    if provider not in {"openrouter", "openai-compatible"}:
        raise RuntimeError(f"Unsupported provider: {provider}")

    payload = {
        "model": config.get("model"),
        "messages": messages,
        "temperature": config.get("temperature", 0.2),
        "max_tokens": config.get("max_tokens", 800)
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(api_base, data=data, headers=_headers_from_config(config), method="POST")

    verify_ssl = config.get("verify_ssl", True)
    ssl_ctx = _make_ssl_context(verify=verify_ssl)
    try:
        with urllib.request.urlopen(req, timeout=60, context=ssl_ctx) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore") if exc.fp else ""
        raise RuntimeError(f"LLM API HTTP {exc.code}: {body[:400]}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"LLM API connection error: {exc.reason}") from exc

    parsed = json.loads(raw)
    choices = parsed.get("choices", [])
    if not choices:
        raise RuntimeError("LLM response missing choices")

    message = choices[0].get("message", {})
    content = message.get("content", "")
    if not content:
        raise RuntimeError("LLM response missing content")
        
    # LOG TRACE
    try:
        import datetime
        trace_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'llm_trace.json')
        trace_data = []
        if os.path.exists(trace_path):
            with open(trace_path, 'r', encoding='utf-8') as f:
                try: trace_data = json.load(f)
                except json.JSONDecodeError: pass
        
        trace_data.append({
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "model": config.get("model", "unknown"),
            "input_messages": messages,
            "raw_response": content
        })
        
        with open(trace_path, 'w', encoding='utf-8') as f:
            json.dump(trace_data, f, indent=2)
    except Exception as e:
        print(f"Warning: Failed to log LLM trace: {e}")

    return content


def extract_json(text: str) -> Dict[str, Any]:
    # 1. Direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # 2. Strip markdown code fences (```json ... ``` or ``` ... ```)
    stripped = text.strip()
    for fence in ("```json", "```JSON", "```"):
        if stripped.startswith(fence):
            stripped = stripped[len(fence):].strip()
            if stripped.endswith("```"):
                stripped = stripped[:-3].strip()
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass
            break

    # 3. Extract the outermost {} block
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                try:
                    return json.loads(text[start:i + 1])
                except json.JSONDecodeError:
                    pass

    raise RuntimeError("No valid JSON object found in LLM output")
