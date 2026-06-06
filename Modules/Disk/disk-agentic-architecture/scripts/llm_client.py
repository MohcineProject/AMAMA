#!/usr/bin/env python3
import contextlib
import fcntl
import json
import os
import ssl
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List


# Tracks usage from the most recent call_chat() invocation.
_last_call_usage: dict = {"tokens_in": 0, "tokens_out": 0}


@contextlib.contextmanager
def _api_lock():
    """Cross-process mutex so RAM and Disk never call the LLM API simultaneously.

    Both modules run as separate OS subprocesses, so an in-process lock would do
    nothing. They share a single lockfile (overridable via AMAMA_API_LOCK) and
    acquire an exclusive flock around the one HTTP request — held only for the
    request itself, released before any 429 backoff sleep so a module that is
    waiting out a rate limit does not block the other. Degrades to a no-op if the
    lockfile can't be created, so standalone runs are unaffected.
    """
    lock_path = os.environ.get("AMAMA_API_LOCK") or os.path.join(
        tempfile.gettempdir(), "amama_anthropic_api.lock"
    )
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o666)
    except OSError:
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def get_last_usage() -> dict:
    """Return token counts from the most recent call_chat() call."""
    return dict(_last_call_usage)


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


def _call_anthropic(messages: List[Dict[str, str]], config: Dict[str, Any]) -> str:
    """Handle Anthropic's native API format (/v1/messages)."""
    api_base = config.get("api_base", "https://api.anthropic.com/v1/messages")

    api_key_env = config.get("api_key_env", "ANTHROPIC_API_KEY")
    api_key = config.get("api_key") or os.environ.get(api_key_env, "")
    if not api_key:
        raise RuntimeError(f"Missing Anthropic API key (field api_key or env {api_key_env})")

    # Anthropic uses a top-level `system` field; extract it from messages
    system_content = ""
    user_messages = []
    for msg in messages:
        if msg.get("role") == "system":
            system_content = msg.get("content", "")
        else:
            user_messages.append(msg)

    payload: Dict[str, Any] = {
        "model": config.get("model"),
        "max_tokens": config.get("max_tokens", 2000),
        "messages": user_messages,
    }
    if system_content:
        payload["system"] = system_content
    if "temperature" in config:
        payload["temperature"] = config["temperature"]

    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    data = json.dumps(payload).encode("utf-8")
    verify_ssl = config.get("verify_ssl", True)
    ssl_ctx = _make_ssl_context(verify=verify_ssl)

    max_attempts = int(config.get("max_retries", 5)) + 1
    for attempt in range(1, max_attempts + 1):
        req = urllib.request.Request(api_base, data=data, headers=headers, method="POST")
        try:
            with _api_lock():
                with urllib.request.urlopen(req, timeout=120, context=ssl_ctx) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
            break
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore") if exc.fp else ""
            if exc.code == 429 and attempt < max_attempts:
                wait = _parse_retry_after(body)
                print(f"[llm] 429 rate limit — waiting {wait:.0f}s (attempt {attempt}/{max_attempts})...", flush=True)
                time.sleep(wait)
                continue
            raise RuntimeError(f"Anthropic API HTTP {exc.code}: {body[:400]}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Anthropic API connection error: {exc.reason}") from exc

    parsed = json.loads(raw)
    content_blocks = parsed.get("content", [])
    if not content_blocks:
        raise RuntimeError(f"Anthropic response missing content: {str(parsed)[:200]}")
    usage = parsed.get("usage", {})
    _last_call_usage["tokens_in"] = int(usage.get("input_tokens", 0))
    _last_call_usage["tokens_out"] = int(usage.get("output_tokens", 0))
    return content_blocks[0].get("text", "")


def _parse_retry_after(body: str) -> float:
    """Extract wait time in seconds from a 429 response body."""
    try:
        parsed = json.loads(body)
        meta = parsed.get("error", {}).get("metadata", {})
        # Provider-level retry hint (e.g. Venice upstream)
        if "retry_after_seconds" in meta:
            return float(meta["retry_after_seconds"]) + 1.0
        # OpenRouter rate-limit reset timestamp (milliseconds)
        reset_ms = meta.get("headers", {}).get("X-RateLimit-Reset")
        if reset_ms:
            wait = (int(reset_ms) / 1000.0) - time.time()
            return max(wait + 1.0, 5.0)
        # Standard Retry-After header value
        retry_after = meta.get("headers", {}).get("Retry-After")
        if retry_after:
            return float(retry_after) + 1.0
    except Exception:
        pass
    return 15.0  # conservative default


def call_chat(messages: List[Dict[str, str]], config: Dict[str, Any]) -> str:
    provider = str(config.get("provider", "openrouter")).lower()
    api_base = config.get("api_base")
    if not api_base:
        raise RuntimeError("Missing api_base in LLM config")

    if provider == "anthropic":
        content = _call_anthropic(messages, config)
        # Fall through to trace logging below
    elif provider in {"openrouter", "openai-compatible"}:
        payload = {
            "model": config.get("model"),
            "messages": messages,
            "temperature": config.get("temperature", 0.2),
            "max_tokens": config.get("max_tokens", 800)
        }

        # Allow extra top-level payload keys (e.g. {"thinking": {"type": "disabled"}} for Gemini)
        extra_payload = config.get("extra_payload", {})
        if isinstance(extra_payload, dict):
            payload.update(extra_payload)

        data = json.dumps(payload).encode("utf-8")
        verify_ssl = config.get("verify_ssl", True)
        ssl_ctx = _make_ssl_context(verify=verify_ssl)

        max_attempts = int(config.get("max_retries", 5)) + 1
        for attempt in range(1, max_attempts + 1):
            req = urllib.request.Request(api_base, data=data, headers=_headers_from_config(config), method="POST")
            try:
                with _api_lock():
                    with urllib.request.urlopen(req, timeout=120, context=ssl_ctx) as resp:
                        raw = resp.read().decode("utf-8", errors="ignore")
                break
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="ignore") if exc.fp else ""
                if exc.code == 429 and attempt < max_attempts:
                    wait = _parse_retry_after(body)
                    print(f"[llm] 429 rate limit — waiting {wait:.0f}s (attempt {attempt}/{max_attempts})...", flush=True)
                    time.sleep(wait)
                    continue
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
        usage = parsed.get("usage", {})
        _last_call_usage["tokens_in"] = int(usage.get("prompt_tokens", 0))
        _last_call_usage["tokens_out"] = int(usage.get("completion_tokens", 0))
    else:
        raise RuntimeError(f"Unsupported provider: {provider}")
        
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
