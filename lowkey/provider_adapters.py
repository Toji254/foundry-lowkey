"""Replaceable transports for Lowkey's structured model requests.

The application owns prompts, policy, schemas and conclusions. Adapters own only
transport. A provider adapter must never execute tools or mutate audit state.
"""
from __future__ import annotations

import json
import re
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class ProviderAdapterError(RuntimeError):
    """Transport failure with a safe category that excludes provider response bodies."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


class OpenAICompatibleAdapter:
    """Transport adapter for OpenAI-compatible chat-completions APIs."""

    name = "openai-compatible"

    def send(
        self,
        *,
        config: Mapping[str, Any],
        api_key: str | None,
        payload: Mapping[str, Any],
        request_type: Callable[..., Any] = Request,
        urlopen_fn: Callable[..., Any] = urlopen,
        http_error_type: type[BaseException] = HTTPError,
        url_error_type: type[BaseException] = URLError,
        max_response_bytes: int = 96_000,
    ) -> bytes:
        base_url = str(config.get("base_url") or "").rstrip("/")
        if not base_url:
            raise ProviderAdapterError("configuration", "Provider base URL is missing.")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        request = request_type(
            base_url + "/chat/completions",
            data=json.dumps(dict(payload), ensure_ascii=False).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen_fn(request, timeout=int(config.get("timeout_seconds", 45))) as response:
                raw = response.read(max_response_bytes + 1)
        except http_error_type as exc:
            status = getattr(exc, "code", None)
            # Inspect only a bounded body for classification; never echo or persist it.
            try:
                error_body = exc.read(4096).decode("utf-8", errors="replace").lower()
            except Exception:
                error_body = ""
            quota_markers = (
                "quota", "resource_exhausted", "insufficient_quota", "billing hard limit",
                "exceeded your current quota", "token limit reached", "out of credits",
            )
            rate_markers = ("rate limit", "rate_limit", "too many requests", "requests per minute")
            if any(marker in error_body for marker in quota_markers):
                category, detail = "quota", "provider quota or token allowance exhausted"
            elif status == 429:
                category, detail = "rate-limit", "provider rate limit reached"
            elif status in {401, 403}:
                category, detail = "authentication", "authentication or access rejected"
            else:
                category, detail = "http", f"HTTP {status if status is not None else 'error'}"
            raise ProviderAdapterError(category, f"AI provider request failed ({detail}).") from exc
        except url_error_type as exc:
            raise ProviderAdapterError("network", "AI provider could not be reached.") from exc
        except TimeoutError as exc:
            raise ProviderAdapterError("network", "AI provider request timed out.") from exc
        if len(raw) > max_response_bytes:
            raise ProviderAdapterError("response-size", "Provider response exceeded Lowkey's response-size limit.")
        return raw


_ADAPTERS: dict[str, Any] = {}
_PROVIDER_NAME = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


def register_provider_adapter(provider: str, adapter: Any, *, replace: bool = False) -> None:
    """Register an adapter implementation. Replacements must be explicit in application code."""
    name = str(provider or "").strip().lower()
    if not _PROVIDER_NAME.fullmatch(name):
        raise ValueError("Provider adapter name must be a lowercase identifier.")
    if not callable(getattr(adapter, "send", None)):
        raise TypeError("Provider adapter must implement send(...).")
    if name in _ADAPTERS and not replace:
        raise ValueError(f"Provider adapter already registered: {name}")
    _ADAPTERS[name] = adapter


def get_provider_adapter(provider: str) -> Any:
    name = str(provider or "").strip().lower()
    try:
        return _ADAPTERS[name]
    except KeyError as exc:
        raise ProviderAdapterError("configuration", f"No provider adapter registered for '{name}'.") from exc


def provider_adapter_status() -> dict[str, Any]:
    """Return observable adapter names without revealing credentials or endpoint secrets."""
    return {
        "registered_providers": sorted(_ADAPTERS),
        "adapters": sorted({str(getattr(item, "name", type(item).__name__)) for item in _ADAPTERS.values()}),
    }


_default = OpenAICompatibleAdapter()
for _provider in ("deepseek", "gemini", "openai", "openai-compatible", "ollama", "orcarouter", "openrouter", "nvidia"):
    register_provider_adapter(_provider, _default)
