"""Minimal chat clients for Ollama and OpenAI-compatible servers. Only httpx is required."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx


class LLMError(Exception):
    pass


@dataclass
class ChatResult:
    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)  # [{"id", "name", "arguments"}]


class ChatClient(Protocol):
    name: str
    model: str

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None,
             json_schema: dict[str, Any] | None = None, seed: int = 0, timeout: float = 60) -> ChatResult: ...

    def available(self) -> bool: ...


class OllamaClient:
    name = "ollama"

    def __init__(self, base_url: str, model: str, http: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.http = http or httpx.Client()

    def chat(self, messages, tools=None, json_schema=None, seed=0, timeout=60.0) -> ChatResult:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0, "seed": seed},
        }
        if tools:
            body["tools"] = tools
        if json_schema:
            body["format"] = json_schema
        try:
            resp = self.http.post(f"{self.base_url}/api/chat", json=body, timeout=timeout)
            resp.raise_for_status()
            message = resp.json()["message"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc
        calls = []
        for i, call in enumerate(message.get("tool_calls") or []):
            fn = call.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except ValueError:
                    args = {"__unparsed__": args}
            calls.append({"id": f"call_{i}", "name": fn.get("name", ""), "arguments": args})
        return ChatResult(content=message.get("content") or "", tool_calls=calls)

    def available(self) -> bool:
        try:
            resp = self.http.get(f"{self.base_url}/api/tags", timeout=2)
            resp.raise_for_status()
            names = [m.get("name", "") for m in resp.json().get("models", [])]
            return self.model in names or f"{self.model}:latest" in names
        except (httpx.HTTPError, ValueError):
            return False


class OpenAICompatibleClient:
    name = "openai_compatible"

    def __init__(self, base_url: str, model: str, api_key: str = "", http: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.http = http or httpx.Client()

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

    def chat(self, messages, tools=None, json_schema=None, seed=0, timeout=60.0) -> ChatResult:
        body: dict[str, Any] = {"model": self.model, "messages": messages, "temperature": 0, "seed": seed}
        if tools:
            body["tools"] = tools
        if json_schema:
            body["response_format"] = {"type": "json_object"}
        try:
            resp = self.http.post(f"{self.base_url}/chat/completions", json=body, headers=self._headers(), timeout=timeout)
            resp.raise_for_status()
            message = resp.json()["choices"][0]["message"]
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise LLMError(f"Chat request failed: {exc}") from exc
        calls = []
        for call in message.get("tool_calls") or []:
            fn = call.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except ValueError:
                args = {"__unparsed__": fn.get("arguments")}
            calls.append({"id": call.get("id", ""), "name": fn.get("name", ""), "arguments": args})
        return ChatResult(content=message.get("content") or "", tool_calls=calls)

    def available(self) -> bool:
        if not self.base_url or not self.model:
            return False
        try:
            return self.http.get(f"{self.base_url}/models", headers=self._headers(), timeout=3).status_code == 200
        except httpx.HTTPError:
            return False


def build_client(kind: str, settings, http: httpx.Client | None = None) -> ChatClient:
    if kind == "ollama":
        return OllamaClient(settings.ollama_url, settings.ollama_model, http=http)
    if kind == "openai_compatible":
        if not settings.openai_base_url or not settings.openai_model:
            raise LLMError("BG_OPENAI_BASE_URL and BG_OPENAI_MODEL must be set.")
        return OpenAICompatibleClient(settings.openai_base_url, settings.openai_model, settings.openai_api_key, http=http)
    raise LLMError(f"Unknown LLM provider '{kind}'.")
