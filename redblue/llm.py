"""llm.py — the brain seam. A thin, model-agnostic client over the Claude Messages API.

Zero dependencies (stdlib ``urllib``) on purpose: the whole agent must run in an
air-gapped / minimal box with nothing but Python. The class is deliberately small so a
different backend (a local model, another vendor) can be dropped in behind the same
``complete()`` signature later.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-opus-5"


class LLMError(Exception):
    pass


class Claude:
    """Minimal Claude Messages-API client (tool-use capable, adaptive thinking)."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None,
                 effort: str = "high", timeout: int = 600):
        self.model = model
        self.effort = effort
        self.timeout = timeout
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise LLMError(
                "no API key: set ANTHROPIC_API_KEY or pass api_key=..."
            )

    def complete(self, system, messages, tools=None, max_tokens: int = 16000, on_delta=None):
        """One round-trip. Returns the parsed JSON response dict.

        Sends a standard Messages-API body. `thinking`/`output_config` (adaptive thinking +
        effort) are added when supported, but if the endpoint rejects them with a 400 we retry
        WITHOUT them — so the same client works against the public Anthropic API too, not only
        an environment that understands those fields.
        """
        base = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
        }
        if tools:
            base["tools"] = tools
        enriched = dict(base, thinking={"type": "adaptive"},
                        output_config={"effort": self.effort})
        try:
            return self._send(enriched)
        except LLMError as e:
            msg = str(e)
            fieldish = ("thinking", "output_config", "effort", "adaptive", "unexpected",
                        "unknown", "not supported", "invalid_request", "extra field")
            if "HTTP 400" in msg and any(k in msg for k in fieldish):
                return self._send(base)   # standard public API — drop the extras and retry
            raise

    def _send(self, body):
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            API_URL,
            data=data,
            method="POST",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                payload = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            raise LLMError(f"HTTP {e.code} from Claude API: {detail}") from e
        except urllib.error.URLError as e:
            raise LLMError(f"network error reaching Claude API: {e.reason}") from e

        try:
            return json.loads(payload)
        except json.JSONDecodeError as e:
            raise LLMError(f"bad JSON from Claude API: {e}") from e
