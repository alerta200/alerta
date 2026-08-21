"""local.py — an OFFLINE brain backend over Ollama. No API key, no internet.

This is the owned-model arc's destination made runnable today: redblue driven by a local
model (e.g. Qwen2.5) served by Ollama. It exposes the exact same ``complete()`` seam as
the Claude client, so agent.py is unchanged. The work here is translation:

  Anthropic content-block shape  <->  Ollama /api/chat tool-calling shape

We keep Anthropic's shape as the internal lingua franca (the agent speaks it), and
convert at the boundary on every call.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5:7b"


class LocalError(Exception):
    pass


def list_models(url: str = DEFAULT_URL, timeout: float = 2.0) -> list[str]:
    """Names of models Ollama has pulled locally. Empty list if the server is unreachable."""
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/tags", timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return [m.get("name", "") for m in data.get("models", [])]
    except (urllib.error.URLError, OSError, ValueError):
        return []


class Ollama:
    """Local model brain via Ollama. Same interface as Claude: complete(...)."""

    # The agent may pass on_delta to stream the model's text live; Ollama supports it.
    streams = True

    def __init__(self, model: str = DEFAULT_MODEL, url: str = DEFAULT_URL,
                 num_ctx: int = 8192, timeout: int = 600, tool_mode: str = "native",
                 temperature: float | None = None, seed: int | None = None):
        self.model = model
        self.url = url.rstrip("/")
        self.num_ctx = num_ctx
        self.timeout = timeout
        # 'native' uses Ollama's tools API; 'prompt' describes tools in text and parses
        # the reply — the only way to drive models (like deepseek-r1) that lack tool support.
        self.tool_mode = tool_mode
        # Optional deterministic decoding: leave both None for Ollama's stochastic defaults
        # (unchanged for existing callers); set temperature=0, seed=0 for a reproducible run —
        # what a benchmark/eval needs so a score is a property of the model, not of the sampler.
        self.temperature = temperature
        self.seed = seed
        self._id_counter = 0

    def _opts(self, max_tokens: int) -> dict:
        o = {"num_ctx": self.num_ctx, "num_predict": max_tokens}
        if self.temperature is not None:
            o["temperature"] = self.temperature
        if self.seed is not None:
            o["seed"] = self.seed
        return o

    # ---- public seam -----------------------------------------------------

    def complete(self, system, messages, tools=None, max_tokens: int = 16000, on_delta=None):
        # remember the tool names so we can salvage calls the model writes as ```json in text
        self._tool_names = {t.get("name") for t in tools} if tools else set()
        if tools and self.tool_mode == "prompt":
            return self._complete_prompt(system, messages, tools, max_tokens, on_delta)
        body = {
            "model": self.model,
            "stream": bool(on_delta),
            "messages": self._to_ollama(system, messages),
            "options": self._opts(max_tokens),
        }
        if tools:
            body["tools"] = self._tools_to_ollama(tools)

        try:
            return self._from_ollama(self._post(body, on_delta))
        except LocalError as e:
            # Reasoning models (deepseek-r1, …) reject Ollama's native tools API. Fall back to
            # describing the tools in the prompt and parsing the reply — and remember, so the
            # rest of the run doesn't re-hit the error on every step.
            if tools and "does not support tools" in str(e).lower():
                self.tool_mode = "prompt"
                return self._complete_prompt(system, messages, tools, max_tokens, on_delta)
            raise

    def _post(self, body, on_delta=None):
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.url + "/api/chat", data=data, method="POST",
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if body.get("stream") and on_delta is not None:
                    # NDJSON is consumed here, inside the try: a drop MID-STREAM (Ollama reloads
                    # the model or dies under memory pressure) raises IncompleteRead/timeout —
                    # not URLError — so it must be caught here or it escapes as a raw exception
                    # past complete()'s `except LocalError` and crashes the run.
                    return self._read_stream(resp, on_delta)
                payload = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")
            raise LocalError(f"HTTP {e.code} from Ollama: {detail}") from e
        except urllib.error.URLError as e:
            raise LocalError(
                f"cannot reach Ollama at {self.url} ({e.reason}); is it running?"
            ) from e
        except (http.client.HTTPException, socket.timeout, ConnectionError, OSError) as e:
            raise LocalError(
                f"lost the connection to Ollama at {self.url} mid-response "
                f"({type(e).__name__}); the model may have been reloaded — retry."
            ) from e
        try:
            return json.loads(payload)
        except json.JSONDecodeError as e:
            raise LocalError(f"bad JSON from Ollama: {e}") from e

    @staticmethod
    def _read_stream(resp, on_delta):
        """Consume Ollama's NDJSON stream: forward each content chunk to on_delta for a live
        view, and assemble a single non-streaming-shaped response for the normal parser."""
        parts, tool_calls = [], []
        for raw in resp:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            msg = obj.get("message") or {}
            chunk = msg.get("content") or ""
            if chunk:
                parts.append(chunk)
                try:
                    on_delta(chunk)
                except Exception:  # noqa: BLE001 — a display hiccup must never kill the run
                    pass
            if msg.get("tool_calls"):
                tool_calls.extend(msg["tool_calls"])
            if obj.get("done"):
                break
        return {"message": {"role": "assistant", "content": "".join(parts),
                            "tool_calls": tool_calls}, "done": True}

    # ---- translation: tools ---------------------------------------------

    @staticmethod
    def _tools_to_ollama(tools):
        out = []
        for t in tools:
            out.append({
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {"type": "object"}),
                },
            })
        return out

    # ---- translation: request messages ----------------------------------

    def _to_ollama(self, system, messages):
        out = [{"role": "system", "content": system}]
        # map tool_use id -> tool name, so tool_result turns can be labelled
        id_to_name = {}
        for msg in messages:
            role = msg["role"]
            content = msg["content"]

            if isinstance(content, str):
                out.append({"role": role, "content": content})
                continue

            if role == "assistant":
                text_parts, tool_calls = [], []
                for b in content:
                    if b.get("type") == "text":
                        text_parts.append(b["text"])
                    elif b.get("type") == "tool_use":
                        id_to_name[b["id"]] = b["name"]
                        tool_calls.append({
                            "function": {"name": b["name"],
                                         "arguments": b.get("input", {})}
                        })
                m = {"role": "assistant", "content": "\n".join(text_parts)}
                if tool_calls:
                    m["tool_calls"] = tool_calls
                out.append(m)

            elif role == "user":
                # a list on a user turn = tool_result blocks
                for b in content:
                    if b.get("type") == "tool_result":
                        name = id_to_name.get(b.get("tool_use_id"), "")
                        tmsg = {"role": "tool", "content": str(b.get("content", ""))}
                        if name:
                            tmsg["tool_name"] = name
                        out.append(tmsg)
                    elif b.get("type") == "text":
                        out.append({"role": "user", "content": b["text"]})
        return out

    # ---- translation: response ------------------------------------------

    def _from_ollama(self, raw):
        msg = raw.get("message", {}) or {}
        blocks = []
        text = msg.get("content") or ""
        if text:
            blocks.append({"type": "text", "text": text})

        tool_calls = msg.get("tool_calls") or []
        for tc in tool_calls:
            fn = tc.get("function", {}) or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_raw": args}
            self._id_counter += 1
            blocks.append({
                "type": "tool_use",
                "id": f"call_{self._id_counter}",
                "name": fn.get("name", ""),
                "input": args,
            })

        # Smaller models (qwen2.5:7b) often write the tool call as a ```json block INSIDE the
        # text instead of using the native tool_calls field. Without this, that call is lost and
        # the agent thinks the model is done → shallow, premature runs. Salvage those so a call
        # emitted as prose is executed just like a native one.
        salvaged = []
        if not tool_calls and text:
            salvaged = self._salvage_text_calls(text)
            for nm, args in salvaged:
                self._id_counter += 1
                blocks.append({
                    "type": "tool_use",
                    "id": f"call_{self._id_counter}",
                    "name": nm,
                    "input": args,
                })

        stop_reason = "tool_use" if (tool_calls or salvaged) else "end_turn"
        if not blocks:
            blocks.append({"type": "text", "text": ""})
        return {"content": blocks, "stop_reason": stop_reason}

    def _salvage_text_calls(self, text):
        """Extract tool calls a model wrote as JSON in its text (```json {"name","arguments"}```
        or {"tool","input"}). Only objects whose name is a REAL tool are accepted, so ordinary
        prose and report examples are ignored. De-duplicated, order preserved."""
        names = getattr(self, "_tool_names", set())
        if not names:
            return []
        found, seen = [], set()
        for m in re.finditer(r"\{", text):
            depth = 0
            for i in range(m.start(), len(text)):
                ch = text[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            obj = json.loads(text[m.start():i + 1])
                        except json.JSONDecodeError:
                            break
                        if isinstance(obj, dict):
                            nm = obj.get("name") or obj.get("tool")
                            args = obj.get("arguments")
                            if args is None:
                                args = obj.get("input", {})
                            if nm in names and isinstance(args, dict):
                                key = (nm, json.dumps(args, sort_keys=True, default=str))
                                if key not in seen:
                                    seen.add(key)
                                    found.append((nm, args))
                        break
        return found

    # ---- prompt-based tool calling (for models without native tool support) ----

    def _complete_prompt(self, system, messages, tools, max_tokens, on_delta=None):
        sys_text = system + "\n\n" + self._tool_manual(tools)
        body = {
            "model": self.model,
            "stream": bool(on_delta),
            "messages": self._to_ollama_prompt(sys_text, messages),
            "options": self._opts(max_tokens),
        }
        return self._parse_prompt_response(self._post(body, on_delta))

    @staticmethod
    def _tool_manual(tools):
        lines = ["You have TOOLS. You cannot act except by calling a tool.",
                 "AVAILABLE TOOLS:"]
        for t in tools:
            props = (t.get("input_schema", {}) or {}).get("properties", {})
            args = ", ".join(props.keys())
            lines.append(f"- {t['name']}({args}): {t.get('description','')}")
        lines.append(
            "\nTo CALL a tool, output ONE line of JSON and nothing else:\n"
            '{"tool": "<name>", "input": {<args>}}\n'
            "You will then receive the tool result and may call another tool.\n"
            "When the assessment is COMPLETE, output your final report as plain prose "
            "with NO json. Do not output json and a report in the same message.")
        return "\n".join(lines)

    def _to_ollama_prompt(self, sys_text, messages):
        out = [{"role": "system", "content": sys_text}]
        id_to_name = {}
        for msg in messages:
            role, content = msg["role"], msg["content"]
            if isinstance(content, str):
                out.append({"role": role, "content": content})
                continue
            if role == "assistant":
                parts = []
                for b in content:
                    if b.get("type") == "text" and b.get("text"):
                        parts.append(b["text"])
                    elif b.get("type") == "tool_use":
                        id_to_name[b["id"]] = b["name"]
                        parts.append(json.dumps({"tool": b["name"],
                                                 "input": b.get("input", {})}))
                out.append({"role": "assistant", "content": "\n".join(parts)})
            elif role == "user":
                for b in content:
                    if b.get("type") == "tool_result":
                        name = id_to_name.get(b.get("tool_use_id"), "tool")
                        out.append({"role": "user",
                                    "content": f"TOOL RESULT [{name}]:\n"
                                               + str(b.get("content", ""))})
                    elif b.get("type") == "text":
                        out.append({"role": "user", "content": b["text"]})
        return out

    def _parse_prompt_response(self, raw):
        text = (raw.get("message", {}) or {}).get("content", "") or ""
        # strip reasoning models' <think>...</think> before parsing for a tool call
        think = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        call = self._extract_tool_json(think, getattr(self, "_tool_names", None))
        if call:
            self._id_counter += 1
            return {"content": [{"type": "tool_use",
                                 "id": f"call_{self._id_counter}",
                                 "name": call["tool"],
                                 "input": call.get("input", {})}],
                    "stop_reason": "tool_use"}
        return {"content": [{"type": "text", "text": think or text}],
                "stop_reason": "end_turn"}

    @staticmethod
    def _extract_tool_json(text, names=None):
        # Find a tool call written as JSON, scanning balanced braces. Accept BOTH the format we
        # instruct ({"tool","input"}) and the OpenAI style many models emit unprompted
        # ({"name","arguments"}) — the latter validated against real tool names to avoid
        # mistaking a random JSON object for a call. Returns a normalized {"tool","input"}.
        for m in re.finditer(r"\{", text):
            depth = 0
            for i in range(m.start(), len(text)):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            obj = json.loads(text[m.start():i + 1])
                        except json.JSONDecodeError:
                            break
                        if isinstance(obj, dict):
                            if "tool" in obj:
                                return {"tool": obj["tool"], "input": obj.get("input", {})}
                            nm = obj.get("name")
                            if (nm and (not names or nm in names)
                                    and ("arguments" in obj or "input" in obj)):
                                return {"tool": nm,
                                        "input": obj.get("arguments") or obj.get("input") or {}}
                        break
        return None
