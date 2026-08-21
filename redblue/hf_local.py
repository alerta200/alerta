"""hf_local.py — a transformers-backed brain (base model + optional LoRA adapter).

Same complete() seam as llm.Claude / local.Ollama, so SecurityAgent can drive a locally
fine-tuned student exactly like any other brain. This is how we measure the LoRA adapter on
the same linejka the baseline scored 74% on — no GGUF export, no Ollama round-trip.

Tool calls use Qwen2.5's native chat-template format (<tool_call>{json}</tool_call>); we
render the Anthropic-block conversation into chat messages, generate, and parse the calls
back into Anthropic blocks.
"""

from __future__ import annotations

import json
import os
import re

import torch
from transformers import (AutoModelForCausalLM, AutoTokenizer, StoppingCriteria,
                          StoppingCriteriaList)

_CALL = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)

# Inference must feed the model the SAME shape it was trained on: prepare_sft.py trims each
# tool result's `body_preview` to its evidence-bearing head (~400 chars — where the JWT, the
# first collection emails, the SQL error, the reflected marker all sit). At inference the live
# tools return FULL bodies (e.g. Juice Shop's ~100 KB Angular SPA), so without the same trim the
# context balloons to tens of thousands of tokens and prefill OOMs a 12 GB card — AND it's off
# the training distribution. We trim ONLY what the model sees here; the agent's transcript keeps
# the full result, so the evidence scorer (findings.analyze) still reads every signal.
_BODY_CAP = 400
_TOOL_CAP = 1200


def _trim_tool_content(content):
    if not isinstance(content, str):
        return content
    try:
        obj = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return content if len(content) <= _TOOL_CAP else content[:_TOOL_CAP] + "...[truncated]"
    bp = obj.get("body_preview")
    if isinstance(bp, str) and len(bp) > _BODY_CAP:
        obj["body_preview"] = bp[:_BODY_CAP] + "...[truncated]"
        return json.dumps(obj, ensure_ascii=False)
    return content

# Salvage seam for a known 1.5B failure: on an injection payload (a bare quote ' for
# SQLi, ../ for traversal), greedy decode derails — it emits a garbage token (e.g. a CJK
# fragment) and a malformed / double-stringified tool-call whose JSON string never closes,
# so _bare_calls can't recover it and the intended probe is silently dropped (trajectory
# ends, the payload is never actually sent). The model's *intent* is explicit and correct
# ("test ...?text= for SQL injection with a quote"); only the token emission collapses. So
# when no call parsed but the text clearly carries a failed single-arg URL tool-call, we
# reconstruct it. The probe then really fires; the evidence scorer credits it only because
# the live server confirms — no fabrication is introduced, we just stop losing the request.
_SALVAGE_TOOLS = {"http_probe": "url", "security_headers": "url",
                  "content_discovery": "base_url"}
_NAME_RE = re.compile(r"""["']name["']\s*:\s*["'](\w+)["']""")
_URL_RE = re.compile(r"""https?://[^\s"'\\}\],]*['<>][^\s"\\}\],]*|https?://[^\s"'\\}\],]+""")


# The token-carry probe is the one the model most often collapses into PROSE rather than a
# JSON call — it writes `read_collection(http://host/rest/user/profile, token)` as narration,
# so the broken-access / data-exposure test never actually fires. Its intent is explicit and
# correct; reconstruct it (split the URL into base_url + path — the tool re-attaches the token
# captured by a prior login_test). Same discipline as the URL-tool salvage: the evidence scorer
# still gates the credit on a live server response, so nothing is fabricated.
_RC_RE = re.compile(r"read_collection\(\s*(https?://[^\s,()'\"]+)", re.I)


def _clean_lead(text):
    """Drop non-ASCII garbage (collapse artifacts) and dangling call scaffolding from lead text."""
    return re.sub(r"[^\x00-\x7F]+", " ", text).rstrip(" \t\n{").strip()


def _salvage(text):
    """Reconstruct a collapsed tool-call (as (tool, input_dict, lead)) from a derailed
    generation, or None. Handles the prose `read_collection(url, token)` token-carry probe and
    the single-arg URL tools whose JSON call collapsed on an injection payload."""
    m = _RC_RE.search(text)
    if m:
        from urllib.parse import urlsplit
        u = urlsplit(m.group(1))
        base = f"{u.scheme}://{u.netloc}"
        path = u.path or "/"
        return "read_collection", {"base_url": base, "path": path}, _clean_lead(text[:m.start()])
    nm = _NAME_RE.search(text)
    if not nm or nm.group(1) not in _SALVAGE_TOOLS:
        return None
    um = _URL_RE.search(text, nm.end()) or _URL_RE.search(text)
    if not um:
        return None
    tool = nm.group(1)
    return tool, {_SALVAGE_TOOLS[tool]: um.group(0)}, _clean_lead(text[:nm.start()])


def _looping(text, thresh=5):
    """True if a substantial line (>12 chars) has recurred >=thresh times — the signature of a
    greedy-decode runaway (a spurious token seeds an exact-repeat cycle that eats the budget)."""
    lines = [ln.strip() for ln in text.splitlines() if len(ln.strip()) > 12]
    return bool(lines) and lines.count(lines[-1]) >= thresh


class _StopOnCallOrLoop(StoppingCriteria):
    """Stop a step's generation as soon as it has emitted its first COMPLETE tool-call, or once a
    verbatim-repeat loop is detected. Unlike repetition_penalty / no_repeat_ngram (which act on
    logits over the whole sequence and corrupt structured JSON), this only *ends* generation — it
    never alters what token is chosen — so tool-call JSON stays intact while the runaway budget-
    eating loop can't form. The agent re-prompts each turn, so stopping at the first call is free."""

    def __init__(self, tok, plen, check_every=8):
        self.tok, self.plen, self.every, self.n = tok, plen, check_every, 0

    def __call__(self, input_ids, scores, **kw):
        self.n += 1
        if self.n % self.every:
            return False
        tail = self.tok.decode(input_ids[0, self.plen:], skip_special_tokens=True)
        if _CALL.search(tail):
            return True
        for _s, _e, blob in _bare_calls(tail):
            if '"name"' in blob:
                return True
        return _looping(tail)


def _openai_tools(schemas):
    out = []
    for s in schemas:
        out.append({"type": "function",
                    "function": {"name": s["name"], "description": s["description"],
                                 "parameters": s["input_schema"]}})
    return out


def _to_chat(system, messages):
    """Anthropic blocks -> Qwen chat messages (assistant tool_calls / tool role)."""
    chat = [{"role": "system", "content": system}]
    for m in messages:
        role, content = m["role"], m["content"]
        if isinstance(content, str):
            chat.append({"role": role, "content": content})
            continue
        if role == "assistant":
            text, calls = [], []
            for b in content:
                if b.get("type") == "text":
                    text.append(b["text"])
                elif b.get("type") == "tool_use":
                    calls.append({"id": b["id"], "type": "function",
                                  "function": {"name": b["name"],
                                               "arguments": json.dumps(b.get("input", {}))}})
            a = {"role": "assistant", "content": "\n".join(text)}
            if calls:
                a["tool_calls"] = calls
            chat.append(a)
        else:  # user turn carrying tool_result blocks
            for b in content:
                if b.get("type") == "tool_result":
                    chat.append({"role": "tool", "tool_call_id": b["tool_use_id"],
                                 "content": _trim_tool_content(b["content"])})
    return chat


class HFBrain:
    # The agent streams the model's text live when the brain advertises `streams` — the local
    # model is the slow one (~4-5 tok/s), so signs of life matter most here.
    streams = True

    def __init__(self, base: str, adapter: str | None = None, max_new_tokens: int = 1024,
                 load_4bit: bool | None = None, temperature: float = 0.0):
        self.model_name = adapter or base
        self.model = base + (f"+{adapter}" if adapter else "")
        self.max_new_tokens = max_new_tokens
        # Sampled decoding for the self-improvement flywheel (rejection sampling needs the k
        # attempts per problem to DIFFER). Default 0.0 == greedy == the proven eval path, byte
        # for byte — sampling only activates when a caller opts in (temperature>0). Set
        # `gen_seed` per attempt for reproducible-but-varied samples.
        self.temperature: float = float(temperature)
        self.gen_seed: int | None = None
        self.tok = AutoTokenizer.from_pretrained(base)
        # 4-bit (NF4) включается параметром или env RB_4BIT — чтобы 7B влез в 12 ГБ VRAM.
        if load_4bit is None:
            load_4bit = os.environ.get("RB_4BIT", "") not in ("", "0", "false", "False")
        # Авто-выбор устройства: GPU (bf16/4-bit) если есть CUDA, иначе CPU (f32) — чтобы
        # харнесс воспроизводился и без CUDA-torch (был хардкод device_map={"":0}).
        if torch.cuda.is_available():
            # Force the memory-efficient SDPA kernel: over a multi-step trajectory the context
            # grows long, and the eager MATH attention path materializes O(seq^2) scores that
            # OOM a 12 GB card on prefill. Mem-efficient attention is O(seq). Flash is
            # unavailable on this Windows build, so mem-efficient carries it.
            # Enabling mem-efficient alone is not enough — the dispatcher still silently falls
            # back to MATH when mem-efficient declines a call, and that O(seq^2) prefill is what
            # OOMs once a deeper trajectory (login spray + token carry) grows the context. So we
            # DISABLE MATH outright, forcing the O(seq) kernel (an explicit error beats a silent
            # OOM if a call is ever unservable).
            # MATH is disabled by default to force the O(seq) kernel (see above). But on some
            # torch builds (e.g. 2.6 + Windows) mem-efficient/flash/cudnn all DECLINE the GQA
            # broadcast / seq-len-1 decode step, so disabling MATH leaves "No available kernel".
            # RB_MATH_SDP=1 keeps MATH enabled for those builds (fine for short contexts).
            torch.backends.cuda.enable_mem_efficient_sdp(True)
            torch.backends.cuda.enable_flash_sdp(True)
            allow_math = os.environ.get("RB_MATH_SDP", "") not in ("", "0", "false", "False")
            torch.backends.cuda.enable_math_sdp(allow_math)
            if load_4bit:
                from transformers import BitsAndBytesConfig
                quant = BitsAndBytesConfig(
                    load_in_4bit=True, bnb_4bit_quant_type="nf4",
                    bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
                model = AutoModelForCausalLM.from_pretrained(
                    base, quantization_config=quant, device_map={"": 0},
                    torch_dtype=torch.bfloat16, attn_implementation="sdpa")
            else:
                # device_map={"":0} (accelerate GPU placement) segfaults (0xC0000005) on this
                # torch 2.11+cu126 / transformers build. Load on CPU then move with .to("cuda") —
                # equivalent for a single card and stable (verified: forward pass clean).
                model = AutoModelForCausalLM.from_pretrained(
                    base, torch_dtype=torch.bfloat16,
                    attn_implementation="sdpa").to("cuda")
        else:
            model = AutoModelForCausalLM.from_pretrained(
                base, torch_dtype=torch.float32)
        if adapter:
            from peft import PeftModel
            model = PeftModel.from_pretrained(model, adapter)
        model.eval()
        self.lm = model
        self._cid = 0

    def complete(self, system, messages, tools=None, max_tokens=None, effort=None, on_delta=None):
        chat = _to_chat(system, messages)
        enc = self.tok.apply_chat_template(
            chat, tools=_openai_tools(tools or []),
            add_generation_prompt=True, return_tensors="pt", return_dict=True)
        enc = {k: v.to(self.lm.device) for k, v in enc.items()}
        plen = enc["input_ids"].shape[1]
        # Anti-collapse decoding. Greedy decode on this base+adapter derails on some steps into
        # a runaway loop — a spurious token ("kInstruction") seeds an exact-repeat cycle that
        # fills the whole budget with one prose line (never a JSON tool_call), so the intended
        # probe (token-carry read_collection / login_test) is silently dropped. The model's
        # *reasoning* is correct; only the emission collapses. A repetition penalty plus an
        # exact-n-gram block kill the loop while staying deterministic (still greedy, do_sample
        # off) — no sampling, so findings stay reproducible and the evidence scorer still gates
        # every credit on a live response (fp unaffected). Tunable via env; defaults on because
        # the collapse is real in this environment.
        # Default OFF: global repetition/n-gram penalties act over the WHOLE sequence and
        # corrupt structured tool-call JSON (measured: devportal 3/7 -> 0/7 with nrn=6). The
        # runaway loop is a local decode collapse; the right fix is surgical (suppress the
        # loop-seeding garbage token + salvage the prose call), not a global penalty. Knobs
        # kept for experiments but off by default so behavior == the pinned greedy baseline.
        rep = float(os.environ.get("RB_REP_PENALTY", "1.0"))
        nrn = int(os.environ.get("RB_NO_REPEAT_NGRAM", "0"))
        gen_kw = dict(max_new_tokens=max_tokens or self.max_new_tokens,
                      do_sample=False, pad_token_id=self.tok.eos_token_id)
        # Opt-in sampled decoding (flywheel k-sampling). Off by default → identical greedy path.
        if self.temperature and self.temperature > 0:
            gen_kw.update(do_sample=True, temperature=self.temperature, top_p=0.95)
            if self.gen_seed is not None:
                torch.manual_seed(self.gen_seed)   # reproducible-but-varied per attempt
        if rep and rep != 1.0:
            gen_kw["repetition_penalty"] = rep
        if nrn:
            gen_kw["no_repeat_ngram_size"] = nrn
        if os.environ.get("RB_STOP_ON_CALL", "1") not in ("", "0", "false", "False"):
            gen_kw["stopping_criteria"] = StoppingCriteriaList(
                [_StopOnCallOrLoop(self.tok, plen)])
        if on_delta is not None:
            # Live token stream for signs-of-life in the UI. The streamer ONLY drives the
            # on_delta callback; the authoritative `text` is still decoded from the final
            # tensor below, so parsing / findings stay byte-identical to the non-streamed path.
            import threading
            from transformers import TextIteratorStreamer
            streamer = TextIteratorStreamer(self.tok, skip_prompt=True, skip_special_tokens=True)
            gen_kw["streamer"] = streamer
            holder: dict = {}

            def _run():
                try:
                    with torch.no_grad():
                        holder["out"] = self.lm.generate(**enc, **gen_kw)
                except BaseException as e:   # re-raised after join so the UI thread sees it
                    holder["err"] = e

            th = threading.Thread(target=_run, daemon=True)
            th.start()
            for piece in streamer:
                if piece:
                    on_delta(piece)
            th.join()
            if "err" in holder:
                raise holder["err"]
            out = holder["out"]
        else:
            with torch.no_grad():
                out = self.lm.generate(**enc, **gen_kw)
        text = self.tok.decode(out[0, plen:], skip_special_tokens=True)
        ntok = out.shape[1] - plen
        # Free the KV cache + prefill activations before the next step. Across a multi-step
        # trajectory each generate() runs a different-length prefill, so the caching allocator
        # fragments and its reserved pool grows unboundedly (measured: climbs past the 12 GB
        # card until prefill OOMs). Releasing per step keeps each step's peak ~independent.
        del out, enc
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        if os.environ.get("RB_DEBUG", "") not in ("", "0", "false", "False"):
            print("\n--- RAW GEN (%d new tok) ---\n%s\n--- /RAW ---" %
                  (ntok, text), flush=True)
        return self._parse(text)

    def _parse(self, text):
        # Accept both Qwen's <tool_call>{...}</tool_call> wrapper AND a bare function-call
        # JSON object {"name":..., "arguments":...} — the small student often drops the
        # wrapper tags, and the intent is unambiguous either way.
        spans = [(m.start(), m.end(), m.group(1)) for m in _CALL.finditer(text)]
        if not spans:
            spans = _bare_calls(text)
        blocks, calls = [], []
        cursor = 0
        for start, end, payload in spans:
            lead = text[cursor:start].strip()
            if lead:
                blocks.append({"type": "text", "text": lead})
            cursor = end
            try:
                call = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if "name" not in call:
                continue
            args = call.get("arguments", {}) or {}
            if isinstance(args, str):           # some generations stringify arguments
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            self._cid += 1
            calls.append(call)
            blocks.append({"type": "tool_use", "id": f"c{self._cid}",
                           "name": call.get("name", ""), "input": args})
        tail = text[cursor:].strip()
        if tail:
            blocks.append({"type": "text", "text": tail})
        if not calls:                                  # nothing parsed — try to salvage a
            salv = _salvage(text)                      # collapsed injection / token-carry call
            if salv:
                tool, inp, lead = salv
                self._cid += 1
                nb = []
                if lead:
                    nb.append({"type": "text", "text": lead})
                nb.append({"type": "tool_use", "id": f"c{self._cid}",
                           "name": tool, "input": inp})
                return {"content": nb, "stop_reason": "tool_use"}
        if not blocks:
            blocks = [{"type": "text", "text": text}]
        stop = "tool_use" if calls else "end_turn"
        return {"content": blocks, "stop_reason": stop}


def _bare_calls(text):
    """Find top-level JSON objects carrying a "name" key (function-call shape), returning
    (start, end, json_str) spans via a balanced-brace scan."""
    spans, i, n = [], 0, len(text)
    while i < n:
        if text[i] == "{":
            depth, j, instr, esc = 0, i, False, False
            while j < n:
                c = text[j]
                if instr:
                    if esc:
                        esc = False
                    elif c == "\\":
                        esc = True
                    elif c == '"':
                        instr = False
                elif c == '"':
                    instr = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if depth == 0 and j < n:
                blob = text[i:j + 1]
                if '"name"' in blob:
                    spans.append((i, j + 1, blob))
                i = j + 1
                continue
        i += 1
    return spans
