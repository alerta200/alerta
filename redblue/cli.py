"""cli.py — launch the agent from the command line, with the ethical gate up front.

The operator must pass --authorized to attest they have permission to test the scope.
Without it, redblue refuses to start. The scope defaults to include --target so the
common case ("assess this host I own") is one line, but can be widened explicitly.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime
import os
import re
import sys
import threading
import time

from . import __version__
from .scope import Scope
from .llm import Claude, LLMError, DEFAULT_MODEL as CLAUDE_MODEL
from .local import Ollama, LocalError, list_models as ollama_models
from .agent import SecurityAgent
from .trajectory import Trajectory
from . import findings
from . import knowledge
from . import license as _license
from . import tui
from . import tui_app

# The out-of-the-box free brain: a capable local model served by Ollama, auto-pulled on first
# use so Nexus works with zero setup. Users switch it live with /model. (Roadmap: publish the
# Nexus-tuned model to the Ollama registry and point DEFAULT_MODEL at it.)
DEFAULT_MODEL = "qwen2.5:7b"

# When the user types something that isn't a target or a command, Nexus answers it like a
# normal AI assistant (with a security bent) instead of rejecting it — so it's a chat agent
# that ALSO runs assessments, not a single-purpose tool.
CHAT_SYSTEM = (
    "You are Nexus — an open-source autonomous security-assessment agent and a senior security "
    "engineer. You are fluent in programming: you read and write code, and you understand "
    "vulnerabilities at the source-code level — how SQL injection, XSS, authentication bypass, "
    "path traversal, SSRF, insecure deserialization, and similar flaws actually arise in code, "
    "and how to fix them. You reason like an attacker and report like a defender. You drive real "
    "tools behind an evidence gate so findings are never fabricated — and you understand exactly "
    "what those tools do under the hood and why. When asked about your abilities, answer "
    "accurately and with confidence: you know programming and security engineering deeply; you "
    "do NOT merely run canned tools without understanding them, and you never claim to lack that "
    "knowledge. You have no company and no backstory; you are simply the Nexus project. You "
    "cannot scan or browse by yourself — to test a system, the user gives a host or URL (e.g. "
    "example.com) and Nexus scans it for real. Answer briefly, and only in the user's own "
    "language. Never invent findings, results, URLs, companies, or credentials, and never claim "
    "to have scanned something you did not."
)


# glyph + colour per event kind — a calmer, scannable vocabulary than [tool]/[<-] labels.
_EVENT_GLYPH = {
    "text":   ("96", "»"),   # the model's reasoning, spoken aloud
    "tool":   ("93", "→"),   # a tool call going out
    "result": ("90", "←"),   # its result coming back
    "nudge":  ("90", "·"),   # a harness nudge (dim, low-signal)
    "done":   ("92", "✓"),
}


def _print_event(kind: str, text: str):
    if kind == "step":
        print(_c("90", f"  ┄┄ {text} " + "┄" * max(2, 46 - len(text))))
        return
    colour, glyph = _EVENT_GLYPH.get(kind, ("97", "•"))
    if kind == "result":
        clipped = text if len(text) <= 240 else text[:240] + "…"
        print(_c("90", f"  {glyph} {clipped}"))
    elif kind == "tool":
        print(f"  {_c(colour, glyph)} {_c('1', text)}")   # tool call stands out (bold)
    elif kind == "text":
        print(f"  {_c(colour, glyph)} {_c('96', text)}")
    else:
        print(f"  {_c(colour, glyph)} {_c('90', text)}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nexus",
        description="Nexus — autonomous red+blue security assessment. Authorized scope only.",
        epilog="subcommands:  nexus learn [topic]   browse the offline security knowledge base"
               "\n              nexus license [status|add <token>]   commercial-use licence"
               "\n              nexus ask <report.json> \"<question>\"   interrogate a saved report"
               "\n              nexus fixes <report.json>   prioritised remediation plan + fixes"
               "\n              nexus retest <old.json> <new.json>   diff two assessments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"nexus {__version__}",
                   help="print the Nexus version and exit.")
    p.add_argument("--target", default=None,
                   help="primary target (host or URL) to assess. "
                        "Omit to launch the interactive wizard.")
    p.add_argument("--scope", action="append", default=[],
                   help="additional in-scope entry (host, IP, or CIDR); repeatable. "
                        "--target is always included.")
    p.add_argument("--objective",
                   help="what to assess (default: a general security assessment)")
    p.add_argument("--max-steps", type=int, default=40)
    p.add_argument("--brain", default="claude", choices=["claude", "ollama", "local"],
                   help="which brain drives the agent: claude (API key), ollama (local server), "
                        "or local (the trained Nexus student, offline — needs nexus-sec[local])")
    p.add_argument("--model",
                   help="model name (default: claude-opus-5 for claude, qwen2.5:7b for ollama)")
    p.add_argument("--ollama-url", default="http://127.0.0.1:11434",
                   help="Ollama server URL (for --brain ollama)")
    p.add_argument("--base", default="Qwen/Qwen2.5-Coder-1.5B-Instruct",
                   help="base HF model for --brain local")
    p.add_argument("--adapter", default=None,
                   help="LoRA adapter (local path or HF repo id) for --brain local — "
                        "the trained Nexus student. Omit to run the untuned base.")
    p.add_argument("--effort", default="xhigh",
                   choices=["high", "xhigh", "max"],
                   help="reasoning effort (claude only; xhigh recommended for agentic work)")
    p.add_argument("--format", default="md", choices=["md", "sarif", "json", "html"],
                   help="report format: md (human report, default), sarif (SARIF 2.1.0 for "
                        "GitHub code-scanning / CI), json (structured findings), or html "
                        "(client-ready deliverable: executive summary, CVSS, attack paths — "
                        "print to PDF from a browser). The output file extension follows the format.")
    p.add_argument("--report", metavar="PATH",
                   help="write the final report to a markdown file")
    p.add_argument("--client", metavar="NAME",
                   help="client/organisation name to brand the html deliverable (\"Prepared for\")")
    p.add_argument("--vendor", metavar="NAME",
                   help="your company name for the html deliverable header (defaults to a neutral title)")
    p.add_argument("--trust-model-report", action="store_true",
                   help="emit the model's own prose as the authoritative report. Off by "
                        "default: the report is derived from EVIDENCE (real tool results), so "
                        "no finding is credited unless the live target confirmed it — this is "
                        "what makes Nexus reports free of fabricated findings.")
    p.add_argument("--explain", action="store_true",
                   help="append a senior-level 'Understanding the findings' section to the md "
                        "report — code-level root cause + fix for each confirmed class, grounded "
                        "in the curated knowledge base (deterministic, not model prose).")
    p.add_argument("--no-floor", action="store_true",
                   help="disable the methodology floor — the deterministic recon + injection + "
                        "access sweep the harness runs at the end of a scan to guarantee every "
                        "checkable finding class regardless of the model. The floor is ON by "
                        "default; pass this to measure the model's UNAIDED detection, or for a "
                        "light-touch scan without the floor's extra requests.")
    p.add_argument("--record", metavar="PATH",
                   help="append the full run trajectory to a JSONL dataset (for training)")
    p.add_argument("--authorized", action="store_true",
                   help="REQUIRED: attests you are authorized to test the scope")
    p.add_argument("--rules-accepted", action="store_true",
                   help="REQUIRED for external (public-internet) targets: attests that active/"
                        "automated testing is permitted by the target's program rules (e.g. a "
                        "bug-bounty or VDP policy) and that your scope and request rate comply "
                        "with them. Lab/loopback targets don't need it.")
    p.add_argument("--rate-limit", type=float, default=None, metavar="SEC",
                   help="minimum seconds between outbound requests (politeness throttle). "
                        "Defaults to 0 for loopback/lab targets and 1.0 for external targets "
                        "so a live program is never hammered; raise it to match a stricter "
                        "program rule.")
    p.add_argument("--allow-dangerous", action="store_true",
                   help="disable the built-in denylist and permit internal ranges "
                        "(cloud metadata, loopback, RFC1918). Only for assessing your own "
                        "internal infrastructure you have explicit authorization for.")

    # ---- defender (blue-team): attach to systems you own and defend them from the inside ----
    d = p.add_argument_group(
        "defender (blue-team — read-only posture of systems you OWN; proposals only, never applied)")
    d.add_argument("--defend", action="store_true",
                   help="one-shot: read-only posture of THIS host (network-exposed services, "
                        "Defender/firewall state, hijackable service paths) + an AI triage brief "
                        "+ fix PROPOSALS. Nothing is changed. Requires --authorized.")
    d.add_argument("--guard", action="store_true",
                   help="continuous guardian: cheap deterministic host sweeps on a timer; the AI "
                        "brain engages ONLY when a NEW hole appears. Use with --interval.")
    d.add_argument("--estate", nargs="?", const="", default=None, metavar="CONFIG",
                   help="defend a whole estate: patrol every asset in the CONFIG JSON (hosts + web "
                        "services) and roll up what changed. --estate with no file = just this host.")
    d.add_argument("--interval", type=float, default=0.0,
                   help="with --guard/--estate: seconds between patrols (0 = one pass and exit).")
    d.add_argument("--include-secrets", action="store_true",
                   help="the host sweep also checks for credential files in your user profile "
                        "(opt-in; sensitive).")
    d.add_argument("--state", default=None, metavar="PATH",
                   help="defender state file (finding history across sweeps). "
                        "Default: alongside your nexus config (~/.nexus/sentinel_state.json).")
    return p


def _target_is_external(target: str) -> bool:
    """True if the target resolves to (or is) a public-internet address.

    Loopback/private/reserved addresses are 'lab/internal' and skip the external preflight;
    anything globally routable is a real third party and must clear the program-rules gate.
    Resolution failure is treated as external (fail-safe: gate rather than wave through).
    """
    import ipaddress
    import socket
    from urllib.parse import urlparse

    import threading

    host = urlparse(target if "://" in target else "//" + target).hostname or target
    try:
        return ipaddress.ip_address(host).is_global   # IP literal: no DNS, instant
    except ValueError:
        pass

    # Hostname → DNS. This is called on the UI thread when a target is entered, so bound it
    # with a timeout: a slow/dead resolver must never freeze the app. On timeout or failure we
    # treat the target as external (fail-safe: gate rather than wave a third party through).
    result = {}

    def _resolve():
        try:
            for _f, _t, _p, _c, sa in socket.getaddrinfo(host, None):
                try:
                    if ipaddress.ip_address(sa[0]).is_global:
                        result["v"] = True
                        return
                except ValueError:
                    continue
            result["v"] = False
        except (socket.gaierror, OSError):
            result["v"] = True

    t = threading.Thread(target=_resolve, daemon=True)
    t.start()
    t.join(2.0)
    return result.get("v", True)   # not resolved in time → external (fail-safe)


_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9_-]+\.)*[a-zA-Z0-9_-]+$")


def _valid_target(s: str) -> bool:
    """Does `s` look like a host / IP / host:port / URL we could actually assess?

    Rejects free-text ('привет', 'hello there') AND bare single words ('hi', 'test') — a real
    hostname target is an IP, localhost, an FQDN (has a dot), or came with an explicit port or
    scheme. A lone word is almost always a typo, and letting it through mislabels it a
    'public-internet target'."""
    import ipaddress
    from urllib.parse import urlparse
    p = urlparse(s if "://" in s else "//" + s)
    host = (p.hostname or "").strip()
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if host == "localhost":
        return True
    if not _HOSTNAME_RE.match(host):
        return False
    try:
        has_port = p.port is not None
    except ValueError:
        has_port = False
    return "." in host or bool(p.scheme) or has_port


_CJK_RE = re.compile(r"[㐀-鿿぀-ヿ＀-￯　-〿]")


def _strip_cjk_drift(text: str) -> str:
    """Qwen/DeepSeek-family models sprinkle Chinese into a Russian/English reply. REMOVE the CJK
    inline (keeping the surrounding sentence) rather than truncating at it — truncating cut
    answers off mid-sentence. If the reply is genuinely CJK from the start (the user wrote CJK),
    leave it alone."""
    m = _CJK_RE.search(text)
    if not m or m.start() < 12:
        return text
    cleaned = _CJK_RE.sub("", text)
    return re.sub(r"[ \t]{2,}", " ", cleaned).strip()


# Words that mean "check/scan/test a system" — if the user says one but names no target, we give
# a DETERMINISTIC, correct hand-off (type the URL → real scan) instead of trusting the weak chat
# model, which invents a bogus questionnaire and falsely promises to check.
_SCAN_INTENT_RE = re.compile(
    r"(?i)(scan|pentest|провер|скан|сканир|пентест|взлом|проникновени"
    r"|check\s+\S*\s*(site|url|host|website|server|system)"
    r"|test\s+\S*\s*(site|url|host|website|server|system))")


def _scan_handoff(text: str) -> str | None:
    """A fixed, honest reply when the user asks to check a system but gave no target."""
    if not _SCAN_INTENT_RE.search(text):
        return None
    if re.search(r"[а-яА-ЯёЁ]", text):
        return ("Чтобы я проверил систему, просто введите её адрес — например example.com "
                "или https://вашсайт.ру — и я запущу НАСТОЯЩИЙ скан с доказательствами "
                "(каждая находка подтверждается реальным ответом сервера). Сам из чата я ничего "
                "не проверяю и не выдумываю.")
    return ("To check a system, just type its URL or host — e.g. example.com or "
            "https://yoursite.com — and I'll run a REAL, evidence-backed scan (every finding "
            "proven by the target's own response). I never check anything, or make it up, from "
            "chat alone.")


# Suffixes that look like a dotted host's last label but are NOT top-level domains — common
# code/file/library tokens ("Node.js", "README.md", "index.html", "app.json"). Auto-extraction
# from natural language must not mistake these for a scan target and misroute a chat message into
# a scan. Deliberately excludes real ccTLDs that double as extensions (py=Paraguay, sh, rs, io,
# co, pl, in…): those stay scannable, and an explicit http:// / port always forces a scan anyway.
_NON_TLD_SUFFIXES = frozenset((
    "js", "ts", "jsx", "tsx", "mjs", "cjs", "md", "html", "htm", "css", "scss", "sass",
    "json", "xml", "yml", "yaml", "toml", "ini", "cfg", "lock", "sum", "txt", "csv", "log",
    "cpp", "hpp", "cc", "hh", "cs", "kt", "kts", "java", "swift", "dart", "scala", "vue",
    "png", "jpg", "jpeg", "gif", "svg", "webp", "pdf", "doc", "docx", "xls", "xlsx", "ppt",
    "pptx", "ipynb", "env", "gitignore", "dockerfile",
    # These ARE real ccTLDs, but in chat they read overwhelmingly as source files (main.py,
    # build.sh, lib.rs). Auto-extraction skips them; a genuine domain in one of these zones is
    # still scannable by typing an explicit scheme (http://acme.py) or a port.
    "py", "sh", "rs", "pl", "go", "rb", "lua",
))


def _extract_target(text: str):
    """Pull a real host / IP / URL out of a natural-language message, so 'check example.com
    for XSS' runs an actual scan instead of letting the chat model make up an answer. Returns
    the target string, or None if the message names no system to check."""
    for raw in text.split():
        tok = raw.strip(".,;:!?()[]{}<>\"'`«»").rstrip("/")
        if not tok or not _valid_target(tok):
            continue
        # Guard against abbreviations ("e.g.", "i.e.") slipping through as domains: a plain
        # dotted host must end in a 2+ letter label. IPs, ports, and URLs are always solid.
        if "://" in tok:
            return tok
        try:
            import ipaddress
            from urllib.parse import urlparse
            host = urlparse("//" + tok).hostname or tok
            ipaddress.ip_address(host)
            return tok
        except ValueError:
            pass
        if ":" in tok:                      # host:port
            return tok
        # Decide on the HOST's TLD, not the raw token: "example.com/index.php" is a real target
        # (host example.com) even though the token ends in ".php", while "Node.js" is not.
        host = urlparse("//" + tok).hostname or tok
        if "." in host:
            suffix = host.rsplit(".", 1)[-1]
            if (suffix.isalpha() and len(suffix) >= 2
                    and suffix.lower() not in _NON_TLD_SUFFIXES):
                return tok
    return None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m"


def _banner() -> str:
    # red+blue duality baked into the wordmark: NE red · X magenta seam · US blue → NE·X·US
    wm = (_c("1;91", "NE") + _c("95", "·") + _c("1;95", "X") + _c("95", "·") + _c("1;94", "US"))
    line = _c("90", "─" * 46)
    return (
        f"\n  {line}\n"
        f"   {wm}   {_c('90', 'autonomous red + blue security assessment')}\n"
        f"  {line}\n"
    )


def _ask(label: str, default: str | None = None) -> str:
    suffix = _c("90", f" [{default}]") if default else ""
    try:
        v = input(f"  {_c('96', '›')} {label}{suffix}: ").strip()
    except EOFError:
        return ""
    return v or (default or "")


def _yesno(label: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    try:
        v = input(f"  {_c('93', '?')} {label} {_c('90', '[' + d + ']')}: ").strip().lower()
    except EOFError:
        return default
    if not v:
        return default
    return v in ("y", "yes")


def _config_file():
    from pathlib import Path
    return Path.home() / ".nexus" / "config.json"


def _load_config() -> dict:
    import json
    try:
        return json.loads(_config_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_config(cfg: dict) -> bool:
    import json
    try:
        p = _config_file()
        # This file holds the Anthropic API key. Lock it down to the owner (0700 dir / 0600
        # file) so a shared or air-gapped box doesn't leak the key to other local users.
        # No-op on Windows ACLs, meaningful on POSIX.
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(p.parent, 0o700)
        except OSError:
            pass
        data = json.dumps(cfg, indent=2)
        # Create with 0600 from the start (os.open honors the mode on first create) so the key
        # is never briefly world-readable between write and chmod.
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(data)
        finally:
            try:
                os.chmod(p, 0o600)  # tighten if the file pre-existed with looser perms
            except OSError:
                pass
        return True
    except OSError:
        return False


def _ollama_up(url: str = "http://127.0.0.1:11434") -> bool:
    import socket
    from urllib.parse import urlparse
    u = urlparse(url)
    try:
        s = socket.create_connection((u.hostname or "127.0.0.1", u.port or 11434), timeout=0.5)
        s.close()
        return True
    except OSError:
        return False


def _ensure_claude_key() -> bool:
    """Prompt for an Anthropic key, use it now, and remember it. Returns True if we have one."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True
    import getpass
    print(_c("90", "  Get a key at https://console.anthropic.com/settings/keys"))
    try:
        key = getpass.getpass(f"  {_c('96', '›')} Paste your Anthropic API key "
                              f"{_c('90', '(hidden — Enter to skip)')}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return False
    if not key:
        return False
    os.environ["ANTHROPIC_API_KEY"] = key
    cfg = _load_config()
    cfg["anthropic_api_key"] = key
    saved = _save_config(cfg)
    where = "saved to ~/.nexus/config.json" if saved else "kept for this session"
    print(_c("92", f"  ✓ key {where}"))
    return True


def _interactive(args) -> bool:
    """Guided setup when nexus is launched with no --target. Returns False if aborted."""
    print(_banner())

    target = _ask("Target host or URL")
    if not target:
        print(_c("91", "\n  No target given — nothing to do.\n"))
        return False
    args.target = target

    # Pick a brain the machine can actually run: detect a saved key and a live Ollama,
    # default to whatever is ready, and handle the API key inline instead of crashing.
    have_key = bool(os.environ.get("ANTHROPIC_API_KEY"))
    have_ollama = _ollama_up(args.ollama_url)
    default_brain = "claude" if have_key else ("ollama" if have_ollama else "claude")
    ck = _c("92", "✓") if have_key else _c("90", "needs key")
    ok_ = _c("92", "✓ running") if have_ollama else _c("90", "not detected")
    print(_c("90", f"  brains:  claude {ck}   ·   ollama {ok_}   ·   local (offline)"))
    brain = _ask("Brain — claude / ollama / local", default=default_brain).lower()
    args.brain = brain if brain in ("claude", "ollama", "local") else default_brain

    if args.brain == "claude" and not _ensure_claude_key():
        if have_ollama and _yesno("No key given — use the local Ollama server instead?", True):
            args.brain = "ollama"
        else:
            print(_c("91", "\n  A brain is required to run — aborting.\n"))
            return False

    # sensible defaults so the common case is just three answers; power users use flags
    if not args.report:
        args.report = "nexus-report.md"

    print("\n  " + _c("93", "Authorization"))
    print(_c("90", "  Nexus only tests systems you own or are explicitly authorized to test."))
    if not _yesno("I am authorized to test this scope"):
        print(_c("91", "\n  Not authorized — aborting. (Required to proceed.)\n"))
        return False
    args.authorized = True

    if _target_is_external(args.target):
        print("\n  " + _c("93", f"{args.target} looks like a public-internet target."))
        print(_c("90", "  Confirm automated testing is permitted by its program rules "
                        "(bug-bounty / VDP / written scope)."))
        if not _yesno("Automated testing is permitted by the program's rules"):
            print(_c("91", "\n  Program rules not confirmed — aborting.\n"))
            return False
        args.rules_accepted = True

    print()
    return True


# Clean multilingual chat models, in order of preference — used for the assistant/chat side
# only (the scan side keeps whatever drives tools best). Matched by family prefix.
_CHAT_MODEL_FAMILIES = ("llama3.1", "llama3.2", "llama3.3", "gemma2", "mistral-nemo",
                        "mistral", "phi3", "llama3")


def _preferred_chat_model(ollama_url: str, fallback: str) -> str:
    """Pick a clean chat model from what's installed, else keep the current (scan) model."""
    installed = ollama_models(ollama_url)
    for fam in _CHAT_MODEL_FAMILIES:
        for m in installed:
            if m.startswith(fam):
                return m
    return fallback


def _target_reachable(target: str, timeout: float = 4.0) -> bool:
    """Quick TCP reachability check. Scanning a DOWN host burns steps and then reports 'no
    findings' — which reads as 'secure'. Better to tell the user the target didn't respond."""
    import socket
    from urllib.parse import urlparse
    u = urlparse(target if "://" in target else "//" + target)
    host = u.hostname
    if not host:
        return False
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        port = 80
    try:
        socket.create_connection((host, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def _report_name(target) -> str:
    """A unique, findable report path per scan — so running several never overwrites the last."""
    safe = re.sub(r"[^A-Za-z0-9.\-]+", "_", str(target))[:40].strip("_") or "target"
    return os.path.join("nexus-reports",
                        f"nexus-{safe}-{datetime.datetime.now():%Y%m%d-%H%M%S}.md")


def _with_ext(path: str, ext: str) -> str:
    """Swap the file extension (nexus-report.md -> nexus-report.sarif) so the on-disk name
    matches --format. Leaves the directory and stem intact."""
    root, _old = os.path.splitext(path)
    return root + ext


def _write_raw(path: str, content: str) -> None:
    """Write a machine-readable artifact (SARIF/JSON) verbatim — no markdown wrapper."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def write_report(path: str, scope, objective: str, final: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    when = datetime.datetime.now().isoformat(timespec="seconds")
    doc = (
        f"# Nexus security assessment\n\n"
        f"- **Date:** {when}\n"
        f"- **Scope:** {', '.join(scope.raw)}\n"
        f"- **Objective:** {objective}\n\n"
        f"---\n\n{final}\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)


def _cmd_license(rest) -> int:
    """`nexus license` (status) · `nexus license add <token>` · `nexus license status`."""
    sub = rest[0].lower() if rest else "status"
    if sub in ("add", "activate", "install"):
        token = rest[1].strip() if len(rest) > 1 else ""
        if not token:
            try:
                token = input(f"  {_c('96', '›')} Paste your Nexus licence token: ").strip()
            except (EOFError, KeyboardInterrupt):
                token = ""
        if not token:
            print(_c("90", "  cancelled — no token entered."))
            return 1
        ok, msg = _license.save_license(token)
        print(_c("92", "  ✓ " + msg) if ok else _c("91", "  " + msg))
        return 0 if ok else 1
    if sub in ("status", "show", "info", ""):
        print("  " + _c("1", _license.status_line()))
        lic = _license.load_license()
        if lic is None:
            print(_c("90", "  add one with:  nexus license add <token>"))
        return 0
    print(_c("91", f"  unknown: nexus license {sub}") + _c("90", " — try status | add <token>"))
    return 2


def _cmd_model_pack(rest) -> int:
    """`nexus model install <pack>` · `nexus model status`. Installs the sealed tuned defender
    adapter using the content key carried in the activated licence (the honour-based distribution
    gate — see nxpack.py / model_store.py). No licence key → clear guidance, never a crash."""
    from . import model_store
    sub = rest[0].lower() if rest else "status"
    if sub in ("status", "show", "info", ""):
        p = model_store.installed_adapter()
        if p:
            print("  " + _c("92", "✓ tuned defender model installed") + _c("90", f"  ({p})"))
        else:
            print("  " + _c("90", "no tuned defender model installed — "
                                  "buy Pro, then:  nexus model install <pack>"))
        return 0
    if sub in ("install", "add", "unpack"):
        pack = rest[1].strip() if len(rest) > 1 else ""
        if not pack:
            print(_c("91", "  usage: nexus model install <pack.nxpack>"))
            return 2
        lic = _license.load_license()
        if lic is None or not lic.valid:
            print(_c("91", "  no valid licence — activate first:  nexus license add <token>"))
            return 1
        if not lic.model_key:
            print(_c("91", "  your licence carries no model key.") +
                  _c("90", " The tuned defender ships with Pro/Enterprise; contact the vendor."))
            return 1
        try:
            dest = model_store.install(pack, lic.model_key)
        except (ValueError, OSError) as e:
            print(_c("91", f"  install failed: {e}"))
            return 1
        print("  " + _c("92", "✓ tuned defender model installed") + _c("90", f"  → {dest}"))
        print(_c("90", "  it now loads automatically under:  nexus --defend --brain local"))
        return 0
    print(_c("91", f"  unknown: nexus model {sub}") + _c("90", " — try status | install <pack>"))
    return 2


def _cmd_learn(rest) -> int:
    """`nexus learn` (list topics) · `nexus learn <topic|query>` (show the curated reference).

    Surfaces the same offline knowledge base that grounds the chat and the --explain report, so a
    user can study a class directly. Accepts an exact topic id or a free-text query (fuzzy match)."""
    query = " ".join(rest).strip()
    if not query:
        print("  " + _c("1", "Nexus knowledge base") + _c("90", f"  ({len(knowledge.topics())} topics)"))
        print(_c("90", "  study one with:  nexus learn <topic>   e.g. nexus learn sqli\n"))
        for t in knowledge.topics():
            print(f"  {_c('96', t['id']):<28} {_c('90', t['title'])}")
        return 0
    topic = knowledge.by_id(query.lower())
    if topic is None:
        hits = knowledge.match(query, limit=1)
        topic = hits[0] if hits else None
    if topic is None:
        print(_c("91", f"  no topic matches {query!r}") + _c("90", "  — try:  nexus learn"))
        return 1
    import textwrap
    print("  " + _c("1", topic["title"]) + _c("90", f"   [{topic['id']}]") + "\n")
    print(textwrap.fill(topic["text"], width=94, initial_indent="  ", subsequent_indent="  "))
    return 0


def _cmd_retest(rest) -> int:
    """`nexus retest <old.json> <new.json>` — diff two assessments and report what changed.

    Offline retest phase: feed two `nexus --format json` artefacts (a prior run and the current
    one); prints/writes fixed / still-open / new. `--format html` renders a branded, printable
    retest document (like the deliverable). Nothing is inferred — findings match by class+location."""
    p = argparse.ArgumentParser(prog="nexus retest", add_help=True,
                                description="Compare two Nexus JSON reports (fixed / still-open / new).")
    p.add_argument("old", help="previous assessment  (a nexus --format json file)")
    p.add_argument("new", help="current assessment   (a nexus --format json file)")
    p.add_argument("--format", default="md", choices=["md", "html"])
    p.add_argument("--report", metavar="PATH", help="write to a file (extension follows --format)")
    p.add_argument("--client", metavar="NAME", help="brand the html retest (\"Prepared for\")")
    p.add_argument("--vendor", metavar="NAME", help="your company name for the html header")
    try:
        a = p.parse_args(rest)
    except SystemExit as e:               # argparse prints usage/errors itself
        return int(e.code or 0)
    from . import retest
    try:
        old, t_old = retest.load_findings(a.old)
        new, t_new = retest.load_findings(a.new)
    except (OSError, ValueError) as e:    # ValueError covers JSONDecodeError
        print(_c("91", f"  could not read reports: {e}"), file=sys.stderr)
        print(_c("90", "  both files must be `nexus --format json` output."), file=sys.stderr)
        return 1
    target = t_new or t_old or "target"
    d = retest.diff(old, new)
    if a.format == "html":
        out = retest.to_html(target, d, meta={"client": a.client, "vendor": a.vendor},
                             version=__version__)
        path = _with_ext(a.report, ".html") if a.report else "nexus-retest.html"
        try:
            _write_raw(path, out)
        except OSError as e:
            print(_c("91", f"  could not write {path}: {e}"), file=sys.stderr)
            return 1
        print(_c("92", f"  ✓ retest report written to {path}"))
    else:
        out = retest.to_markdown(target, d)
        if a.report:
            try:
                _write_raw(a.report, out)
            except OSError as e:
                print(_c("91", f"  could not write {a.report}: {e}"), file=sys.stderr)
                return 1
            print(_c("92", f"  ✓ retest report written to {a.report}"))
        else:
            print(out)
    return 0


def _cmd_fixes(rest) -> int:
    """`nexus fixes <report.json>` — a prioritised remediation plan + copy-paste fixes derived from
    a saved `nexus --format json` assessment. Prints markdown (paste into a ticket / PR) or writes
    it with `--report`. Deterministic; the full HTML client report (`--format html`) also carries
    this plan."""
    p = argparse.ArgumentParser(prog="nexus fixes", add_help=True,
                                description="Remediation plan + fixes from a Nexus JSON report.")
    p.add_argument("report", help="a nexus --format json assessment file")
    p.add_argument("--report", metavar="PATH", dest="out",
                   help="write the fix-pack to a markdown file instead of printing it")
    try:
        a = p.parse_args(rest)
    except SystemExit as e:
        return int(e.code or 0)
    from . import retest, deliverable, fixpack
    try:
        raw, target = retest.load_findings(a.report)
    except (OSError, ValueError) as e:
        print(_c("91", f"  could not read {a.report}: {e}"), file=sys.stderr)
        print(_c("90", "  it must be `nexus --format json` output."), file=sys.stderr)
        return 1
    md = fixpack.to_markdown(target or "target", deliverable.enrich(raw))
    if a.out:
        try:
            _write_raw(a.out, md)
        except OSError as e:
            print(_c("91", f"  could not write {a.out}: {e}"), file=sys.stderr)
            return 1
        print(_c("92", f"  ✓ remediation plan written to {a.out}"))
    else:
        print(md)
    return 0


def _cmd_ask(rest) -> int:
    """`nexus ask <report.json> <question>` — interrogate a saved assessment in plain language.
    Answers DETERMINISTICALLY and only from the evidence-gated findings (reusing the CVSS /
    attack-path / compliance / fix projections), so a co-pilot answer can never invent a finding
    the target didn't confirm. Offline; no model needed. Ask about an absent class and it says so."""
    p = argparse.ArgumentParser(prog="nexus ask", add_help=True,
                                description="Ask about a saved Nexus JSON assessment, grounded in "
                                            "its evidence-gated findings.")
    p.add_argument("report", help="a nexus --format json assessment file")
    p.add_argument("question", nargs="*",
                   help='your question, e.g. "what do I fix first?" or "explain the sqli"')
    p.add_argument("--report", metavar="PATH", dest="out",
                   help="write the answer to a file instead of printing it")
    try:
        a = p.parse_args(rest)
    except SystemExit as e:
        return int(e.code or 0)
    from . import retest, deliverable, copilot
    try:
        raw, target = retest.load_findings(a.report)
    except (OSError, ValueError) as e:
        print(_c("91", f"  could not read {a.report}: {e}"), file=sys.stderr)
        print(_c("90", "  it must be `nexus --format json` output."), file=sys.stderr)
        return 1
    enriched = deliverable.enrich(raw)
    question = " ".join(a.question).strip()
    if not question:
        print(copilot.menu())
        return 0
    ans = copilot.answer(question, target or "target", enriched)
    if ans is None:
        print(_c("90", f"  I can't map that to the findings.\n\n{copilot.menu()}"))
        return 0
    if a.out:
        try:
            _write_raw(a.out, ans + "\n")
        except OSError as e:
            print(_c("91", f"  could not write {a.out}: {e}"), file=sys.stderr)
            return 1
        print(_c("92", f"  ✓ answer written to {a.out}"))
    else:
        print(ans)
    return 0


def _main(argv=None) -> int:
    # Windows consoles default to a legacy codepage (cp1251 on RU installs) that can't encode
    # the box-drawing / ✓✗ characters in the banner and reports → UnicodeEncodeError mid-run.
    # Force UTF-8 so nexus behaves the same in cmd, PowerShell, and piped output.
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:  # noqa: BLE001 — best-effort; reconfigure below is the main guard
            pass
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    # `nexus license [status|add <token>]` — a tiny subcommand handled before argparse so the
    # UX matches the docs (not a --flag). Returns without touching the assessment path.
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "license":
        return _cmd_license(argv[1:])
    # `nexus learn [topic|query]` — browse the offline knowledge base directly.
    if argv and argv[0] == "learn":
        return _cmd_learn(argv[1:])
    # `nexus model [status|install <pack>]` — install the sealed tuned defender adapter.
    if argv and argv[0] == "model":
        return _cmd_model_pack(argv[1:])
    # `nexus retest <old.json> <new.json>` — diff two assessments (fixed / still-open / new).
    if argv and argv[0] == "retest":
        return _cmd_retest(argv[1:])
    # `nexus fixes <report.json>` — a remediation plan + copy-paste fixes from a saved report.
    if argv and argv[0] == "fixes":
        return _cmd_fixes(argv[1:])
    # `nexus ask <report.json> "<q>"` — interrogate a saved assessment (evidence-grounded co-pilot).
    if argv and argv[0] == "ask":
        return _cmd_ask(argv[1:])

    # Load a remembered API key so both the wizard and the flag path (nexus --brain claude)
    # just work after the first time it was entered.
    _cfg = _load_config()
    if _cfg.get("anthropic_api_key") and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = _cfg["anthropic_api_key"]

    parser = build_parser()
    args = parser.parse_args(argv)

    # Honour-based licence notice at point of use: the tuned local defender model is a Pro/
    # Enterprise feature. We state the position (never block — see license.py ethos); the real
    # gate is that the tuned weights ship only to licensees.
    if getattr(args, "brain", None) == "local":
        _note = _license.defender_notice()
        if _note:
            print(_c("93", "  " + _note), file=sys.stderr)

    # Defender modes (blue-team) turn Nexus from attacker to defender: attach to a host/estate
    # you own and report its posture read-only. Dispatched before the target/REPL branch so
    # `nexus --defend` (which has no --target) reaches the defender, not the assess wizard.
    if args.defend or args.guard or args.estate is not None:
        return _run_defender(args)

    # No target on the command line → run the interactive wizard (a real CLI, not an
    # argparse error wall). If we're not attached to a terminal (piped/scripted), show help.
    if args.target is None:
        if sys.stdin.isatty() and sys.stdout.isatty():
            return _repl(args)
        parser.print_help()
        return 2

    if not args.authorized:
        print(_c("91", "REFUSED: Nexus only tests systems you are authorized to test."),
              file=sys.stderr)
        print(_c("90", "  re-run with --authorized to attest you have permission for the scope."),
              file=sys.stderr)
        return 2
    model = args.model or (DEFAULT_MODEL if args.brain == "ollama"
                           else CLAUDE_MODEL if args.brain == "claude" else None)
    return _assess(
        args.target, args.scope, brain=args.brain, model=model, ollama_url=args.ollama_url,
        base=args.base, adapter=args.adapter, effort=args.effort, objective=args.objective,
        report=args.report, max_steps=args.max_steps, allow_dangerous=args.allow_dangerous,
        rules_accepted=args.rules_accepted, rate_limit=args.rate_limit, record=args.record,
        trust_model_report=args.trust_model_report, report_format=args.format,
        explain=args.explain, methodology_floor=not args.no_floor,
        client=args.client, vendor=args.vendor)


def _build_brain(brain, model, ollama_url, base, adapter, effort):
    """Construct a brain. Returns (llm, None) on success or (None, error_string)."""
    try:
        if brain == "local":
            try:
                from .hf_local import HFBrain
            except ImportError as e:
                return None, f"--brain local needs the ML extras: pip install nexus-sec[local] ({e})"
            if not adapter:
                # No adapter given → fall back to the installed tuned defender if the licensee
                # ran `nexus model install`. This is how a Pro customer's --defend picks up the
                # sealed weights automatically.
                from . import model_store
                adapter = model_store.installed_adapter()
            try:
                return HFBrain(base=base, adapter=adapter), None
            except Exception as e:  # noqa: BLE001 — model/adapter load, CUDA OOM, ...
                return None, f"could not load local brain: {e}"
        if brain == "ollama":
            if not _ensure_ollama_server(ollama_url):
                return None, "could not reach or start the Ollama server."
            installed = ollama_models(ollama_url)
            if installed and model not in installed:
                return None, (f"Ollama has no model {model!r}. "
                              f"installed: {', '.join(installed) or '(none)'}. "
                              f"pull it with: ollama pull {model}")
            return Ollama(model=model, url=ollama_url), None
        return Claude(model=model or CLAUDE_MODEL, effort=effort), None
    except (LLMError, LocalError) as e:
        return None, str(e)


# ------------------------------------------------------------------ defender (blue-team) surface
# Nexus's red side finds holes; the defender attaches to a system you OWN and reports its live,
# evidence-gated posture. Everything here is read-only introspection and PROPOSALS — no product
# path ever changes the system (applying a fix stays the separate, confirm-first
# `python -m redblue.blue --apply <finding> --yes`). These thin wrappers reuse the existing
# engine (redblue.host / sentinel / estate / blue / remediate) so both the one-shot flags and the
# interactive console share one implementation.

def _resolve_model(brain, model):
    return model or (DEFAULT_MODEL if brain == "ollama"
                     else CLAUDE_MODEL if brain == "claude" else None)


def _defender_state_path(args) -> str:
    """Where the patrol history lives. Default is stable per-user (next to the nexus config) so
    the new/still-open/fixed diff persists regardless of the working directory."""
    if getattr(args, "state", None):
        return args.state
    return str(_config_file().parent / "sentinel_state.json")


class _NoBrain:
    """Guardian stand-in when no real model is configured: the deterministic patrol + diff (the
    evidence-gated backbone) still run; a 'brief' just says how to turn on AI triage."""

    def complete(self, system, messages, tools=None, **_k):
        return {"content": [{"type": "text", "text":
                "(no AI brain configured — deterministic posture only; add --brain "
                "claude|ollama|local for a triage brief on what changed)"}],
                "stop_reason": "end_turn"}


def _defender_blocks(brain, state_path, include_secrets, *, mode="defend", config="") -> list:
    """One read-only defender pass, rendered as titled text blocks [(title, body), …] so BOTH the
    console (printed) and the full-screen app (panels) share one implementation and one engine.

    mode="defend": full host posture + optional AI brief + all fix proposals.
    mode="guard":  same sweep, but the AI focuses only on what is NEW since the last patrol.
    mode="estate": roll up every asset in `config` (or just this host when config is "").
    `brain` may be None → posture + proposals only, no brief. Nothing is ever changed."""
    import socket
    from . import host as host_mod, remediate, blue, estate as estate_mod
    from .sentinel import patrol_once, _fmt_posture
    from .scope import Scope, ScopeError

    if mode == "estate":
        try:
            if config:
                assets = estate_mod.load_estate(config, include_secrets)
            else:
                assets = [(host_mod.make_kind(include_secrets),
                           socket.gethostname(), Scope(["127.0.0.1"]))]
        except (OSError, ValueError, KeyError, ScopeError) as e:
            return [("estate", f"bad estate config: {e}")]
        pairs = estate_mod.patrol_estate(assets, state_path)
        return [("estate posture", estate_mod.format_estate(pairs))]

    # defend / guard: a single sweep of THIS host, graded through the evidence gate + diffed.
    kind = host_mod.make_kind(include_secrets)
    diff = patrol_once(kind, socket.gethostname(), Scope(["127.0.0.1"]), state_path)
    blocks = [("host posture", _fmt_posture(kind, diff))]
    if mode == "guard":
        focus = set(diff["new"])                       # the guardian reasons only on what changed
        if not focus:
            blocks.append(("guardian", f"stable — no change since last patrol "
                                       f"({len(diff['persisting'])} known open). AI idle."))
            return blocks
        open_findings = {fid: diff["evidence"].get(fid, "") for fid in focus}
    else:
        open_findings = {fid: diff["evidence"].get(fid, "")
                         for fid in (diff["new"] + diff["persisting"])}
    if not open_findings:
        return blocks                                  # clean posture already stands on its own
    proposals = remediate.plan(open_findings)
    if brain is not None:
        try:
            brief = blue.defensive_brief(brain, set(open_findings), open_findings, proposals)
            if brief:
                blocks.append(("AI defence brief", brief))
        except Exception as e:  # noqa: BLE001 — a brief failure must not sink the posture/plan
            blocks.append(("AI defence brief", f"(unavailable: {e})"))
    blocks.append(("remediation · proposals only", remediate.format_plan(proposals)))
    return blocks


def _emit_blocks(blocks, emit=print) -> int:
    """Print defender blocks for the console (a coloured section header per block)."""
    for title, body in blocks:
        emit("\n" + _c("96", f"── {title} ──"))
        emit(body)
    return 0


def _defend_snapshot(brain, state_path, include_secrets, emit=print) -> int:
    """One read-only pass over THIS host: posture + optional AI brief + fix proposals. Read-only."""
    return _emit_blocks(_defender_blocks(brain, state_path, include_secrets, mode="defend"), emit)


def _estate_snapshot(config, state_path, interval, include_secrets, emit=print) -> int:
    """Patrol a whole estate (hosts + web services). With interval>0 it loops via the engine;
    a single tick renders through the shared block builder. `config`="" = just this host."""
    if interval and interval > 0:
        import socket
        from . import host as host_mod, estate as estate_mod
        from .scope import Scope, ScopeError
        try:
            if config:
                assets = estate_mod.load_estate(config, include_secrets)
            else:
                assets = [(host_mod.make_kind(include_secrets),
                           socket.gethostname(), Scope(["127.0.0.1"]))]
        except (OSError, ValueError, KeyError, ScopeError) as e:
            emit(_c("91", f"  bad estate config: {e}"))
            return 2
        return estate_mod.run_estate(assets, state_path, interval, emit=emit)
    return _emit_blocks(
        _defender_blocks(None, state_path, include_secrets, mode="estate", config=config), emit)


def _quiet_brain(state, args):
    """Build a brain from the live console state WITHOUT printing or spawning anything (safe to
    call from inside the full-screen app's worker). Returns the brain, or None to skip the brief:
    a down Ollama server is left alone here (the console's /model flow starts it explicitly)."""
    brain_kind = state["brain"]
    if brain_kind == "ollama" and not _ollama_server_up(state["ollama_url"]):
        return None
    brain, _err = _build_brain(brain_kind, _resolve_model(brain_kind, state.get("model")),
                               state["ollama_url"], args.base, args.adapter, args.effort)
    return brain


def _run_defender(args) -> int:
    """One-shot CLI entry for the blue-team modes (--defend / --guard / --estate)."""
    if not args.authorized:
        print(_c("91", "REFUSED: pass --authorized to affirm you own / may inspect this host."),
              file=sys.stderr)
        return 2
    # Defender runs against a host you OWN, so it stays usable for evaluation (no hard block —
    # same honour-based ethos as the model notice). We only state the position: the continuous
    # guardian and whole-estate view are licensed features.
    if not _license.is_commercial_authorized():
        print(_c("93", "  EVALUATION mode — non-production use only; the continuous guardian and "
                       "whole-estate view are licensed features.  nexus license add <token>"),
              file=sys.stderr)
    state_path = _defender_state_path(args)

    if args.estate is not None:
        return _estate_snapshot(args.estate, state_path, args.interval, args.include_secrets)

    if args.guard:
        from . import blue
        brain, err = _build_brain(args.brain, _resolve_model(args.brain, args.model),
                                  args.ollama_url, args.base, args.adapter, args.effort)
        if err is not None:
            print(_c("90", f"  (guardian running deterministic-only — {err})"))
            brain = _NoBrain()
        return blue.guard(brain, state_path=state_path, interval=args.interval,
                          include_secrets=args.include_secrets)

    # default: --defend one-shot snapshot
    brain, err = _build_brain(args.brain, _resolve_model(args.brain, args.model),
                              args.ollama_url, args.base, args.adapter, args.effort)
    if err is not None:
        print(_c("90", f"  (no AI brief — {err})"))
        brain = None
    return _defend_snapshot(brain, state_path, args.include_secrets)


def _repl_brain_or_none(state, args):
    """Build a brain from the LIVE repl state (brain/model may have changed via /model). Returns
    the brain, or None with a one-line note if it can't come up — the deterministic posture still
    runs, the AI brief is just skipped."""
    brain, err = _build_brain(state["brain"], _resolve_model(state["brain"], state.get("model")),
                              state["ollama_url"], args.base, args.adapter, args.effort)
    if err is not None:
        print(_c("90", f"  (no AI brief — {err})"))
        return None
    return brain


def _cmd_defend(state, args) -> None:
    print(_c("90", "  defending this host (read-only introspection · proposals only)…"))
    _defend_snapshot(_repl_brain_or_none(state, args), _defender_state_path(args), False)


def _cmd_guard(state, args, rest) -> None:
    from . import blue
    try:
        interval = float(rest) if rest.strip() else 0.0
    except ValueError:
        interval = 0.0
    if interval > 0:
        print(_c("90", f"  guardian watching this host every {interval:g}s · Ctrl-C to stop…"))
    blue.guard(_repl_brain_or_none(state, args) or _NoBrain(),
               state_path=_defender_state_path(args), interval=interval, include_secrets=False)


def _cmd_estate(state, args, rest) -> None:
    _estate_snapshot(rest.strip(), _defender_state_path(args), 0.0, False)


def _assess(target, extra_scope, *, brain, model, ollama_url, base, adapter, effort,
            objective=None, report=None, max_steps=40, allow_dangerous=False,
            rules_accepted=False, rate_limit=None, record=None,
            trust_model_report=False, present=None, should_stop=None,
            report_format="md", explain=False, methodology_floor=True,
            client=None, vendor=None) -> int:
    """Run one full assessment. Shared by the flag path and the interactive REPL."""
    import time as _time
    if present is None:
        # A real terminal gets the live heartbeat; pipes/redirects stay clean line output.
        present = LivePresenter() if sys.stdout.isatty() else PlainPresenter()

    external = _target_is_external(target)

    # Licence gate (evaluation mode). Assessing an EXTERNAL / public-internet target is a
    # commercial use and needs a licence; local / private / lab targets run free in evaluation
    # mode with a watermarked report. Honour-based + this soft gate: the source is open, so the
    # force is honest B2B + BUSL terms, not anti-crack. Covers every caller (flag/REPL/wizard).
    eval_mode = not _license.is_commercial_authorized()
    if eval_mode and external:
        print(_c("91", f"\n  EVALUATION build — assessing {target!r} (a public-internet target) "
                       "is a commercial use."), file=sys.stderr)
        print(_c("93", "  Activate a licence to run against external targets:  "
                       "nexus license add <token>"), file=sys.stderr)
        print(_c("90", "  Local / private / lab targets run free in evaluation mode."),
              file=sys.stderr)
        return 2
    if eval_mode:
        print(_c("93", "  EVALUATION mode — non-production use only; the report is watermarked. "
                       "Activate a licence for licensed deliverables:  nexus license add <token>"),
              file=sys.stderr)

    if external and not rules_accepted:
        print(_c("91", f"REFUSED: {target!r} is a public-internet target."), file=sys.stderr)
        print(_c("90", "  it must be in a bug-bounty/VDP/written scope AND permit automated "
                       "testing; attest the program rules to proceed."), file=sys.stderr)
        return 2
    rl = rate_limit if rate_limit is not None else (1.0 if external else 0.0)
    scope = Scope([target, *extra_scope], allow_dangerous=allow_dangerous, rate_limit=rl)
    objective = objective or (
        f"Perform an authorized security assessment of {target}. "
        "Find weaknesses, then report them with severity, evidence, and remediation.")

    # Preflight: don't scan (and don't even load the model for) a host that isn't answering —
    # a run against a dead target would end in "no findings", which is easily misread as "secure".
    if not _target_reachable(target):
        present.event("result", f"ERROR {target} did not respond — connection refused or timed "
                                "out. Check the host is up and the port is right. No scan was run.")
        return 1

    llm, err = _build_brain(brain, model, ollama_url, base, adapter, effort)
    if err is not None:
        print(_c("91", f"REFUSED: {err}"), file=sys.stderr)
        return 2

    if external:
        print(_c("90", f"  external target — throttling to {rl:g}s between requests"))
    present.header(brain, getattr(llm, "model", "?"), scope.raw, objective)

    recorder = Trajectory(objective, scope.raw) if record else None
    agent = SecurityAgent(scope, llm, max_steps=max_steps, on_event=present.event,
                          recorder=recorder, methodology_floor=methodology_floor)
    if hasattr(present, "set_agent"):
        present.set_agent(agent)   # lets a live presenter count findings as they land
    _t0 = _time.monotonic()
    try:
        with present.thinking(target):
            final = agent.run(objective, target=target, should_stop=should_stop)
    except (LLMError, LocalError) as e:
        print(_c("91", f"\n  brain error: {e}"), file=sys.stderr)
        print(_c("90", "  the run stopped early; no report was written."), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(_c("93", "\n  interrupted — stopping.\n"), file=sys.stderr)
        return 130
    elapsed = _time.monotonic() - _t0

    if recorder is not None:
        try:
            recorder.save(record)
            print(_c("92", f"\n  [trajectory saved] {record}"))
        except OSError as e:
            print(_c("91", f"\n  could not write trajectory: {e}"), file=sys.stderr)

    # The authoritative report is derived from EVIDENCE (real tool results), not the model's
    # prose — no finding is credited unless the live target confirmed it, so fabrication can't
    # reach the report. --trust-model-report opts back into the raw prose.
    evidence_report = findings.report(target, agent.messages, deep=explain)
    if trust_model_report:
        report_body = final
    else:
        report_body = evidence_report + (
            "\n\n---\n\n## Agent narrative (unverified)\n\n"
            "> The following is the model's own write-up. It is NOT evidence-gated and may "
            "contain unconfirmed claims; the findings above are the authoritative result.\n\n"
            + final)

    if eval_mode:
        report_body = (
            "> **EVALUATION REPORT — NOT A LICENSED DELIVERABLE.** Generated by an unlicensed "
            "Nexus build for non-production evaluation only. Do not present as a client "
            "deliverable. Activate a commercial licence (`nexus license add <token>`) to remove "
            "this notice.\n\n---\n\n" + report_body)

    report_path = report or "nexus-report.md"
    saved = False
    try:
        if report_format == "sarif":
            report_path = _with_ext(report_path, ".sarif")
            _write_raw(report_path, findings.to_sarif(target, agent.messages, __version__))
        elif report_format == "json":
            report_path = _with_ext(report_path, ".json")
            _write_raw(report_path, findings.to_json(target, agent.messages, __version__))
        elif report_format == "html":
            from . import deliverable
            report_path = _with_ext(report_path, ".html")
            _write_raw(report_path, deliverable.to_html(
                target, agent.messages, meta={"client": client, "vendor": vendor},
                version=__version__, eval_mode=eval_mode))
        else:
            write_report(report_path, scope, objective, report_body)
        saved = True
    except OSError as e:
        print(_c("91", f"\n  could not write report: {e}"), file=sys.stderr)

    stopped = should_stop is not None and should_stop()
    present.summary(target, agent.messages, report_path if saved else None, elapsed,
                    evidence_report, stopped=stopped)
    return 0


class PlainPresenter:
    """The default (stdlib, no-deps) presentation: ANSI prints, used for the flag path,
    pipes, and whenever the rich TUI extras aren't installed."""

    def header(self, brain, model, scope_raw, objective):
        print(f"  {_c('1', 'nexus')} {_c('90', 'brain')} {brain} {_c('90', '(' + str(model) + ')')}")
        print(f"  {_c('90', 'scope')} {', '.join(scope_raw)}")
        print(f"  {_c('90', 'objective')} {objective}")
        print(f"  {_c('90', _license.status_line())}\n")

    def thinking(self, target):
        import contextlib
        return contextlib.nullcontext()

    def event(self, kind, text):
        if kind == "delta":
            return   # live token stream is a TUI nicety; keep plain/piped output clean
        _print_event(kind, text)

    def summary(self, target, messages, report_path, elapsed, evidence_report, stopped=False):
        _print_summary(target, messages, report_path, elapsed, evidence_report, stopped)


_SPIN_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _tok_rate(tok: int, tok_t0, now: float) -> float:
    """Streaming rate in tok/s, guarded: the first delta and a status tick can land on the
    SAME coarse-resolution monotonic instant (a real Windows race), so the interval can be
    exactly 0 — return 0.0 rather than dividing by zero."""
    if not (tok and tok_t0):
        return 0.0
    dt = now - tok_t0
    return tok / dt if dt > 0 else 0.0


def _status_line(frame_char: str, phase: str, elapsed: float, tok: int, rate: float) -> str:
    """The live 'signs of life' line (no carriage-return/clear — pure, so it's testable):
    a spinner frame + the current phase + token throughput (when streaming) + elapsed time."""
    parts = [phase]
    if tok:
        parts.append(f"{tok} tok")
        if rate:
            parts.append(f"{rate:.1f} tok/s")
    parts.append(f"{elapsed:.0f}s")
    return f"{_c('96;1', frame_char)} {_c('90', ' · '.join(parts))}"


class LivePresenter(PlainPresenter):
    """TTY presentation with a heartbeat. While the brain generates — which on the local
    model is slow — an animated spinner shows the phase, live token rate, and elapsed time,
    so a long think reads as 'working', not 'hung'. Discrete events (tool calls, results,
    reasoning) clear the spinner, print, and the spinner resumes below. Stdlib threading; the
    plain per-event rendering is inherited, so pipes/non-TTY keep clean line output."""

    def __init__(self):
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        self._frame = 0
        self._phase = "thinking"
        self._t0 = 0.0
        self._tok = 0
        self._tok_t0 = None   # monotonic time of the first delta this phase → for tok/s

    # --- the animated line (all stdout writes go through the lock) ---
    def _write_status(self):
        el = time.monotonic() - self._t0
        rate = _tok_rate(self._tok, self._tok_t0, time.monotonic())
        frame = _SPIN_FRAMES[self._frame % len(_SPIN_FRAMES)]
        sys.stdout.write("\r" + _status_line(frame, self._phase, el, self._tok, rate) + "\033[K")
        sys.stdout.flush()

    def _clear(self):
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()

    def _spin(self):
        while not self._stop.is_set():
            with self._lock:
                self._write_status()
            self._frame += 1
            self._stop.wait(0.1)

    def thinking(self, target):
        @contextlib.contextmanager
        def _cm():
            self._t0 = time.monotonic()
            self._tok = 0
            self._tok_t0 = None
            self._stop.clear()
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
            try:
                yield
            finally:
                self._stop.set()
                if self._thread:
                    self._thread.join(timeout=0.3)
                with self._lock:
                    self._clear()
        return _cm()

    def event(self, kind, text):
        if kind == "delta":
            with self._lock:
                if self._tok_t0 is None:
                    self._tok_t0 = time.monotonic()
                self._tok += 1
            return
        with self._lock:
            self._clear()
            _print_event(kind, text)
            if kind == "tool":
                self._phase = "running " + (text.split(" ", 1)[0] or "tool")
                self._tok = 0
                self._tok_t0 = None
            elif kind in ("step", "result"):
                self._phase = "thinking"
                self._tok = 0
                self._tok_t0 = None


def _print_summary(target, messages, report_path, elapsed, evidence_report, stopped=False) -> None:
    """A clean, scannable end-of-run summary — colour-coded findings, counts, report path."""
    found, ev = findings.analyze(messages)
    scans = findings.scanner_matches(messages)
    tool_calls = sum(
        1 for m in messages if isinstance(m.get("content"), list)
        for b in m["content"] if isinstance(b, dict) and b.get("type") == "tool_use")
    sev_colour = {"Critical": "91", "High": "91", "Medium": "93", "Low": "93", "Info": "94"}

    heading = _c("93", "ASSESSMENT STOPPED (partial)") if stopped else _c("1", "ASSESSMENT COMPLETE")
    print("\n" + _c("90", "  " + "─" * 52))
    print(f"  {heading}  {_c('90', '·')}  {target}")
    print(_c("90", "  " + "─" * 52))

    n = 0
    for fid, label, sev in findings._SPEC:
        if fid in found:
            n += 1
            dot = _c(sev_colour.get(sev, "97"), "●")
            detail = ev.get(fid, "").split(" Remediation:")[0].strip()
            print(f"  {dot} {_c(sev_colour.get(sev, '97'), sev.upper().ljust(8))} "
                  f"{label}{_c('90', '  — ' + detail[:60]) if detail else ''}")
    for f in scans:
        n += 1
        sev = (f.get("severity") or "info").capitalize()
        dot = _c(sev_colour.get(sev, "94"), "●")
        print(f"  {dot} {_c(sev_colour.get(sev, '94'), sev.upper().ljust(8))} "
              f"{f.get('name') or f.get('template')} {_c('90', '(nuclei)')}")
    if n == 0:
        print(_c("90", "  no findings confirmed by evidence "
                       "(nothing was fabricated to fill the gap)."))

    print(_c("90", "  " + "─" * 52))
    print(f"  {_c('1', str(n))} findings {_c('90', '·')} {_c('92', '0 fabricated')} "
          f"{_c('90', '·')} {tool_calls} tool calls {_c('90', '·')} {elapsed:.0f}s")
    if tool_calls == 0:
        print(_c("93", "  ⚠ the model made no tool calls — it may not drive tools well."))
        print(_c("90", "    switch to a tools-capable model:  /model → qwen2.5:7b"))
    if report_path:
        print(f"  {_c('90', 'full report →')} {report_path}")
    print()


def _repl_help() -> None:
    print(_c("90", "\n  commands:"))
    print("  " + _c("96", "<target>") + _c("90", "   assess a host or URL you are authorized to test"))
    print("  " + _c("96", "/model") + _c("90", "     switch the brain / model"))
    print("  " + _c("96", "/format") + _c("90", "    report format: md · sarif · json"))
    print("  " + _c("96", "/key") + _c("90", "       set or replace the Anthropic API key"))
    print("  " + _c("96", "/scope") + _c("90", "     show or add extra in-scope hosts"))
    print("  " + _c("96", "/report") + _c("90", "    show the last report"))
    print("  " + _c("96", "/defend") + _c("90", "    defend THIS host: read-only posture + AI brief + fix proposals"))
    print("  " + _c("96", "/guard") + _c("90", "     [secs] continuous guardian; AI engages only on a new hole"))
    print("  " + _c("96", "/estate") + _c("90", "    [config] roll up a whole estate's posture (hosts + web)"))
    print("  " + _c("96", "/help") + _c("90", "      show this help"))
    print("  " + _c("96", "/quit") + _c("90", "      exit\n"))


_REPORT_FORMATS = ("md", "sarif", "json")


def _cmd_format(state, rest) -> None:
    """Show or set the report format for the plain REPL (parity with the TUI /format)."""
    cur = state.get("format", "md")
    choice = (rest or "").strip().lower()
    if not choice:
        print(_c("90", f"  report format: ") + _c("96", cur)
              + _c("90", "   — set with /format md|sarif|json"))
        return
    if choice not in _REPORT_FORMATS:
        print(_c("91", f"  unknown format {choice!r}") + _c("90", " — choose md, sarif, or json."))
        return
    state["format"] = choice
    print(_c("92", f"  ✓ report format → {choice}"))


def _cmd_key(state=None) -> None:
    """Set or replace the Anthropic API key from the REPL, hidden as you type."""
    have = bool(os.environ.get("ANTHROPIC_API_KEY"))
    print(_c("90", f"  {'Replace' if have else 'Set'} the Anthropic API key "
                   "(get one at https://console.anthropic.com/settings/keys)"))
    import getpass
    try:
        key = getpass.getpass(f"  {_c('96', '›')} Paste key {_c('90', '(hidden — Enter to skip)')}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print(_c("90", "  cancelled — key unchanged."))
        return
    if not key:
        print(_c("90", "  cancelled — key unchanged."))
        return
    if not key.startswith("sk-ant-"):
        print(_c("91", "  that doesn't look like an Anthropic key (expected sk-ant-…)."))
        return
    os.environ["ANTHROPIC_API_KEY"] = key
    cfg = _load_config()
    cfg["anthropic_api_key"] = key
    saved = _save_config(cfg)
    print(_c("92", "  ✓ key saved to ~/.nexus/config.json (0600)." if saved
                   else "  ✓ key set for this session (couldn't write config)."))


def _ollama_server_up(ollama_url) -> bool:
    import socket
    from urllib.parse import urlparse
    u = urlparse(ollama_url)
    try:
        s = socket.create_connection((u.hostname or "127.0.0.1", u.port or 11434), timeout=0.5)
        s.close()
        return True
    except OSError:
        return False


def _ensure_ollama_server(ollama_url, wait: float = 30.0) -> bool:
    """Start the local Ollama server automatically if it isn't already running, so the user
    never has to launch `ollama serve` by hand. Fast no-op when it's already up."""
    if _ollama_server_up(ollama_url):
        return True
    import shutil
    import subprocess
    import time
    exe = shutil.which("ollama")
    if not exe:
        print(_c("91", "  Ollama is not installed."))
        print(_c("90", "  install it once from https://ollama.com, then Nexus starts it for you."))
        return False
    print(_c("90", "  starting the local Ollama server…"))
    kwargs = {"stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL,
              "stdin": subprocess.DEVNULL}
    if os.name == "nt":
        # DETACHED_PROCESS | CREATE_NO_WINDOW — outlive nexus, no console popup.
        kwargs["creationflags"] = 0x00000008 | 0x08000000
    else:
        kwargs["start_new_session"] = True
    try:
        subprocess.Popen([exe, "serve"], **kwargs)
    except OSError as e:
        print(_c("91", f"  could not start Ollama: {e}"))
        return False
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        if _ollama_server_up(ollama_url):
            return True
        time.sleep(0.4)
    print(_c("91", "  Ollama did not become ready in time."))
    return False


def _ensure_model(model, ollama_url) -> bool:
    """Ensure the server is up and the model is present, pulling it on first use."""
    if not _ensure_ollama_server(ollama_url):
        return False
    if model in ollama_models(ollama_url):
        return True
    import shutil
    import subprocess
    if not shutil.which("ollama"):
        print(_c("91", "  Ollama is not installed."))
        print(_c("90", "  install it from https://ollama.com, then try again."))
        return False
    print(_c("90", f"  first run: pulling {model} (free, one-time download)…"))
    try:
        subprocess.run(["ollama", "pull", model], check=True)
    except (subprocess.CalledProcessError, OSError) as e:
        print(_c("91", f"  pull failed: {e}"))
        return False
    return True


def _cmd_scope(state, rest) -> None:
    """Show, add to, or clear the extra in-scope hosts carried into each assessment."""
    if not rest:
        cur = ", ".join(state["extra_scope"]) or "(just the target you type)"
        print(_c("90", f"  extra scope: {cur}"))
        print(_c("90", "  add with:  /scope host-or-cidr[, host2]   ·   clear with:  /scope none"))
        return
    if rest.lower() in ("none", "clear", "reset"):
        state["extra_scope"] = []
        print(_c("92", "  extra scope cleared."))
        return
    added = [s.strip() for s in rest.replace(",", " ").split() if s.strip()]
    for s in added:
        if s not in state["extra_scope"]:
            state["extra_scope"].append(s)
    print(_c("92", f"  extra scope: {', '.join(state['extra_scope'])}"))


def _cmd_report(state, con) -> None:
    """Render the last full report (evidence findings + narrative) in the terminal."""
    path = state.get("last_report")
    if not path or not os.path.exists(path):
        print(_c("90", "  no report yet — assess a target first."))
        return
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        print(_c("91", f"  could not read {path}: {e}"))
        return
    # Only the markdown report goes through the markdown renderer; SARIF/JSON is machine data
    # and reads correctly as plain text (markdown would mangle the braces).
    if con is not None and path.lower().endswith(".md"):
        tui.render_markdown(con, text)
    else:
        print("\n" + text)


def _cmd_model(state, con=None) -> None:
    """Interactive /model picker; persists the choice to ~/.nexus/config.json."""
    rows = [("ollama", m) for m in ollama_models(state["ollama_url"])]
    rows.append(("claude", CLAUDE_MODEL))
    rows.append(("local", "tuned offline brain (Pro)"))
    if con is not None:
        tui.model_table(con, rows, (state["brain"], state["model"]))
    else:
        print(_c("90", "\n  available models:"))
        for i, (br, mdl) in enumerate(rows, 1):
            cur = "  " + _c("92", "← current") if (br == state["brain"] and mdl == state["model"]) else ""
            print(f"   {i}. {mdl} {_c('90', '[' + br + ']')}{cur}")
    try:
        pick = input(_c("96", "\n  pick #: ")).strip()
    except (EOFError, KeyboardInterrupt):
        return
    if not pick.isdigit() or not (1 <= int(pick) <= len(rows)):
        print(_c("90", "  unchanged."))
        return
    br, mdl = rows[int(pick) - 1]
    if br == "claude" and not _ensure_claude_key():
        print(_c("90", "  no key — keeping current model."))
        return
    if br == "ollama" and not _ensure_model(mdl, state["ollama_url"]):
        return
    state["brain"], state["model"] = br, mdl
    cfg = _load_config()
    cfg["brain"], cfg["model"] = br, mdl
    _save_config(cfg)
    print(_c("92", f"  ✓ model set to {mdl} [{br}]") + _c("90", " (saved)"))


def _build_ctx(args, state):
    """Callables the full-screen app uses — keeps all logic in cli.py, no import cycle."""
    def assess(target, extra_scope, rules, present, objective=None, should_stop=None):
        model = state["model"] or (DEFAULT_MODEL if state["brain"] == "ollama"
                                   else CLAUDE_MODEL)
        fmt = state.get("format", "md")
        report = _with_ext(_report_name(target), {"sarif": ".sarif", "json": ".json"}.get(fmt, ".md"))
        rc = _assess(target, extra_scope, brain=state["brain"], model=model,
                     ollama_url=state["ollama_url"], base=args.base, adapter=args.adapter,
                     effort=args.effort, max_steps=args.max_steps, objective=objective,
                     report=report, rules_accepted=rules, present=present, should_stop=should_stop,
                     report_format=fmt, methodology_floor=not args.no_floor)
        if rc == 0:
            state["last_report"] = report
        return rc

    def save_model(br, mdl):
        state["brain"], state["model"] = br, mdl
        cfg = _load_config()
        cfg["brain"], cfg["model"] = br, mdl
        _save_config(cfg)

    def read(p):
        try:
            with open(p, encoding="utf-8") as f:
                return f.read()
        except OSError:
            return None

    def set_api_key(key):
        """Store an Anthropic API key entered in the console: use it now (env) and remember it
        (0600 config). Returns (ok, message). Light format check only — the key is verified for
        real on the first Claude call, so a wrong key surfaces there, not with a blocking probe."""
        key = (key or "").strip()
        if not key:
            return False, "no key entered."
        if not key.startswith("sk-ant-"):
            return False, "that doesn't look like an Anthropic key (expected sk-ant-…)."
        os.environ["ANTHROPIC_API_KEY"] = key
        cfg = _load_config()
        cfg["anthropic_api_key"] = key
        saved = _save_config(cfg)
        return True, ("key saved to ~/.nexus/config.json (0600)." if saved
                      else "key set for this session (couldn't write config).")

    def chat(history, on_delta=None):
        model = state["model"] or (DEFAULT_MODEL if state["brain"] == "ollama"
                                   else CLAUDE_MODEL)
        # The scan model (qwen) drives tools best but chats poorly (language drift). If a clean
        # multilingual chat model is installed, use it for chat only — best of both.
        if state["brain"] == "ollama":
            model = _preferred_chat_model(state["ollama_url"], model)
        llm, err = _build_brain(state["brain"], model, state["ollama_url"], args.base,
                                args.adapter, args.effort)
        if err is not None:
            return "⚠ " + err
        # Ground the answer: if the latest user question touches a known security/programming
        # topic, hand the model the authoritative reference for this turn so even a small local
        # brain answers correctly (real knowledge, not the model's shaky guess).
        last_user = next((m.get("content", "") for m in reversed(history)
                          if m.get("role") == "user" and isinstance(m.get("content"), str)), "")
        system = CHAT_SYSTEM + knowledge.grounding(last_user)
        kw = {"on_delta": on_delta} if (on_delta and getattr(llm, "streams", False)) else {}
        try:
            resp = llm.complete(system, history, tools=None, **kw)
        except (LLMError, LocalError) as e:
            return "⚠ " + str(e)
        text = "".join(b.get("text", "") for b in resp.get("content", [])
                       if b.get("type") == "text").strip()
        return _strip_cjk_drift(text) or "(no response)"

    return {
        "state": state,
        "assess": assess,
        "chat": chat,
        "chat_model": lambda: (
            _preferred_chat_model(state["ollama_url"], state["model"] or DEFAULT_MODEL)
            if state["brain"] == "ollama"
            else (state["model"] or CLAUDE_MODEL)),
        "valid_target": _valid_target,
        "extract_target": _extract_target,
        "scan_handoff": _scan_handoff,
        "is_external": _target_is_external,
        "ensure_server": _ensure_ollama_server,
        "ensure_model": _ensure_model,
        "models": ollama_models,
        "has_key": lambda: bool(os.environ.get("ANTHROPIC_API_KEY")),
        "license_status": _license.status_line,
        "claude_model": CLAUDE_MODEL,
        "set_api_key": set_api_key,
        "save_model": save_model,
        "scope_host": lambda s: (Scope._host(s) or s).lower(),
        # defender (blue-team): each returns titled text blocks [(title, body), …] the app wraps
        # in panels. Read-only introspection + proposals — no path here ever changes the system.
        "defend": lambda: _defender_blocks(_quiet_brain(state, args),
                                           _defender_state_path(args), False, mode="defend"),
        "guard": lambda: _defender_blocks(_quiet_brain(state, args),
                                          _defender_state_path(args), False, mode="guard"),
        "estate": lambda cfg="": _defender_blocks(None, _defender_state_path(args),
                                                  False, mode="estate", config=cfg),
        "exists": os.path.exists,
        "read": read,
    }


def _repl(args) -> int:
    """Interactive session: assess targets, switch models with /model — a real CLI.

    Uses the rich TUI (bottom input, slash autocomplete, spinner, findings panel) when the
    [tui] extras are installed; otherwise a clean plain-ANSI REPL. Same loop either way.
    """
    cfg = _load_config()
    state = {
        "brain": cfg.get("brain", "ollama"),
        "model": cfg.get("model", DEFAULT_MODEL),
        "ollama_url": args.ollama_url,
        "extra_scope": [],
        "last_report": None,
        "last_target": None,
        "format": getattr(args, "format", "md"),   # report format, switchable live via /format
    }
    # Prefer the full-screen Textual app (pinned input, scrolling output) — the Claude
    # Code / Gemini shape. Fall back to the rich/plain REPL if it isn't available or the
    # terminal can't host a full-screen app.
    if tui_app.available():
        try:
            return tui_app.run(_build_ctx(args, state))
        except Exception:  # noqa: BLE001 — not a real terminal, etc. → fall through
            pass

    ctx = _build_ctx(args, state)
    chat_history: list = []
    use_tui = tui.available()
    con = tui.console() if use_tui else None
    session = tui.make_session(_config_file().parent / "history") if use_tui else None

    if use_tui:
        tui.banner(con, state["brain"], state["model"])
    else:
        print(_banner())
        print(f"  {_c('90', 'model')} {state['model']} {_c('90', '[' + state['brain'] + ']')}"
              f"   {_c('90', '·  type /help')}")
    print(f"  {_c('90', _license.status_line())}")

    # Bring the local brain online up front so the first assessment is instant, not stalled.
    if state["brain"] == "ollama":
        _ensure_ollama_server(state["ollama_url"])

    def _read():
        if use_tui:
            return tui.ask(session, state["brain"], state["model"])
        return input(_c("96", "\n  nexus› ")).strip()

    authorized_hosts: set = set()
    while True:
        try:
            line = _read()
        except (EOFError, KeyboardInterrupt):
            print(_c("90", "\n  bye.\n"))
            return 0
        if not line:
            continue
        if line.startswith("/"):
            parts = line[1:].split(None, 1)
            cmd = parts[0].lower() if parts else ""
            rest = parts[1].strip() if len(parts) > 1 else ""
            if cmd in ("quit", "exit", "q"):
                print(_c("90", "  bye.\n"))
                return 0
            if cmd in ("help", "h", "?", ""):
                tui.help_panel(con) if use_tui else _repl_help()
            elif cmd in ("model", "brain"):
                _cmd_model(state, con if use_tui else None)
            elif cmd == "format":
                _cmd_format(state, rest)
            elif cmd == "key":
                _cmd_key(state)
            elif cmd == "scope":
                _cmd_scope(state, rest)
            elif cmd == "report":
                _cmd_report(state, con if use_tui else None)
            elif cmd == "defend":
                _cmd_defend(state, args)
            elif cmd == "guard":
                _cmd_guard(state, args, rest)
            elif cmd == "estate":
                _cmd_estate(state, args, rest)
            elif cmd == "clear":
                con.clear() if use_tui else print("\033[2J\033[H", end="")
                if use_tui:
                    tui.banner(con, state["brain"], state["model"])
            else:
                print(_c("90", f"  unknown command /{cmd} — try /help"))
            continue

        # A message naming a host/URL → REAL scan (never let chat fabricate results about a
        # system); a plain question → chat. "check example.com for xss" works naturally.
        target = _extract_target(line)
        if target is None:
            handoff = _scan_handoff(line)
            if handoff:                      # "check my site" with no URL → correct fixed reply
                print(f"  {_c('94', 'Nexus')}  {handoff}\n")
                continue
            chat_history.append({"role": "user", "content": line})
            print(_c("90", "  Nexus is thinking…"))
            answer = ctx["chat"](chat_history)
            chat_history.append({"role": "assistant", "content": answer})
            if len(chat_history) > 16:
                del chat_history[:-16]
            print(f"  {_c('94', 'Nexus')}  {answer}\n")
            continue
        objective = line if line.strip() != target else None
        if state["brain"] == "ollama" and not _ensure_model(state["model"], state["ollama_url"]):
            continue
        host = (Scope._host(target) or target).lower()
        if host not in authorized_hosts:
            print(_c("90", "  Nexus only tests systems you own or are explicitly authorized to test."))
            if not _yesno("I am authorized to test this scope"):
                print(_c("91", "  not authorized — skipped."))
                continue
            authorized_hosts.add(host)
        rules = False
        if _target_is_external(target):
            print(_c("93", f"  {target} looks like a public-internet target."))
            if not _yesno("automated testing is permitted by the program's rules"):
                print(_c("91", "  rules not confirmed — skipped."))
                continue
            rules = True
        present = (tui.RichPresenter(con) if use_tui
                   else LivePresenter() if sys.stdout.isatty() else PlainPresenter())
        report = _report_name(target)
        rc = _assess(target, list(state["extra_scope"]), brain=state["brain"],
                     model=state["model"], ollama_url=state["ollama_url"], base=args.base,
                     adapter=args.adapter, effort=args.effort, max_steps=args.max_steps,
                     objective=objective, report=report, rules_accepted=rules, present=present)
        if rc == 0:
            state["last_report"], state["last_target"] = report, target


def main(argv=None) -> int:
    """Console entry point — never lets a raw traceback reach the user."""
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print(_c("93", "\n  interrupted.\n"), file=sys.stderr)
        return 130
    except Exception as e:  # noqa: BLE001 — a CLI must fail gracefully, not dump a stack trace
        print(_c("91", f"\n  unexpected error: {type(e).__name__}: {e}"), file=sys.stderr)
        print(_c("90", "  if this keeps happening, re-run with the same input and report it."),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
