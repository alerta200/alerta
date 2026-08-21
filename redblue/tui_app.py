"""tui_app.py — the full-screen Nexus console (Textual).

A pinned bottom input box, a scrolling output pane above it, and a status line — the
Claude Code / Gemini shape, not a line-by-line REPL. Optional: cli.py falls back to the
plain REPL when Textual isn't installed or the terminal can't host a full-screen app.

cli.py stays the owner of all logic; it hands this module a `ctx` of callables, so there
is no import cycle and the app is presentation only.
"""

from __future__ import annotations

import contextlib
import re
import textwrap
import threading
import time

# Qwen/DeepSeek models drift into Chinese mid-reply; the live "thinking" view trims at the
# drift so it stays as clean as the committed answer (which cli.py also strips).
_CJK_RE = re.compile(r"[㐀-鿿぀-ヿ＀-￯　-〿]")


def _trim_cjk(text: str) -> str:
    m = _CJK_RE.search(text)
    if not m or m.start() < 12:
        return text
    return re.sub(r"[ \t]{2,}", " ", _CJK_RE.sub("", text))

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.widgets import Input, RichLog, Static
    from textual.containers import Horizontal, Vertical, VerticalScroll
    from rich.table import Table
    from rich.text import Text
    from rich.box import ROUNDED
    from rich.panel import Panel
    from rich.align import Align
    from rich.console import Group
    from rich.markup import escape
    from . import findings
    from . import _style as S
    _HAVE = True
except Exception:  # noqa: BLE001
    _HAVE = False
    # Stand-ins so the class body below still *defines* without Textual installed (the app is
    # never instantiated in that case — cli.py checks available() first).
    App = object

    def Binding(*_a, **_k):
        return None


def available() -> bool:
    return _HAVE


_SEV_STYLE = {"Critical": "bold red", "High": "red", "Medium": "yellow",
              "Low": "yellow", "Info": "cyan"}

_HELP = [
    ("<target>", "assess a host or URL you are authorized to test"),
    ("/model", "switch the brain / model"),
    ("/format", "report format: md · sarif · json"),
    ("/key", "set or replace the Anthropic API key"),
    ("/scope", "show or add extra in-scope hosts"),
    ("/report", "show the last full report"),
    ("/defend", "defend THIS host: read-only posture + AI brief + fix proposals"),
    ("/guard", "what changed since the last patrol (AI engages only on a new hole)"),
    ("/estate", "roll up a whole estate's posture — /estate [config.json]"),
    ("/clear", "clear the screen"),
    ("/help", "these commands"),
    ("/quit", "exit  (or Ctrl-C)"),
]


def _tok_rate(tok: int, tok_t0, now: float) -> float:
    """tok/s, guarded: the worker thread may set tok_t0 in the SAME coarse monotonic instant
    this UI tick reads it, so the interval can be exactly 0 — return 0.0, never divide by it."""
    if not (tok and tok_t0):
        return 0.0
    dt = now - tok_t0
    return tok / dt if dt > 0 else 0.0


class _AppPresenter:
    """Presenter handed to cli._assess. Its methods run on a worker thread, so every UI
    touch is marshalled onto Textual's thread with call_from_thread."""

    def __init__(self, app):
        self.app = app
        self._buf = ""

    def set_agent(self, agent):
        """cli._assess hands us the live agent so the UI can count evidence-gated findings as
        they accumulate — findings.analyze over its growing transcript, same gate as the report."""
        self.app._agent = agent

    def header(self, brain, model, scope_raw, objective):
        t = Text()
        t.append("scope ", style="dim")
        t.append(", ".join(scope_raw))
        t.append("  ·  ", style="dim")
        t.append(objective, style="dim")
        self.app.call_from_thread(self.app.write_line, t)

    def thinking(self, target):
        return contextlib.nullcontext()

    def _flush_reasoning(self):
        """Commit the reasoning streamed since the last tool/step as a permanent » line in the
        transcript, so the red-team side reads as spoken thought → action — not bare tool calls."""
        reasoning = " ".join(self._buf.split())
        if not reasoning:
            return
        r = Text("  ")
        r.append(S.GLYPH["text"] + " ", style=f"bold {S.GLYPH_STYLE['text']}")
        r.append(_trim_cjk(reasoning)[:300], style="#c6d2e8")
        self.app.call_from_thread(self.app.write_line, r)

    def event(self, kind, text):
        # Status data (step/tail/tool count) is written to plain attributes and rendered by the
        # UI-thread timer — NOT via call_from_thread. This avoids a blocking cross-thread hop on
        # every streamed token (which made real runs crawl); the counter race is harmless.
        if kind == "step":
            self._flush_reasoning()          # commit any reasoning before the phase turns over
            self._buf = ""
            self.app._rp_step = text
            self.app._rp_full = ""
            self.app._rp_tok, self.app._rp_tok_t0 = 0, None
            m = re.search(r"(\d+)\s*/\s*(\d+)", text)   # real "step N/max" → the HUD gauge
            if m:
                self.app._rp_step_done, self.app._rp_step_total = int(m.group(1)), int(m.group(2))
            div = Text("\n  ")               # a phase divider in the transcript (step N/max)
            div.append(f"{S.GLYPH['step'] * 2} ", style=S.GHOST)   # rule glyph stays quiet
            div.append(f"{text} ", style=S.FAINT)                  # phase label stays legible
            self.app.call_from_thread(self.app.write_line, div)
        elif kind == "delta":
            self._buf += text
            self.app._rp_tail = " ".join(self._buf.split())
            self.app._rp_full = self._buf
            if self.app._rp_tok_t0 is None:
                self.app._rp_tok_t0 = time.monotonic()
            self.app._rp_tok += 1
        elif kind == "tool":
            self._flush_reasoning()          # the » reasoning that led to this tool call
            self._buf = ""
            self.app._rp_full = ""
            self.app._rp_tools += 1
            self.app._rp_tok, self.app._rp_tok_t0 = 0, None
            t = Text("  ")
            t.append(S.GLYPH["tool"] + " ", style=f"bold {S.GLYPH_STYLE['tool']}")
            name, _, rest = text.partition(" ")   # bold the tool name, dim its arguments
            seq = getattr(self.app, "_rp_toolseq", None)   # honest breadcrumb (real app only;
            if seq is not None:                            # a minimal presenter-consumer omits it)
                seq.append(name)
                if len(seq) > 32:
                    del seq[:-32]
            t.append(name, style=f"bold {S.INK}")
            if rest:
                t.append(" " + rest, style=S.DIM)
            self.app.call_from_thread(self.app.write_line, t)
        elif kind == "result":
            err = text.startswith("ERROR")
            t = Text("  ")
            t.append(S.GLYPH["result"] + " ", style=S.RED if err else S.GLYPH_STYLE["result"])
            t.append(text.replace("\n", " ")[:100], style=S.RED if err else S.FAINT)
            self.app.call_from_thread(self.app.write_line, t)

    def summary(self, target, messages, report_path, elapsed, evidence_report, stopped=False):
        self.app.call_from_thread(self.app.write_findings, target, messages,
                                  report_path, elapsed, stopped)


def _dock_render(messages, *, final=False, elapsed=None, report_path=None, stopped=False):
    """Build the evidence dock (the blue-team side): a header metric — N · 0 fabricated —
    over one proof-pair receipt per evidence-gated finding. Shared by the live tick and the
    final summary, so a finding looks identical while it lands and after. Returns (renderable, n).
    """
    found, ev = findings.analyze(messages)
    scans = findings.scanner_matches(messages)
    tool_calls = sum(
        1 for m in messages if isinstance(m.get("content"), list)
        for b in m["content"] if isinstance(b, dict) and b.get("type") == "tool_use")

    blocks, n = [], 0
    counts: dict = {}
    for fid, label, sev in findings._SPEC:
        if fid in found:
            n += 1
            counts[sev] = counts.get(sev, 0) + 1
            detail = ev.get(fid, "").split(" Remediation:")[0].strip()
            blocks.append(S.finding_block(
                sev, label, detail, probe=S.probe_for(fid),
                remediation=findings._REMEDIATION.get(fid, "")))
    for f in scans:
        n += 1
        sev = (f.get("severity") or "info").capitalize()
        counts[sev] = counts.get(sev, 0) + 1
        blocks.append(S.finding_block(
            sev, f.get("name") or f.get("template") or "match",
            "matched a maintained detection template", probe="nuclei"))

    # ── integrity meter: the payoff (N proven · time · tools) over a severity-tinted
    # distribution bar, then the hero guarantee pill — all from REAL counts, nothing inferred. ──
    header = Text()
    if final:
        if stopped:
            header.append("■ ASSESSMENT STOPPED (partial)\n", style=f"bold {S.AMBER}")
        else:
            header.append("✓ ASSESSMENT COMPLETE\n", style=f"bold {S.VERIFY}")
    header.append(str(n), style=f"bold {S.INK}")
    header.append(" proven", style=S.DIM)
    meta = []
    if elapsed is not None:
        meta.append(f"{elapsed:.0f}s")
    if tool_calls:
        meta.append(f"{tool_calls} tools")
    if meta:
        header.append("   ·   " + "  ·  ".join(meta), style=S.DIM)
    bar = S.severity_bar(counts, width=50)
    if bar.plain:
        header.append("\n")
        header.append_text(bar)

    # The hero subtitle is honest about WHAT the '0 fabricated' badge means right now: proof
    # backs each finding (n>0), a clean result was found (final, empty), the run was cut short,
    # or the gate is still open (live). "proven by the target's own response" must NOT show when
    # nothing was proven.
    hero = Text()
    hero.append(" 0 FABRICATED ", style=f"bold {S.VOID} on {S.VERIFY}")
    if n > 0:
        hero.append("  proven by the target's own response", style=S.FAINT)
    elif final and stopped:
        hero.append("  stopped — nothing confirmed", style=S.FAINT)
    elif final:
        hero.append("  a clean result, honestly reported", style=S.FAINT)
    else:
        hero.append("  the integrity guarantee", style=S.FAINT)

    if not blocks:
        # A COMPLETED scan with no findings is a clean bill of health — never "awaiting evidence"
        # (that contradicts "COMPLETE"). Report the honest negative; "awaiting" is for the live
        # gate only (a run still in progress, before the first proof lands).
        if final and stopped:
            note = Text("\nStopped before the target's response confirmed any\n"
                        "finding. Nothing was inferred to fill the gap.", style=S.FAINT)
        elif final:
            note = Text("\nNo findings. The target's responses did not confirm\n"
                        "any check — and nothing was invented to fill the gap.", style=S.FAINT)
        else:
            note = Text(f"\n{S.GATE_GLYPH} awaiting evidence.\n\n", style=S.FAINT)
            note.append("Nothing is credited until the target's\nown response proves it — that is the\n"
                        "evidence gate.", style=S.FAINT)
        return Group(header, hero, note), n
    parts = [header, hero, Text(""), *blocks]
    if report_path:
        parts.append(Text(f"report → {escape(str(report_path))}", style=S.FAINT))
    return Group(*parts), n


_NEXUS_ART = [
    "███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗",
    "████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝",
    "██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗",
    "██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║",
    "██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║",
    "╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝",
]


def _gradient_banner(pad: int = 0):
    """The big NEXUS wordmark with a smooth red→blue horizontal gradient across the columns,
    indented by `pad` spaces so the caller can center it at the current width."""
    c1, c2 = (255, 59, 78), (87, 199, 255)   # red → sky (NE·X·US wordmark gradient)
    width = max(len(line) for line in _NEXUS_ART)
    t = Text()
    t.append("\n")
    for line in _NEXUS_ART:
        t.append(" " * pad)
        for x, ch in enumerate(line):
            if ch == " ":
                t.append(" ")
                continue
            f = x / max(1, width - 1)
            r = int(c1[0] + (c2[0] - c1[0]) * f)
            g = int(c1[1] + (c2[1] - c1[1]) * f)
            b = int(c1[2] + (c2[2] - c1[2]) * f)
            t.append(ch, style=f"bold #{r:02x}{g:02x}{b:02x}")
        t.append("\n")
    return t


def _gradient_banner_reveal(reveal: int):
    """The wordmark mid-ignition: the same red→sky gradient, but only columns up to `reveal`
    are lit — the boot animation sweeps `reveal` left→right so the mark draws itself in.
    Not centered here — the #boot overlay centers it via CSS (content-align)."""
    c1, c2 = (255, 59, 78), (87, 199, 255)
    width = max(len(line) for line in _NEXUS_ART)
    t = Text()
    for line in _NEXUS_ART:
        for x, ch in enumerate(line):
            if ch == " " or x > reveal:
                t.append(" ")
                continue
            f = x / max(1, width - 1)
            r = int(c1[0] + (c2[0] - c1[0]) * f)
            g = int(c1[1] + (c2[1] - c1[1]) * f)
            b = int(c1[2] + (c2[2] - c1[2]) * f)
            t.append(ch, style=f"bold #{r:02x}{g:02x}{b:02x}")
        t.append("\n")
    return t


class NexusApp(App):
    # Layout renders the wordmark: red-team transcript (left) meets the blue-team evidence
    # dock (right) across a magenta seam — the evidence gate. NE · X · US.
    CSS = """
    Screen { background: #0a0b0f; layout: vertical; layers: base boot; }
    #hud {
        height: 1; background: #0c0f17; color: #e7eaf2;
        padding: 0 1; border-bottom: solid #1b1e27;
    }
    #main { height: 1fr; layout: horizontal; }
    #leftcol { width: 1fr; layout: vertical; }
    #log { height: 1fr; background: #0a0b0f; padding: 0 1; scrollbar-color: #232838; scrollbar-size: 1 1; }
    #live {
        display: none; height: 9; background: #0f1218; color: #c7d0e4;
        padding: 0 1; border: round #8f3340; border-title-color: #ff5a66;
    }
    #seam { width: 1; height: 1fr; background: #0a0b0f; padding: 0; }
    #findings {
        width: 40%; min-width: 40; max-width: 58;
        background: #0f1218; color: #e7eaf2; padding: 0 1;
        border: round #232838; border-title-color: #e5399b;
        scrollbar-color: #232838; scrollbar-size: 1 1;
    }
    #dock { width: 1fr; height: auto; background: #0f1218; }
    #status {
        height: 1; background: #0c0f17; color: #8c95ab;
        padding: 0 1; border-top: solid #1b1e27;
    }
    #hints {
        display: none; height: auto; max-height: 8; background: #0a0c13; color: #cdd3e1;
        padding: 0 1; border-top: solid #14304a;
    }
    #cmd {
        height: 3; background: #0a0c13; color: #eef1fa;
        border: round #ff3b4e; padding: 0 1;
    }
    #cmd:focus { border: round #ff5a66; }
    #boot {
        display: none; layer: boot; width: 100%; height: 100%;
        background: #0a0b0f; color: #e7eaf2; content-align: center middle; text-align: center;
    }
    """
    BINDINGS = [
        Binding("ctrl+c", "quit", "quit", show=False),
        Binding("ctrl+d", "quit", "quit", show=False),
        Binding("ctrl+l", "clear", "clear", show=False),
        Binding("escape", "stop", "stop", show=False, priority=True),
        Binding("tab", "complete", "complete", show=False, priority=True),
        Binding("up", "history_prev", "history", show=False, priority=True),
        Binding("down", "history_next", "history", show=False, priority=True),
    ]

    def __init__(self, ctx):
        super().__init__()
        self.ctx = ctx
        self.state = ctx["state"]
        self._pending = None          # (kind, payload) awaiting the next line
        self._authorized: set = set()
        self._busy = False
        # live run indicator (driven by a UI-thread timer; the worker just posts data)
        self._spin_timer = None
        self._spin = 0
        self._rp_step = ""
        self._rp_tools = 0
        self._rp_tail = ""
        self._rp_t0 = 0.0
        self._rp_target = ""
        self._rp_full = ""            # full streamed text for the live "thinking" region
        self._rp_tok = 0             # tokens streamed this generation — the "burn" counter
        self._rp_tok_t0 = None       # monotonic time of the first token → for tok/s
        self._rp_findings = 0        # evidence-gated findings so far this scan (live counter)
        self._rp_msgcount = -1       # transcript length last analysed → recount only on growth
        self._rp_toolseq: list = []  # real tool names in call order → the honest breadcrumb
        self._rp_rate_hist: list = []  # rolling tok/s samples → the live sparkline in #live
        self._rp_step_done = 0       # parsed from the real "step N/max" event (progress gauge)
        self._rp_step_total = 0
        self._rp_found_ids: set = set()  # finding ids already announced → detect NEW proofs
        self._agent = None           # live agent, handed over by cli._assess for the counter
        self._booting = False        # the cinematic boot overlay is playing (skippable)
        self._boot_timer = None
        self._boot_frame = 0
        self._flash_timer = None     # green finding-flash reset timer
        self._chat_mode = False
        self._chat_history: list = []   # conversational memory for the AI-assistant side
        self._cancel = threading.Event()   # set by Esc to stop the running assessment
        self._hint_matches: list = []   # slash commands currently shown in the /-hints popup
        self._resume_scan = None         # a scan parked waiting on a just-entered Claude key
        self._history: list = []         # submitted command lines, for ↑/↓ recall
        self._history_idx = None         # cursor into _history while browsing (None = at prompt)
        self._narrow = False             # width < _NARROW_W → single-column (dock/seam collapse)

    def compose(self) -> ComposeResult:
        yield Static("", id="hud")                    # the persistent NEXUS face (war-room HUD)
        with Horizontal(id="main"):
            with Vertical(id="leftcol"):
                yield RichLog(id="log", highlight=False, markup=True, wrap=True, auto_scroll=True)
                yield Static("", id="live")
            yield Static("", id="seam")               # the magenta evidence-gate seam · NE·X·US
            with VerticalScroll(id="findings"):
                yield Static("", id="dock")
        yield Static("", id="status")
        yield Static("", id="hints")
        yield Input(placeholder="type a target (example.com)  or  /help", id="cmd")
        yield Static("", id="boot")                   # cinematic boot overlay (on the 'boot' layer)

    # ---- helpers that run ON the UI thread ----

    def write_line(self, renderable):
        self.query_one("#log", RichLog).write(renderable)

    def set_status(self, text):
        # Wrap dynamic strings (step/thinking tail) in Text so brackets in the model's
        # reasoning are never mis-parsed as Rich markup.
        self.query_one("#status", Static).update(text if not isinstance(text, str) else Text(text))

    def write_findings(self, target, messages, report_path, elapsed, stopped=False):
        # The dock (blue-team side) carries the full evidence receipts; the transcript keeps a
        # compact completion line as a scrollback record. In single-column mode the dock is
        # hidden, so the full receipts are written into the stream instead — the proof must
        # never disappear just because the terminal is narrow.
        g, n = _dock_render(messages, final=True, elapsed=elapsed, report_path=report_path,
                            stopped=stopped)
        self.query_one("#dock", Static).update(g)      # keep the dock current (for wide / toggle-back)
        log = self.query_one("#log", RichLog)
        if self._narrow:
            log.write(Text(""))
            log.write(g)                               # dock hidden → the evidence lives inline
            self._end_run()
            return
        line = Text()
        line.append("\n■ assessment stopped" if stopped else "\n✓ assessment complete",
                    style=f"bold {S.AMBER if stopped else S.VERIFY}")
        line.append(f"  ·  {target}  ·  ", style=S.DIM)
        line.append(str(n), style=f"bold {S.INK}")
        line.append(" findings  ·  ", style=S.DIM)
        line.append("0 fabricated", style=f"bold {S.VERIFY}")
        line.append(f"  ·  {elapsed:.0f}s", style=S.DIM)
        log.write(line)
        if report_path:
            log.write(Text(f"  full report → {report_path}", style=S.FAINT))
        self._end_run()

    def _refresh_dock_live(self):
        """Repaint the evidence dock from the live transcript — called when the finding count
        changes so a proof lands in the blue-team panel the instant the gate credits it."""
        try:
            g, _ = _dock_render(self._agent.messages if self._agent else [])
            self.query_one("#dock", Static).update(g)
        except Exception:  # noqa: BLE001 — a live repaint must never break the run
            pass

    def _announce_findings(self, new_ids):
        """A finding just cleared the evidence gate — make the moment land: a green line in the
        transcript per new proof (in severity order), and a brief green pulse on the dock."""
        labels = {fid: label for fid, label, _ in findings._SPEC}
        order = [fid for fid, _, _ in findings._SPEC if fid in new_ids]
        order += [fid for fid in new_ids if fid not in labels]   # scanner ids keep their name
        for fid in order:
            line = Text("  ")
            line.append(f"{S.GLYPH['done']} evidence captured", style=f"bold {S.VERIFY}")
            line.append("  ·  ", style=S.DIM)
            line.append(labels.get(fid, str(fid)), style=S.INK)
            self.write_line(line)
        self._flash_finding()

    def _flash_finding(self):
        """Pulse the evidence dock green for a beat, then restore its hairline border."""
        try:
            self.query_one("#findings").styles.border = ("round", S.VERIFY)
            if self._flash_timer is not None:
                self._flash_timer.stop()
            self._flash_timer = self.set_timer(0.7, self._unflash)
        except Exception:  # noqa: BLE001 — cosmetic; never break the run
            pass

    def _unflash(self):
        self._flash_timer = None
        try:
            self.query_one("#findings").styles.border = ("round", S.LINE)
        except Exception:  # noqa: BLE001
            pass

    def _reset_dock(self, running=False):
        """The dock at rest: the evidence-gate promise as an invitation, not an empty box."""
        self.query_one("#findings").border_title = f"{S.GATE_GLYPH} evidence gate"
        head = Text()
        head.append(" 0 FABRICATED ", style=f"bold {S.VOID} on {S.VERIFY}")
        head.append("  the integrity guarantee", style=S.FAINT)
        if running:
            body = Text("\n\nassessing… awaiting the target's\nfirst proof.", style=S.FAINT)
        else:
            body = Text("\n\nno assessment running.\n\n", style=S.FAINT)
            body.append("Type a target on the left to begin.\nEvery finding here is proven by the\n"
                        "target's own response — never inferred.", style=S.FAINT)
        self.query_one("#dock", Static).update(Group(head, body))

    def _refresh_status(self):
        t = Text()
        t.append("● ", style=f"bold {S.VERIFY}")
        t.append(self.state["model"], style=f"bold {S.INK}")
        t.append(f" [{self.state['brain']}]", style="dim")
        fmt = self.state.get("format", "md")
        if fmt != "md":
            t.append(f"  · {fmt}", style=S.SKY)   # surface a non-default report format
        if self._narrow:                               # narrow terminal → keep the status bar short
            t.append("   ·   /help", style="dim")
        else:
            t.append("     ·     /help /model /key /format  ·  ↑ history  ·  ctrl-c quit",
                     style="dim")
        self.set_status(t)
        self._render_hud()

    def _render_hud(self):
        """The persistent NEXUS face at the top: the wordmark always, the live mission while a
        scan runs (target · real step gauge · tools · N found · 0 fabricated). Identity that
        never scrolls away — plus the payoff metric where it can't be missed."""
        t = S.wordmark()
        if self._busy and not self._chat_mode:
            tgt = self._rp_target or "—"
            if self._narrow and len(tgt) > 34:      # keep the payoff on-screen at 1 line
                tgt = tgt[:33] + "…"
            t.append("   ▸ ", style=S.DIM)
            t.append(tgt, style=f"bold {S.INK}")
            if not self._narrow:                    # gauge + tool count are the first to go narrow
                if self._rp_step_total:
                    t.append("   step ", style=S.DIM)
                    t.append(f"{self._rp_step_done}/{self._rp_step_total} ", style=S.FAINT)
                    t.append(S.progress_bar(self._rp_step_done, self._rp_step_total, 8), style=S.SKY)
                if self._rp_tools:
                    t.append(f"   {self._rp_tools} tools", style=S.DIM)
            t.append("   ● ", style=f"bold {S.VERIFY if self._rp_findings else S.GHOST}")
            t.append(f"{self._rp_findings} found",
                     style=f"bold {S.INK}" if self._rp_findings else S.DIM)
            t.append("  ·  0 fabricated", style=f"bold {S.VERIFY}")
        elif self._busy and self._chat_mode:
            t.append("   ▸ ", style=S.DIM)
            t.append("assistant", style=f"bold {S.BLUE}")
            t.append("  ·  thinking…", style=S.DIM)
        else:
            t.append("   ", style=S.DIM)
            t.append(self.state["model"], style=S.DIM)
            t.append(f" [{self.state['brain']}]", style=S.FAINT)
            t.append("   ·  ready", style=S.GHOST)
        try:
            self.query_one("#hud", Static).update(t)
        except Exception:  # noqa: BLE001 — cosmetic; never break on a layout hiccup
            pass

    # ---- live run indicator ----

    _SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def _rp(self, step=None, tool=False, tail=None):
        """Posted from the worker thread as the run progresses; the timer renders it."""
        if step is not None:
            self._rp_step = step
        if tool:
            self._rp_tools += 1
        if tail is not None:
            self._rp_tail = tail

    def _tick(self):
        if not self._busy:
            return
        frame = self._SPIN[self._spin % len(self._SPIN)]
        self._spin += 1
        now = time.monotonic()
        el = now - self._rp_t0
        rate = _tok_rate(self._rp_tok, self._rp_tok_t0, now)
        # Sample the live tok/s into a bounded history — the sparkline charts REAL burn.
        self._rp_rate_hist.append(rate)
        if len(self._rp_rate_hist) > 48:
            del self._rp_rate_hist[:-48]
        # Recount findings only when the transcript grew — cheap, and always current: it catches
        # the FINAL batch too, which an event-time count misses (results append after the event).
        ag = self._agent
        if ag is not None and len(ag.messages) != self._rp_msgcount:
            self._rp_msgcount = len(ag.messages)
            try:
                found = set(findings.analyze(ag.messages)[0])
            except Exception:  # noqa: BLE001 — a live counter must never break the UI
                found = None
            if found is not None:
                new_ids = found - self._rp_found_ids
                if new_ids:                      # NEW proofs cleared the gate → mark the moment
                    self._announce_findings(new_ids)
                    self._rp_found_ids = set(found)
                if len(found) != self._rp_findings:   # repaint the blue side the instant it lands
                    self._rp_findings = len(found)
                    self._refresh_dock_live()
        # --- bottom status: spinner + the live run counters (tok burn · tools · findings), so the
        # always-visible bar carries proof-of-life even when the HUD/#live panel scroll out of view ---
        t = Text()
        if self._chat_mode:
            t.append(frame + " ", style=S.BLUE)
            t.append("Nexus is thinking…", style="bold")
            cm = self._chat_model_name()
            if cm:
                t.append(f"   {cm}", style="dim")
            t.append(f"   {el:.0f}s", style="dim")
        else:
            t.append(frame + " ", style=S.RED)
            t.append(self._rp_target, style="bold")
            t.append(f"   {el:.0f}s", style="dim")
            if self._rp_tok:                        # live generation burn (tok/s omitted at dt≈0)
                t.append(f"  ·  {self._rp_tok} tok", style="dim")
                if rate:
                    t.append(f" ({rate:.0f} tok/s)", style="dim")
            if self._rp_tools:
                t.append(f"  ·  {self._rp_tools} tools", style="dim")
            t.append(f"  ·  {self._rp_findings} findings", style="dim")
            t.append("  ·  esc to stop", style="dim")
        if self._rp_tail:
            t.append("   ")
            t.append(self._rp_tail[-58:], style=S.GHOST)
        self.set_status(t)
        self._render_hud()   # push the live mission (target · step gauge · N found) to the face
        # --- the instrument panel (#live): a moving tok/s sparkline, the honest tool breadcrumb,
        # and the streamed reasoning — an actively-generating brain made unmistakable. ---
        live = self.query_one("#live", Static)
        live.border_title = f"{frame}  NEXUS · {'thinking' if self._chat_mode else 'assessing'}"
        header = Text()
        if self._rp_tok:
            header.append(f"⚡ {self._rp_tok} tok", style=f"bold {S.SKY}")
            if rate:
                header.append(f" · {rate:.0f}/s", style=S.SKY)
        else:
            header.append("⚡ warming up…", style=f"bold {S.SKY}")
        spark = S.sparkline(self._rp_rate_hist, width=36)
        if spark:
            header.append("  " + spark, style=S.SKY)
        header.append(f"    {el:.0f}s", style="dim")
        crumb = Text()
        if not self._chat_mode and self._rp_toolseq:      # real tools, in call order
            crumb.append(" → ".join(self._rp_toolseq[-5:]), style=S.FAINT)
        shown = _trim_cjk(self._rp_full)
        nlines = 4 if (not self._chat_mode and self._rp_toolseq) else 5
        body = Text("\n".join(shown[-1400:].splitlines()[-nlines:]), style="#aeb8cf")
        live.update(Group(header, crumb, body))

    def _end_run(self):
        if self._spin_timer is not None:
            self._spin_timer.stop()
            self._spin_timer = None
        self._busy = False
        self._chat_mode = False
        live = self.query_one("#live", Static)
        live.update("")
        live.display = False
        self._refresh_status()

    def on_mount(self):
        cmd = self.query_one("#cmd", Input)
        cmd.border_title = "nexus ❯"
        # Focus is granted only AFTER the boot animation settles (see _settle_intro), so a key
        # pressed to skip the intro doesn't leak a stray character into the input box.
        self._reset_dock()
        self._render_hud()
        self.call_after_refresh(self._apply_responsive)
        self.call_after_refresh(self._render_seam)
        # Draw the intro AFTER the first layout, when the log's real width is known — otherwise
        # size.width is 0 and the banner centers for a wrong width.
        self.call_after_refresh(self._intro)
        self.run_worker(self._boot, thread=True)

    def on_resize(self, _event=None):
        # Re-evaluate the layout tier first (it may hide/show the dock), then repaint the seam,
        # which is drawn as text sized to the live panel height.
        self._apply_responsive()
        self._render_seam()

    # Below this width the two-column war-room can't give BOTH panes a comfortable size (the
    # transcript starts clipping the longest reasoning lines), so the console drops to a single
    # column: the transcript takes the full width and the blue-team dock + seam collapse. The
    # evidence still lands inline, and full receipts are written into the stream on completion
    # (see write_findings). At >= this width the transcript keeps >= ~65 cols — clean side-by-side.
    _NARROW_W = 110

    def _apply_responsive(self):
        try:
            w = self.size.width or 0
        except Exception:  # noqa: BLE001
            return
        if w <= 0:
            return
        narrow = w < self._NARROW_W
        self._narrow = narrow
        try:
            self.query_one("#seam").display = not narrow
            self.query_one("#findings").display = not narrow
        except Exception:  # noqa: BLE001 — widgets may not exist yet during boot
            pass

    def _render_seam(self):
        if self._narrow:                    # seam is hidden in single-column mode
            return
        try:
            seam = self.query_one("#seam", Static)
            seam.update(S.seam_text(seam.size.height or 0))
        except Exception:  # noqa: BLE001 — decorative; never break on a layout hiccup
            pass

    # ---- cinematic boot: the wordmark ignites, subsystems come online, then it settles ----

    def _intro(self):
        try:
            self._start_boot()
        except Exception:  # noqa: BLE001 — any trouble → skip straight to the settled banner
            self._settle_intro()

    def _start_boot(self):
        boot = self.query_one("#boot", Static)
        self._booting = True
        self._boot_frame = 0
        boot.display = True
        boot.update(self._boot_render())
        self._boot_timer = self.set_interval(0.05, self._boot_tick)

    _BOOT_CHECKS = 3
    _BOOT_COLS_PER_FRAME = 3

    def _boot_tick(self):
        self._boot_frame += 1
        art_w = max(len(line) for line in _NEXUS_ART)
        reveal_frames = art_w // self._BOOT_COLS_PER_FRAME + 1
        # reveal wordmark (left→right), then light up the checks, then hold a beat, then finish
        if self._boot_frame > reveal_frames + self._BOOT_CHECKS * 2 + 4:
            self._finish_boot()
            return
        try:
            self.query_one("#boot", Static).update(self._boot_render())
        except Exception:  # noqa: BLE001
            self._finish_boot()

    def _boot_render(self):
        art_w = max(len(line) for line in _NEXUS_ART)
        reveal_frames = art_w // self._BOOT_COLS_PER_FRAME + 1
        reveal = self._boot_frame * self._BOOT_COLS_PER_FRAME
        too_narrow = (self.size.width or 80) < art_w + 2   # block art won't fit → mini wordmark
        wm = S.wordmark() if too_narrow else _gradient_banner_reveal(reveal)
        parts = [wm, Text("")]
        if self._boot_frame >= reveal_frames:
            sub = Text("autonomous red + blue security assessment", style=S.DIM)
            parts += [sub, Text("")]
            shown = min(self._BOOT_CHECKS, (self._boot_frame - reveal_frames) // 2 + 1)
            checks = [
                ("brain", f"{self.state['model']}  [{self.state['brain']}]"),
                ("scope", "authorized targets only"),
                ("evidence gate", "0 fabricated · proof-gated"),
            ]
            for i in range(shown):
                label, val = checks[i]
                line = Text()
                line.append("● ", style=f"bold {S.VERIFY}")
                line.append(f"{label:<14}", style=S.INK)
                line.append(val, style=S.FAINT)
                parts.append(line)
        return Group(*parts)

    def on_key(self, event):
        # Any key skips the boot animation straight to the settled banner (and is swallowed so
        # it doesn't leak into the input box).
        if self._booting:
            self._finish_boot()
            event.stop()
            event.prevent_default()

    def _finish_boot(self):
        if not self._booting:
            return
        self._booting = False
        if self._boot_timer is not None:
            self._boot_timer.stop()
            self._boot_timer = None
        try:
            boot = self.query_one("#boot", Static)
            boot.update("")
            boot.display = False
        except Exception:  # noqa: BLE001
            pass
        self._settle_intro()

    def _settle_intro(self):
        # A pending boot tick can land after the app is torn down (a fast test or a quit during
        # the ~1.3s boot): the widgets are gone, so there is nothing to settle — bail, don't raise.
        try:
            log = self.query_one("#log", RichLog)
        except Exception:  # noqa: BLE001
            return
        w = log.size.width or 80

        def centered(s, markup):
            pad = max(0, (w - len(s)) // 2)
            return Text(" " * pad) + (Text.from_markup(markup) if markup else Text(s, style="dim"))

        art_w = max(len(line) for line in _NEXUS_ART)
        if w < art_w + 2:                       # too narrow for the block art → the mini wordmark
            wm = S.wordmark()
            log.write(Text(" " * max(0, (w - len(wm.plain)) // 2)) + wm)
        else:
            log.write(_gradient_banner(max(0, (w - art_w) // 2)))
        sub = "autonomous red + blue security assessment · authorized scope only"
        log.write(centered(sub, f"[dim]{sub}[/dim]"))
        hint = "Type a target to scan, ask a question, or /help."
        log.write(Text(""))
        log.write(centered(hint, "Type a [cyan]target[/cyan] to scan, "
                                 "[blue]ask a question[/blue], or [cyan]/help[/cyan]."))
        lic = self.ctx.get("license_status", lambda: "")()
        if lic:
            log.write(centered(lic, f"[dim]{escape(lic)}[/dim]"))
        log.write(Text(""))
        self._refresh_status()
        self._render_hud()
        with contextlib.suppress(Exception):
            self.query_one("#cmd", Input).focus()

    def _boot(self):
        if not self._brain_ready():
            self.call_from_thread(self._setup_hint)

    def _brain_ready(self) -> bool:
        b = self.state["brain"]
        if b == "ollama":
            if not self.ctx["ensure_server"](self.state["ollama_url"]):
                return False
            return self.state["model"] in self.ctx["models"](self.state["ollama_url"])
        if b == "claude":
            return self.ctx["has_key"]()
        return True

    def _setup_hint(self):
        m = escape(self.state["model"])
        self.write_line(Panel(Text.from_markup(
            "To run a scan, Nexus needs a model brain:\n"
            f"• [b]Ollama[/b] (free, local): install from https://ollama.com, then "
            f"[b]ollama pull {m}[/b] — or [cyan]/model[/cyan] to pick one you already have.\n"
            "• [b]Claude[/b]: set ANTHROPIC_API_KEY, then [cyan]/model[/cyan] → claude.\n"
            "[dim]Meanwhile you can still ask me questions right here.[/dim]"),
            title="getting started", border_style=S.AMBER, box=ROUNDED, padding=(1, 2)))

    def action_clear(self):
        self.query_one("#log", RichLog).clear()
        self._reset_dock()
        self._intro()

    def action_stop(self):
        if not self._busy:
            return
        if self._chat_mode:
            self.write_line(Text.from_markup(
                "[dim]…finishing the reply (a chat answer can't be interrupted).[/dim]"))
        else:
            self._cancel.set()
            self.write_line(Text.from_markup(
                "[yellow]■ stopping — halting after the current step…[/yellow]"))

    # ---- input handling ----

    def _echo_user(self, line):
        """Echo the user's own input into the output pane, visibly set apart — a red chip
        marker and bright bold text — so the conversation reads like Claude Code / Gemini."""
        t = Text()
        t.append("\n")
        t.append(" ❯ ", style=f"bold #ffffff on {S.RED}")
        t.append("  " + line, style="bold #eef1fa")
        self.write_line(t)

    def _echo_masked(self):
        """Echo a redacted marker instead of the real text — used when a secret (API key) was
        just entered, so it never lands in the scrollback."""
        t = Text()
        t.append("\n")
        t.append(" ❯ ", style=f"bold #ffffff on {S.RED}")
        t.append("  ••••••••••••", style="bold #6a7080")
        self.write_line(t)

    def on_input_submitted(self, event: "Input.Submitted"):
        line = event.value.strip()
        self.query_one("#cmd", Input).value = ""
        self._hide_hints()
        # An API key is being entered — never echo it in the clear, and allow an empty line to
        # cancel. Everything else ignores an empty submit.
        secret = bool(self._pending) and self._pending[0] in ("apikey", "setkey")
        if not line and not secret:
            return
        if secret:
            self._echo_masked()          # secrets are never recalled — keep them out of history
            self._resume(line)
            return
        self._remember(line)
        self._echo_user(line)
        if self._busy:
            self.write_line(Text.from_markup("[dim]…busy, one assessment at a time.[/dim]"))
            return
        if self._pending:
            self._resume(line)
            return
        if line.startswith("/"):
            self._command(line)
            return
        # A message naming a host/URL → REAL scan (never let the chat model fabricate results
        # about a system); a plain question → chat. Natural language works: "check example.com".
        target = self.ctx["extract_target"](line)
        if target:
            objective = line if line.strip() != target else None
            self._begin_target(target, objective)
        else:
            self._begin_chat(line)

    # ---- slash-command hints (a popup above the input as you type "/") ----

    def on_input_changed(self, event: "Input.Changed"):
        val = event.value
        # Only while idle at a fresh prompt — never over a running scan or a pending answer
        # (e.g. the API-key entry), where "/" isn't a command.
        # Hints help you complete the command NAME; once you type a space you're on to its
        # args, so the popup gets out of the way.
        if val.startswith("/") and " " not in val and not self._busy and not self._pending:
            self._show_hints(val)
        else:
            self._hide_hints()
        self._update_mode_title(val)

    def _update_mode_title(self, val):
        """The input's border title doubles as a mode affordance: it reads 'scan' when the text
        names a host/URL, 'ask' when it's a plain question — so you know which path Enter takes."""
        if self._pending or self._busy:
            return                      # don't fight key-entry / a running scan
        try:
            cmd = self.query_one("#cmd", Input)
        except Exception:  # noqa: BLE001
            return
        v = val.strip()
        if not v or v.startswith("/"):
            cmd.border_title = "nexus ❯"
        elif self.ctx["extract_target"](v):
            cmd.border_title = "nexus ❯ scan"
        else:
            cmd.border_title = "nexus ❯ ask"

    def _show_hints(self, val):
        token = (val.split() or ["/"])[0].lower()
        # a bare "/" lists everything; otherwise prefix-match the command name
        matches = [(c, d) for c, d in _HELP
                   if c.startswith("/") and (token == "/" or c.startswith(token))]
        self._hint_matches = matches
        if not matches:
            self._hide_hints()
            return
        t = Table.grid(padding=(0, 2))
        t.add_column(style="cyan", no_wrap=True)
        t.add_column(style="dim")
        for c, d in matches:
            t.add_row(c, d)
        hints = self.query_one("#hints", Static)
        hints.update(t)
        hints.display = True

    def _hide_hints(self):
        self._hint_matches = []
        try:
            hints = self.query_one("#hints", Static)
            hints.update("")
            hints.display = False
        except Exception:  # noqa: BLE001 — widget may not exist yet during boot
            pass

    def action_complete(self):
        """Tab accepts the top hint: fill the input with that command, ready for its args."""
        if not self._hint_matches:
            return
        cmd = self._hint_matches[0][0]
        inp = self.query_one("#cmd", Input)
        inp.value = cmd + " "
        with contextlib.suppress(Exception):
            inp.cursor_position = len(inp.value)
        self._hide_hints()

    # ---- command history (↑/↓ recall, like a shell / Claude Code) ----

    def action_history_prev(self):
        """↑ — step back to older submitted lines."""
        if not self._history or self._pending:   # don't hijack ↑ while answering a prompt
            return
        if self._history_idx is None:
            self._history_idx = len(self._history)
        if self._history_idx > 0:
            self._history_idx -= 1
            self._set_from_history()

    def action_history_next(self):
        """↓ — step forward toward the live prompt; past the newest entry clears the input."""
        if self._history_idx is None or self._pending:
            return
        self._history_idx += 1
        if self._history_idx >= len(self._history):
            self._history_idx = None
            self.query_one("#cmd", Input).value = ""
        else:
            self._set_from_history()

    def _set_from_history(self):
        inp = self.query_one("#cmd", Input)
        inp.value = self._history[self._history_idx]
        with contextlib.suppress(Exception):
            inp.cursor_position = len(inp.value)
        self._hide_hints()

    def _remember(self, line):
        """Record a submitted line for recall — skip consecutive duplicates, reset the cursor."""
        if not self._history or self._history[-1] != line:
            self._history.append(line)
        self._history_idx = None

    def _command(self, line):
        parts = line[1:].split(None, 1)
        cmd = parts[0].lower() if parts else ""
        rest = parts[1].strip() if len(parts) > 1 else ""
        if cmd in ("quit", "exit", "q"):
            self.exit()
        elif cmd in ("help", "h", "?", ""):
            t = Table.grid(padding=(0, 2))
            t.add_column(style="cyan", no_wrap=True)
            t.add_column(style="dim")
            for c, d in _HELP:
                t.add_row(c, d)
            self.write_line(Panel(t, title="commands", border_style=S.GHOST, box=ROUNDED))
        elif cmd == "clear":
            self.action_clear()
        elif cmd in ("model", "brain"):
            self._show_models()
        elif cmd == "format":
            self._format(rest)
        elif cmd == "key":
            self._prompt_key()
        elif cmd == "scope":
            self._scope(rest)
        elif cmd == "report":
            self._report()
        elif cmd == "defend":
            self._begin_defender("defend")
        elif cmd == "guard":
            self._begin_defender("guard")
        elif cmd == "estate":
            self._begin_defender("estate", rest.strip())
        else:
            self.write_line(Text.from_markup(f"[dim]unknown command /{cmd} — try /help[/dim]"))

    # ---- defender (blue-team): attach to a host/estate you own and show its posture ----

    def _begin_defender(self, kind, arg=""):
        """Run a read-only defender pass off the UI thread (a host sweep spawns PowerShell and can
        take a couple of seconds), then render the posture / brief / proposals as panels. Nothing
        is ever changed — proposals only."""
        if self._busy:
            return
        self._busy = True
        note = {"defend": "defending this host", "guard": "checking what changed",
                "estate": "rolling up the estate"}.get(kind, "defending")
        live = self.query_one("#live", Static)
        live.update(Text(f"  ⏳ {note} — read-only introspection…", style=S.DIM))
        live.display = True
        self.run_worker(lambda: self._defender_run(kind, arg), thread=True)

    def _defender_run(self, kind, arg):
        try:
            blocks = self.ctx["estate"](arg) if kind == "estate" else self.ctx[kind]()
            self.call_from_thread(self._write_defender, kind, blocks)
        except Exception as e:  # noqa: BLE001 — a worker crash must never take the app down
            self.call_from_thread(self.write_line, Text.from_markup(
                f"[red]defender error:[/red] {escape(str(e))}"))
        finally:
            self.call_from_thread(self._end_run)

    def _write_defender(self, kind, blocks):
        head = {"defend": "▸ host defence", "guard": "▸ guardian check",
                "estate": "▸ estate posture"}.get(kind, "▸ defence")
        self.write_line(Text.from_markup(
            f"\n[bold]{head}[/bold]  [dim]· read-only · proposals only, nothing is applied[/dim]"))
        # RichLog's own wrap uses the full region width, so a long report line h-scrolls its tail
        # off the edge (past the padding + scrollbar — see _write_chat). Pre-fold to the VISIBLE
        # columns so every character stays inside the pane.
        log = self.query_one("#log", RichLog)
        width = max(24, (log.size.width or 80) - 4)
        for title, body in blocks:
            hdr = Text()
            hdr.append("── ", style=S.FAINT)
            hdr.append(str(title), style=f"bold {S.SKY}")
            hdr.append(" ──", style=S.FAINT)
            self.write_line(hdr)
            for line in str(body).strip("\n").split("\n"):
                # Text() (not from_markup) keeps the report's brackets — [NEW], [High] — literal.
                for row in self._fold_line(line, width):
                    self.write_line(Text(row))

    @staticmethod
    def _fold_line(line, width):
        """Character-fold one report line to `width`, lossless (keeps its exact spacing/alignment),
        with a hanging indent on continuations so a wrapped row still reads as part of its entry."""
        if len(line) <= width or not line.strip():
            return [line or ""]
        stripped = line.lstrip(" ")
        indent = line[:len(line) - len(stripped)]
        avail = max(8, width - len(indent) - 2)
        rows, first = [], True
        while stripped:
            chunk, stripped = stripped[:avail], stripped[avail:]
            rows.append((indent if first else indent + "  ") + chunk)
            first = False
        return rows

    def _show_models(self):
        rows = [("ollama", m) for m in self.ctx["models"](self.state["ollama_url"])]
        rows.append(("claude", self.ctx.get("claude_model", "claude-opus-5")))
        rows.append(("local", "tuned offline brain (Pro)"))
        t = Table(box=ROUNDED, border_style=S.GHOST, show_header=True, header_style="dim")
        t.add_column("#", justify="right", style="cyan")
        t.add_column("model")
        t.add_column("brain", style="dim")
        t.add_column("", style="green")
        for i, (br, mdl) in enumerate(rows, 1):
            mark = "← current" if (br, mdl) == (self.state["brain"], self.state["model"]) else ""
            t.add_row(str(i), mdl, br, mark)
        self.write_line(t)
        self.write_line(Text.from_markup("[dim]type a number to switch model[/dim]"))
        self._pending = ("model", rows)

    def _prompt_key(self):
        """/key — set or replace the Anthropic API key without switching the model."""
        have = self.ctx["has_key"]()
        verb = "Replace" if have else "Set"
        self.write_line(Text.from_markup(
            f"[cyan]{verb} the Anthropic API key.[/cyan] Paste it "
            "[dim](sk-ant-… — hidden; Enter alone to cancel)[/dim]:"))
        inp = self.query_one("#cmd", Input)
        inp.password = True
        inp.placeholder = "sk-ant-…"
        self._pending = ("setkey", None)

    _FORMATS = ("md", "sarif", "json")

    def _format(self, rest):
        cur = self.state.get("format", "md")
        choice = rest.strip().lower()
        if not choice:
            self.write_line(Text.from_markup(
                f"[dim]report format:[/dim] [b]{cur}[/b]  "
                f"[dim]— set with[/dim] /format md|sarif|json"))
            return
        if choice not in self._FORMATS:
            self.write_line(Text.from_markup(
                f"[yellow]unknown format {escape(choice)}[/yellow] "
                "[dim]— choose md, sarif, or json.[/dim]"))
            return
        self.state["format"] = choice
        note = {"md": "human report", "sarif": "SARIF 2.1.0 for GitHub / CI",
                "json": "structured findings"}[choice]
        self.write_line(Text.from_markup(
            f"[green]✓ report format → {choice}[/green] [dim]({note})[/dim]"))

    def _scope(self, rest):
        if not rest:
            cur = ", ".join(self.state["extra_scope"]) or "(just the target you type)"
            self.write_line(Text.from_markup(f"[dim]extra scope:[/dim] {escape(cur)}"))
            return
        if rest.lower() in ("none", "clear", "reset"):
            self.state["extra_scope"] = []
            self.write_line(Text.from_markup("[green]extra scope cleared.[/green]"))
            return
        for s in (x.strip() for x in rest.replace(",", " ").split()):
            if s and s not in self.state["extra_scope"]:
                self.state["extra_scope"].append(s)
        self.write_line(Text.from_markup(
            f"[green]extra scope:[/green] {escape(', '.join(self.state['extra_scope']))}"))

    def _report(self):
        path = self.state.get("last_report")
        if not path or not self.ctx["exists"](path):
            self.write_line(Text.from_markup("[dim]no report yet — assess a target first.[/dim]"))
            return
        text = self.ctx["read"](path)
        if text is None:
            return
        # Render by format: a SARIF/JSON report is machine data — show it as highlighted JSON,
        # not through the Markdown renderer (which mangles the braces into garbage).
        low = path.lower()
        if low.endswith((".sarif", ".json")):
            try:
                from rich.syntax import Syntax
                self.write_line(Syntax(text, "json", theme="ansi_dark",
                                       word_wrap=True, background_color="default"))
            except Exception:  # noqa: BLE001 — fall back to plain text
                self.write_line(Text(text))
        else:
            from rich.markdown import Markdown
            self.write_line(Markdown(text))

    def _resume(self, line):
        kind, payload = self._pending
        self._pending = None
        if kind == "model":
            rows = payload
            if line.isdigit() and 1 <= int(line) <= len(rows):
                br, mdl = rows[int(line) - 1]
                if br == "claude" and not self.ctx["has_key"]():
                    # Let the user paste the key right here instead of sending them to a shell.
                    self.write_line(Text.from_markup(
                        "[cyan]Claude selected.[/cyan] Paste your Anthropic API key "
                        "[dim](starts with sk-ant-… — hidden as you type; Enter alone to "
                        "cancel)[/dim]:"))
                    self.write_line(Text.from_markup(
                        "[dim]Get one at https://console.anthropic.com/settings/keys[/dim]"))
                    inp = self.query_one("#cmd", Input)
                    inp.password = True
                    inp.placeholder = "sk-ant-…"
                    self._pending = ("apikey", (br, mdl))
                    return
                self.state["brain"], self.state["model"] = br, mdl
                self.ctx["save_model"](br, mdl)
                self.write_line(Text.from_markup(
                    f"[green]✓ model → {escape(mdl)} {escape('[' + br + ']')}[/green]"))
                self._refresh_status()
            else:
                self.write_line(Text.from_markup("[dim]unchanged.[/dim]"))
        elif kind == "apikey":
            br, mdl = payload
            inp = self.query_one("#cmd", Input)
            inp.password = False
            inp.placeholder = "type a target (example.com)  or  /help"
            # A scan may be parked waiting on this key (see _start). Pop it either way so a
            # cancel doesn't silently launch it later.
            resume_scan = getattr(self, "_resume_scan", None)
            self._resume_scan = None
            if not line:
                self.write_line(Text.from_markup("[dim]cancelled — no key entered.[/dim]"))
                return
            ok, msg = self.ctx["set_api_key"](line)
            if ok:
                self.state["brain"], self.state["model"] = br, mdl
                self.ctx["save_model"](br, mdl)
                self.write_line(Text.from_markup(
                    f"[green]✓ {escape(msg)}  model → {escape(mdl)} [claude][/green]"))
                self._refresh_status()
                if resume_scan:                     # key was needed to start a scan — start it now
                    self._start(*resume_scan)
            else:
                self.write_line(Text.from_markup(
                    f"[yellow]{escape(msg)}[/yellow] [dim]model unchanged — try /model "
                    "again.[/dim]"))
        elif kind == "setkey":
            inp = self.query_one("#cmd", Input)
            inp.password = False
            inp.placeholder = "type a target (example.com)  or  /help"
            if not line:
                self.write_line(Text.from_markup("[dim]cancelled — key unchanged.[/dim]"))
                return
            ok, msg = self.ctx["set_api_key"](line)
            style = "green" if ok else "yellow"
            mark = "✓ " if ok else ""
            self.write_line(Text.from_markup(f"[{style}]{mark}{escape(msg)}[/{style}]"))
        elif kind == "auth":
            target, objective = payload
            if line.lower() in ("y", "yes"):
                if self.ctx["is_external"](target):
                    self.write_line(Text.from_markup(
                        f"[yellow]{escape(target)} is a public-internet target.[/yellow] Confirm "
                        "automated testing is permitted by its program rules — type [b]yes[/b]."))
                    self._pending = ("rules", (target, objective))
                    return
                self._authorized.add(self._host(target))
                self._start(target, False, objective)
            else:
                self.write_line(Text.from_markup("[dim]cancelled.[/dim]"))
        elif kind == "rules":
            target, objective = payload
            if line.lower() in ("y", "yes"):
                self._authorized.add(self._host(target))
                self._start(target, True, objective)
            else:
                self.write_line(Text.from_markup("[dim]rules not confirmed — cancelled.[/dim]"))

    def _host(self, target):
        return self.ctx["scope_host"](target)

    def _begin_target(self, target, objective=None):
        if self._host(target) in self._authorized:
            self._start(target, self.ctx["is_external"](target), objective)
            return
        obj_note = ""
        if objective:
            obj_note = f"  [dim]— {escape(objective)}[/dim]"
        self.write_line(Text.from_markup(
            f"[yellow]?[/yellow] Assess [b]{escape(target)}[/b]?{obj_note}\nNexus only tests systems "
            "you own or are authorized to test. Type [b]yes[/b] to confirm."))
        self._pending = ("auth", (target, objective))

    def _ollama_ready(self, model):
        """Ensure the server is up and the model is present — WITHOUT an inline `ollama pull`,
        which would freeze the UI and corrupt the screen with a progress bar. Guides instead."""
        if not self.ctx["ensure_server"](self.state["ollama_url"]):
            self.write_line(Text.from_markup(
                "[red]Ollama isn't available.[/red] install it from https://ollama.com"))
            return False
        if model not in self.ctx["models"](self.state["ollama_url"]):
            self.write_line(Text.from_markup(
                f"[yellow]model {escape(model)} isn't installed.[/yellow] run "
                f"[b]ollama pull {escape(model)}[/b] in a terminal, or [cyan]/model[/cyan] "
                "to pick one you already have."))
            return False
        return True

    def _start(self, target, rules, objective=None):
        if self.state["brain"] == "ollama" and not self._ollama_ready(self.state["model"]):
            return
        # Claude brain with no key: don't launch a scan that can only fail deep in the worker
        # with a cryptic error. Ask for the key right here; once it's saved, resume this scan.
        if self.state["brain"] == "claude" and not self.ctx["has_key"]():
            self.write_line(Text.from_markup(
                "[cyan]Claude needs an API key before it can scan.[/cyan] Paste your Anthropic "
                "key [dim](sk-ant-… — hidden; Enter alone to cancel)[/dim]:"))
            inp = self.query_one("#cmd", Input)
            inp.password = True
            inp.placeholder = "sk-ant-…"
            self._resume_scan = (target, rules, objective)
            self._pending = ("apikey", ("claude", self.ctx.get("claude_model", "claude-opus-5")))
            return
        self.write_line(Text.from_markup(
            f"\n[bold]▸ assessing[/bold] {escape(target)}  "
            f"[dim]· {escape(self.state['model'])} {escape('[' + self.state['brain'] + ']')}[/dim]"))
        self.state["last_target"] = target
        self._busy = True
        self._rp_step, self._rp_tools, self._rp_tail, self._rp_full = "starting", 0, "", ""
        self._rp_t0, self._rp_target = time.monotonic(), target
        self._rp_tok, self._rp_tok_t0 = 0, None
        self._rp_findings, self._agent, self._rp_msgcount = 0, None, -1
        self._rp_toolseq, self._rp_rate_hist = [], []
        self._rp_step_done, self._rp_step_total = 0, 0
        self._rp_found_ids = set()
        self._reset_dock(running=True)
        self.query_one("#live", Static).display = True
        self._cancel.clear()
        self._spin_timer = self.set_interval(0.1, self._tick)
        self.run_worker(lambda: self._run(target, rules, objective), thread=True)

    def _chat_model_name(self):
        """Resolved chat-model name for the status line. Cached — the resolver may hit Ollama
        over HTTP, and _tick fires ~10×/s."""
        cached = getattr(self, "_chat_model_cache", None)
        if cached is not None:
            return cached
        name = ""
        try:
            fn = self.ctx.get("chat_model")
            if fn:
                name = fn() or ""
        except Exception:  # noqa: BLE001 — status cosmetics must never break the run
            name = ""
        self._chat_model_cache = name
        return name

    _CHAT_MEMORY_MAX = 16   # keep conversational memory bounded so context stays small

    def _remember_chat(self, role, content):
        """Append a chat turn and cap the history — every path (LLM reply AND the deterministic
        scan hand-off) goes through here so memory can't grow unbounded on any branch."""
        self._chat_history.append({"role": role, "content": content})
        if len(self._chat_history) > self._CHAT_MEMORY_MAX:
            self._chat_history = self._chat_history[-self._CHAT_MEMORY_MAX:]

    def _begin_chat(self, msg):
        """Non-target input → talk to the AI assistant (with memory), streamed live."""
        handoff = self.ctx.get("scan_handoff", lambda t: None)(msg)
        if handoff:      # "check my site" with no URL → deterministic, honest hand-off (no LLM)
            self._remember_chat("user", msg)
            self._remember_chat("assistant", handoff)
            self._write_chat(handoff)
            return
        self._remember_chat("user", msg)
        self._chat_model_cache = None  # re-resolve once (model may have changed via /model)
        self._busy = True
        self._chat_mode = True
        self._rp_tail, self._rp_full, self._rp_t0 = "", "", time.monotonic()
        self._rp_tok, self._rp_tok_t0 = 0, None
        self._rp_rate_hist = []
        self.query_one("#live", Static).display = True
        self._spin_timer = self.set_interval(0.1, self._tick)
        self.run_worker(self._run_chat, thread=True)

    def _run_chat(self):
        buf = []

        def on_delta(chunk):
            buf.append(chunk)
            full = "".join(buf)
            self._rp_full = full
            self._rp_tail = " ".join(full.split())
            if self._rp_tok_t0 is None:
                self._rp_tok_t0 = time.monotonic()
            self._rp_tok += 1

        try:
            answer = self.ctx["chat"](list(self._chat_history), on_delta)
        except Exception as e:  # noqa: BLE001
            answer = f"⚠ {type(e).__name__}: {e}"
        self._remember_chat("assistant", answer)
        self.call_from_thread(self._write_chat, answer)
        self.call_from_thread(self._end_run)

    def _write_chat(self, answer):
        chip = Text("\n")
        chip.append(" Nexus ", style=f"bold white on {S.BLUE}")   # blue chip (assistant) vs red (you)
        self.write_line(chip)
        # Pre-wrap the reply and emit one short line per row. A long renderable (Text, grid,
        # even with an explicit width) gets laid out at RichLog's region width — wider than what's
        # actually shown once padding + the vertical scrollbar are taken — so its tail h-scrolls
        # off the edge. Short per-row Texts always land inside the viewport, so this never clips.
        log = self.query_one("#log", RichLog)
        w = max(24, log.size.width - 4)     # visible text columns (outer − padding − scrollbar − margin)
        for para in answer.split("\n"):
            if not para.strip():
                self.write_line(Text(""))
                continue
            for line in textwrap.wrap(para, width=w) or [""]:
                self.write_line(Text(line, style="#c6d2e8"))

    def _run(self, target, rules, objective=None):
        present = _AppPresenter(self)
        try:
            # ctx["assess"] picks a unique per-scan report path and sets state["last_report"].
            rc = self.ctx["assess"](target, list(self.state["extra_scope"]), rules, present,
                                    objective=objective, should_stop=self._cancel.is_set)
            if rc and rc != 0:   # brain error / early exit — _assess didn't render a summary
                self.call_from_thread(self.write_line, Text.from_markup(
                    "[red]the run stopped early (brain/tool error) — see above.[/red]"))
        except Exception as e:  # noqa: BLE001 — never let a worker crash take down the app
            self.call_from_thread(self.write_line, Text.from_markup(
                f"[red]run error: {escape(type(e).__name__ + ': ' + str(e))}[/red]"))
        finally:
            # ALWAYS end the run — a non-zero return (Ollama died mid-scan) never reached the
            # summary that normally calls _end_run, which would leave the spinner spinning forever.
            if self._busy:
                self.call_from_thread(self._end_run)


def run(ctx) -> int:
    NexusApp(ctx).run()
    return 0
