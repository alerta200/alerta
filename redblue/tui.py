"""tui.py — an optional rich terminal experience (rich + prompt_toolkit).

The stdlib core never imports this. cli.py uses it only when the extras are installed
(`pip install nexus-sec[tui]`); otherwise it falls back to the plain ANSI REPL, so the
air-gapped core stays dependency-free. Everything here is presentation only.
"""

from __future__ import annotations

from . import findings

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.box import ROUNDED
    from rich.markdown import Markdown
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.formatted_text import HTML
    _HAVE = True
except Exception:  # noqa: BLE001 — any import trouble means "no TUI", fall back cleanly
    _HAVE = False
    # Stand-in base so the _SlashCompleter class below still DEFINES without prompt_toolkit
    # installed (it's never instantiated in that case — cli.py checks available() first).
    Completer = object


def available() -> bool:
    return _HAVE


# Severity → rich style, shared by the stream and the findings table.
_SEV_STYLE = {"Critical": "bold red", "High": "red", "Medium": "yellow",
              "Low": "yellow", "Info": "cyan"}

SLASH = {
    "/model": "switch the brain / model",
    "/format": "report format: md · sarif · json",
    "/key": "set or replace the Anthropic API key",
    "/scope": "show or add extra in-scope hosts",
    "/report": "show the last full report",
    "/help": "show the commands",
    "/clear": "clear the screen",
    "/quit": "exit Nexus",
}


def render_markdown(con, text: str) -> None:
    con.print(Markdown(text))


def model_table(con, rows, current) -> None:
    t = Table(box=ROUNDED, border_style="dim", show_header=True, header_style="dim")
    t.add_column("#", justify="right", style="cyan", no_wrap=True)
    t.add_column("model")
    t.add_column("brain", style="dim")
    t.add_column("", style="green")
    for i, (br, mdl) in enumerate(rows, 1):
        mark = "← current" if (br, mdl) == current else ""
        t.add_row(str(i), mdl, br, mark)
    con.print(t)


def console() -> "Console":
    # legacy_windows=False → rich emits ANSI to the (UTF-8-reconfigured) stdout instead of the
    # win32 console API, so box-drawing/·/→ never hit a legacy cp1251 codepage and crash.
    return Console(highlight=False, legacy_windows=False)


def banner(con, brain: str, model: str) -> None:
    title = Text()
    title.append("NE", style="bold red")
    title.append("·", style="magenta")
    title.append("X", style="bold magenta")
    title.append("·", style="magenta")
    title.append("US", style="bold blue")
    title.append("   autonomous red + blue security assessment", style="dim")
    body = Text.from_markup(
        "Assess systems you own or are authorized to test. Type a [cyan]target[/cyan] "
        "to begin,\nor a command like [cyan]/model[/cyan]. [dim]/help for more.[/dim]")
    con.print(Panel(body, title=title, border_style="red", box=ROUNDED, padding=(1, 2)))
    con.print(f"  [dim]model[/dim] {model} [dim][{brain}][/dim]\n")


class _SlashCompleter(Completer):
    def get_completions(self, document, complete_event):
        text = document.text_before_cursor
        if not text.startswith("/"):
            return
        for cmd, desc in SLASH.items():
            if cmd.startswith(text):
                yield Completion(cmd, start_position=-len(text), display_meta=desc)


def make_session(history_path) -> "PromptSession":
    try:
        hist = FileHistory(str(history_path))
    except Exception:  # noqa: BLE001 — history is a nicety, never block on it
        hist = None
    return PromptSession(history=hist, completer=_SlashCompleter(),
                         complete_while_typing=True)


def ask(session, brain: str, model: str) -> str:
    def toolbar():
        return HTML(f" <b>nexus</b>   model: {model} [{brain}]   ·   /help ")
    return session.prompt(HTML("\n <ansicyan><b>nexus ›</b></ansicyan> "),
                          bottom_toolbar=toolbar).strip()


def help_panel(con) -> None:
    t = Table.grid(padding=(0, 2))
    t.add_column(style="cyan", no_wrap=True)
    t.add_column(style="dim")
    t.add_row("<target>", "assess a host or URL you are authorized to test")
    for cmd, desc in SLASH.items():
        t.add_row(cmd, desc)
    con.print(Panel(t, title="commands", border_style="dim", box=ROUNDED, padding=(1, 2)))


class RichPresenter:
    """Drives the live view during a run: a spinner with the current step, tool calls
    streaming above it, and a findings table at the end."""

    def __init__(self, con):
        self.con = con
        self._status = None
        self._buf = ""

    def header(self, brain, model, scope_raw, objective):
        self.con.print(f"  [dim]brain[/dim] {brain} [dim]({model})[/dim]   "
                       f"[dim]scope[/dim] {', '.join(scope_raw)}")
        self.con.print(f"  [dim]objective[/dim] {objective}\n")

    def thinking(self, target):
        self._status = self.con.status(f"[bold]Nexus[/bold] assessing {target}…",
                                       spinner="dots")
        return self._status

    def event(self, kind, text):
        if kind == "step":
            self._buf = ""
            if self._status is not None:
                self._status.update(f"[bold]Nexus[/bold] · {text}")
        elif kind == "delta":
            # live token stream — show the reasoning tail in the spinner line so a long
            # local step feels alive instead of a frozen spinner.
            self._buf += text
            if self._status is not None:
                tail = " ".join(self._buf.split())[-72:]
                self._status.update(f"[bold]Nexus[/bold] [dim]thinking…[/dim] [dim]{tail}[/dim]")
        elif kind == "tool":
            self._buf = ""
            self.con.print(f"  [cyan]›[/cyan] {text}")
        elif kind == "result":
            err = text.startswith("ERROR")
            style = "red" if err else "dim"
            snippet = text.replace("\n", " ")[:110]
            self.con.print(f"    [{style}]{snippet}[/{style}]")
        elif kind == "nudge":
            self.con.print(f"  [yellow]· {text}[/yellow]")
        elif kind == "done":
            pass  # the summary panel says it better

    def summary(self, target, messages, report_path, elapsed, evidence_report, stopped=False):
        render_findings(self.con, target, messages, elapsed, report_path, stopped)


def render_findings(con, target, messages, elapsed, report_path, stopped=False) -> None:
    found, ev = findings.analyze(messages)
    scans = findings.scanner_matches(messages)
    tool_calls = sum(
        1 for m in messages if isinstance(m.get("content"), list)
        for b in m["content"] if isinstance(b, dict) and b.get("type") == "tool_use")

    table = Table(box=ROUNDED, border_style="dim", expand=True, show_header=True,
                  header_style="dim")
    table.add_column("sev", no_wrap=True)
    table.add_column("finding", no_wrap=True)
    table.add_column("evidence", style="dim", overflow="fold")

    n = 0
    for fid, label, sev in findings._SPEC:
        if fid in found:
            n += 1
            style = _SEV_STYLE.get(sev, "white")
            detail = ev.get(fid, "").split(" Remediation:")[0].strip()
            table.add_row(Text(sev.upper(), style=style), Text(label, style=style), detail[:80])
    for f in scans:
        n += 1
        sev = (f.get("severity") or "info").capitalize()
        style = _SEV_STYLE.get(sev, "cyan")
        table.add_row(Text(sev.upper(), style=style),
                      Text((f.get("name") or f.get("template") or "match"), style=style),
                      "nuclei matcher hit")

    title = Text.from_markup(
        (f"[bold yellow]ASSESSMENT STOPPED (partial)[/bold yellow]  ·  {target}" if stopped
         else f"[bold]ASSESSMENT COMPLETE[/bold]  ·  {target}"))
    if n == 0:
        con.print(Panel(
            Text("No findings confirmed by evidence — and nothing was fabricated to fill the gap.",
                 style="dim"),
            title=title, border_style="green", box=ROUNDED, padding=(1, 2)))
    else:
        con.print(Panel(table, title=title, border_style="red", box=ROUNDED, padding=(1, 1)))

    foot = (f"[bold]{n}[/bold] findings  ·  [green]0 fabricated[/green]  ·  "
            f"{tool_calls} tool calls  ·  {elapsed:.0f}s")
    if tool_calls == 0:
        foot += ("\n[yellow]⚠ the model made no tool calls — it may not drive tools well.[/yellow]"
                 "\n[dim]  switch to a tools-capable model:  /model → qwen2.5:7b[/dim]")
    if report_path:
        foot += f"\n[dim]full report →[/dim] {report_path}"
    con.print(foot + "\n")
