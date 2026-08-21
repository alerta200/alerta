"""_style.py — the shared Nexus visual language for the terminal UIs.

One source of truth for palette, severity styles, event glyphs, and the proof-pair
"receipt" that renders a finding. Consumed by `tui_app.py` (the primary full-screen
Textual console). `tui.py` (the rich-REPL fallback) stays deliberately lean and uses
Rich's generic named colours ("dim"/"red"/…), so it does not import these fine-grained
tokens — the fallback maps to the terminal's own theme instead.

Presentation only — no logic, no evidence gate, no network. The few builders that need
`rich` import it lazily, so this module is safe to import from anywhere (the stdlib core
never imports it, but nothing here would pull in a heavy dependency if it did).

Identity: Nexus is red-team meeting blue-team at a magenta seam — the wordmark NE·X·US.
Red = the attack / probe / high severity. Blue (sky) = the defender's side / info /
verified context. The magenta seam is the evidence gate. Green (verify) is reserved for
one thing only: proof — "proven by the target's response" and "0 fabricated".
"""

from __future__ import annotations

# ── palette (24-bit hex; Rich and Textual both accept #rrggbb) ────────────────────────
VOID   = "#0a0b0f"   # base — a deep blue-graphite, not pure black
PANEL  = "#0f1218"   # raised surface
PANEL2 = "#141824"   # card
LINE   = "#232838"   # hairline border
RED    = "#ff3b4e"   # red team · attack · probe · high severity
RED_HI = "#ff5a66"   # focused red (input focus)
SEAM   = "#e5399b"   # the X · the seam · the EVIDENCE GATE
SKY    = "#57c7ff"   # blue team · info · verified context
BLUE   = "#3b82f6"   # blue accent (chips)
VERIFY = "#2fe0a2"   # integrity — "proven" / "0 fabricated" ONLY
AMBER  = "#f5a524"   # medium severity · caution
INK    = "#e7eaf2"   # primary text
DIM    = "#8c95ab"   # secondary text
FAINT  = "#707b93"   # tertiary / results — bumped to ≥4.5:1 on VOID; it carries REAL evidence
GHOST  = "#3a4256"   # quietest structure — hairlines / seam / rules ONLY, never body text

# ── severity → Rich style string ──────────────────────────────────────────────────────
# Text style for a severity word in a table / list.
SEV_STYLE = {
    "Critical": f"bold {RED}",
    "High":     RED,
    "Medium":   AMBER,
    "Low":      AMBER,
    "Info":     SKY,
}
# The headline severity label, rendered as a filled/outlined chip.
SEV_CHIP = {
    "Critical": f"bold {VOID} on {RED}",   # filled — the alarm
    "High":     f"bold {RED}",             # outline (fg only)
    "Medium":   f"bold {AMBER}",
    "Low":      f"bold {AMBER}",
    "Info":     f"bold {SKY}",
}


def sev_style(sev: str) -> str:
    return SEV_STYLE.get(sev, INK)


def sev_chip(sev: str) -> str:
    return SEV_CHIP.get(sev, f"bold {INK}")


# ── event-stream glyphs (matches cli.py's spoken vocabulary) ──────────────────────────
GLYPH = {
    "text":   "»",   # the model's reasoning, spoken aloud
    "tool":   "→",   # a tool call going out
    "result": "←",   # its result coming back
    "nudge":  "·",   # a harness nudge (low signal)
    "done":   "✓",   # evidence captured
    "step":   "┄",   # a phase divider (recon / enumerate / probe / report)
}
GLYPH_STYLE = {
    "text":   SKY,
    "tool":   AMBER,
    "result": FAINT,
    "nudge":  FAINT,
    "done":   VERIFY,
    "step":   GHOST,
}

# ── illustrative probe per finding class ──────────────────────────────────────────────
# The authoritative PROOF always comes from findings.analyze (the real target response).
# This is only the *technique* shown on the PROBE line so the receipt reads as attack →
# proof. Presentation only — findings.py is never touched and nothing here is credited.
PROBE_TECHNIQUE = {
    "sqli":                  "uid=' OR 1=1-- -",
    "path-traversal":        "file=../../../../etc/passwd",
    "reflected-xss":         "q=<svg/onload=alert(1)>",
    "exposed-secrets":       "GET /.env · /.git/config",
    "broken-access-control": "GET /admin  (no session)",
    "server-disclosure":     "GET /  (read Server banner)",
    "missing-headers":       "GET /  (inspect response headers)",
}


def probe_for(fid: str) -> str:
    return PROBE_TECHNIQUE.get(fid, "")


# ── the signature: a proof-pair "receipt" for one finding ─────────────────────────────
def finding_block(sev: str, label: str, proof: str, *, probe: str = "",
                  remediation: str = "", endpoint: str = "", width_hint: int = 0):
    """Render one finding as an evidence receipt — the thing that makes '0 fabricated'
    visible: the PROBE we sent (red) paired with the PROOF the target returned (green ✓).

    Returns a Rich renderable (a Group of styled lines). Shared by the live evidence dock
    and the final report panel so a finding looks identical everywhere.
    """
    from rich.text import Text
    from rich.console import Group
    from rich.table import Table

    head = Text()
    head.append(f" {sev.upper():<8} ", style=sev_chip(sev))
    head.append(" ")
    head.append(label, style=f"bold {sev_style(sev)}")
    if endpoint:
        head.append("  ")
        head.append(endpoint, style=DIM)

    # A label column + a folding value column, so long payloads / proofs wrap cleanly inside
    # the dock instead of being cropped at the panel edge.
    grid = Table.grid(padding=(0, 1), expand=True)
    grid.add_column(width=8, justify="left", no_wrap=True)
    grid.add_column(overflow="fold", ratio=1)
    if probe:
        grid.add_row(Text("   PROBE", style=f"bold {RED}"), Text(probe, style=INK))
    proof_t = Text(proof or "confirmed by target response", style=INK)
    proof_t.append("   ✓", style=f"bold {VERIFY}")
    grid.add_row(Text("   PROOF", style=f"bold {VERIFY}"), proof_t)
    if remediation:
        grid.add_row(Text("   fix", style=SKY), Text(remediation, style=DIM))
    return Group(head, grid, Text(""))


def zero_fabricated(n: int):
    """The proud integrity badge — 'N findings · 0 fabricated', green where it counts."""
    from rich.text import Text
    t = Text()
    t.append(str(n), style=f"bold {INK}")
    t.append(" findings   ", style=DIM)
    t.append("0 fabricated", style=f"bold {VERIFY}")
    return t


# ── the war-room instrument kit: telemetry & identity glyphs (presentation only) ───────
# Every one of these renders REAL run data — no decorative fake progress. The product's
# soul is "0 fabricated"; the UI honours it by charting only what actually happened.

GATE_GLYPH = "✕"   # the X of NE·X·US — the evidence gate, drawn at the seam's centre

_SPARK_TICKS = "▁▂▃▄▅▆▇█"


def sparkline(values, width: int = 0) -> str:
    """A unicode sparkline of a numeric series (e.g. tok/s over time) — the live sign the
    brain is burning. Normalised from 0 to the window's peak so a lull reads low and a
    burst reads tall. `width` keeps only the most recent N samples. Empty series → ""."""
    vals = [float(v) for v in values if v is not None]
    if width and len(vals) > width:
        vals = vals[-width:]
    if not vals:
        return ""
    hi = max(vals)
    if hi <= 0:
        return _SPARK_TICKS[0] * len(vals)
    out = []
    last = len(_SPARK_TICKS) - 1
    for v in vals:
        f = 0.0 if v < 0 else (1.0 if v > hi else v / hi)
        out.append(_SPARK_TICKS[int(f * last + 0.5)])
    return "".join(out)


def progress_bar(done: int, total: int, width: int = 8) -> str:
    """A compact '▓▓▓▓░░░' gauge for real step N/max progress. Unknown total → all dim."""
    if width <= 0:
        return ""
    if total <= 0:
        return "░" * width
    frac = done / total
    frac = 0.0 if frac < 0 else (1.0 if frac > 1 else frac)
    filled = int(frac * width + 0.5)
    return "▓" * filled + "░" * (width - filled)


# Severity rank for the distribution bar, most-severe first (matches SEV_STYLE's palette).
_SEV_ORDER = ("Critical", "High", "Medium", "Low", "Info")
_SEV_BAR_COLOR = {"Critical": RED, "High": RED, "Medium": AMBER, "Low": AMBER, "Info": SKY}


def severity_bar(counts: dict, width: int = 40):
    """A single line of severity-tinted blocks, one segment per severity, sized by REAL
    counts — the finding mix at a glance. 1 block per finding until it would overflow
    `width`, then scaled proportionally (every non-zero severity keeps ≥1 block).
    Returns a Rich Text; empty when there are no findings."""
    from rich.text import Text
    t = Text()
    present = [(s, int(counts.get(s, 0))) for s in _SEV_ORDER if int(counts.get(s, 0)) > 0]
    total = sum(n for _, n in present)
    if total <= 0:
        return t
    if width <= 0 or total <= width:
        for s, n in present:
            t.append("█" * n, style=_SEV_BAR_COLOR[s])
        return t
    # Overflow → scale to width, giving each non-zero severity at least one block, then
    # distributing the remainder by largest fractional part so the total lands on `width`.
    base = max(0, width - len(present))
    raw = [(s, 1 + base * n / total, n) for s, n in present]
    sized = [(s, int(v), v - int(v)) for s, v, _ in raw]
    used = sum(v for _, v, _ in sized)
    for s, _, _ in sorted(sized, key=lambda r: r[2], reverse=True):
        if used >= width:
            break
        for i, (ss, v, fr) in enumerate(sized):
            if ss == s:
                sized[i] = (ss, v + 1, fr)
                break
        used += 1
    for s, v, _ in sized:
        t.append("█" * v, style=_SEV_BAR_COLOR[s])
    return t


def wordmark(mini: bool = False):
    """The NE·X·US wordmark as inline Rich Text — red team · magenta seam · blue team.
    `mini` drops the interpuncts for a tight HUD badge."""
    from rich.text import Text
    t = Text()
    t.append("NE", style=f"bold {RED}")
    if not mini:
        t.append("·", style=SEAM)
    t.append("X", style=f"bold {SEAM}")
    if not mini:
        t.append("·", style=SEAM)
    t.append("US", style=f"bold {SKY}")
    return t


def seam_text(height: int, glyph: str = GATE_GLYPH):
    """The vertical seam between the red-team transcript and the blue-team dock: a thin rule
    that reddens at the top (NE) and cools to sky at the bottom (US), with the magenta gate
    glyph at its centre (X). The layout itself spells NE·X·US. Returns a Rich Text of
    `height` rows; empty before first layout (height 0)."""
    from rich.text import Text
    t = Text()
    if height <= 0:
        return t
    c1, c2 = (255, 59, 78), (87, 199, 255)   # red (top) → sky (bottom)
    mid = height // 2
    last = max(1, height - 1)
    for y in range(height):
        if y == mid:
            t.append(glyph, style=f"bold {SEAM}")
        else:
            f = y / last
            r = int(c1[0] + (c2[0] - c1[0]) * f)
            g = int(c1[1] + (c2[1] - c1[1]) * f)
            b = int(c1[2] + (c2[2] - c1[2]) * f)
            t.append("│", style=f"#{r:02x}{g:02x}{b:02x}")
        if y != height - 1:
            t.append("\n")
    return t
