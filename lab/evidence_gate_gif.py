"""Render the evidence-gate demo (evidence_gate_demo.py) to a shareable animated GIF.

Pure Pillow — no browser, no external services. Content comes from the demo module (which
drives the real gate), so the GIF can never drift from what Nexus actually does.

    python lab/evidence_gate_demo.py --gif docs/evidence-gate.gif
"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFont

from evidence_gate_demo import (TARGET, MODEL_CLAIMS, CLAIM_REASON, TRANSCRIPT, verdicts)
from redblue import findings

# --- palette (GitHub-dark terminal) ----------------------------------------------------------
BG = (13, 17, 23)
BAR = (22, 27, 34)
FG = (201, 209, 217)
DIM = (110, 118, 129)
GREY = (139, 148, 158)
RED = (255, 123, 114)
GREEN = (63, 185, 80)
YELLOW = (210, 153, 34)
CYAN = (57, 197, 207)
WHITE = (240, 246, 252)
DOTS = [(255, 95, 86), (255, 189, 46), (39, 201, 63)]

PAD_L, PAD_R, PAD_T, PAD_B = 26, 26, 16, 18
BAR_H, LH = 38, 29
FONT_PX = 18


def _font(name, size):
    for p in (rf"C:\Windows\Fonts\{name}", f"/usr/share/fonts/truetype/{name}"):
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


FONT = _font("consola.ttf", FONT_PX)
FONT_B = _font("consolab.ttf", FONT_PX)


def _wrap(text, cols):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > cols and cur:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    if cur:
        lines.append(cur)
    return lines


def build_rows():
    """List of rows; each row is a list of tokens. Token = (kind, ...):
    ('t', text, color, bold) | ('dot', color) | ('ok', color) | ('no', color) | ('gap',)."""
    found, _report = verdicts()
    rows = []
    rows.append([("t", "$ ", GREY, False),
                 ("t", f"nexus --target {TARGET} --scope localhost --authorized", WHITE, False)])
    rows.append([("t", "  agent probes the target, then writes its report\u2026", DIM, False)])
    rows.append([("gap",)])
    rows.append([("t", "\u258c ", WHITE, True), ("t", "What the model wrote in its report ", WHITE, True),
                 ("t", "(free-form prose)", DIM, False)])
    for _cid, sev, text in MODEL_CLAIMS:
        col = RED if sev in ("CRITICAL", "HIGH") else YELLOW
        rows.append([("t", "  ", FG, False), ("dot", col),
                     ("t", f"  {sev:<8} ", col, False), ("t", text, FG, False)])
    rows.append([("t", "  \u2192 5 vulnerabilities claimed.", DIM, False)])
    rows.append([("gap",)])
    rows.append([("t", "\u258c ", WHITE, True), ("t", "Evidence gate reads the transcript ", WHITE, True),
                 ("t", "(tool results \u2014 not prose)", DIM, False)])
    for cid, _sev, _text in MODEL_CLAIMS:
        kind, why = CLAIM_REASON[cid]
        if cid in found:
            rows.append([("t", "  ", FG, False), ("t", f"{why:<40}", GREY, False),
                         ("ok", GREEN), ("t", " proven", GREEN, False)])
        else:
            label = " refused" if kind == "refused" else " no evidence"
            rows.append([("t", "  ", FG, False), ("t", f"{why:<40}", GREY, False),
                         ("no", RED), ("t", label, RED, False)])
    rows.append([("gap",)])
    rows.append([("t", "\u258c ", GREEN, True), ("t", "Nexus report ", GREEN, True),
                 ("t", "(evidence-only)", DIM, False)])
    rows.append([("t", "  # Security Assessment \u2014 " + TARGET, WHITE, True)])
    rows.append([("t", "  ## Findings", WHITE, True)])
    f = findings.structured(TARGET, TRANSCRIPT)[0]
    disp = f"- {f['name']} ({f['severity']}): {f['evidence']}".replace("`", "")
    for i, seg in enumerate(_wrap(disp, 60)):
        rows.append([("t", ("  " if i == 0 else "    ") + seg, GREEN, False)])
    rows.append([("gap",)])
    rows.append([("t", "5 claimed", WHITE, True), ("t", "   \u00b7   ", GREY, False),
                 ("t", "1 proven", GREEN, True), ("t", "   \u00b7   ", GREY, False),
                 ("t", "4 dropped", RED, True)])
    rows.append([("t", "The 4 aren't filtered \u2014 they're structurally excluded:", DIM, False)])
    rows.append([("t", "the report is built from tool results, never the model's prose.", DIM, False)])
    rows.append([("t", "A fabricated finding cannot reach it. By construction.", CYAN, True)])
    return rows


def _tok_width(d, tok):
    k = tok[0]
    if k == "t":
        return d.textlength(tok[1], font=FONT_B if tok[3] else FONT)
    if k in ("dot", "ok", "no"):
        return d.textlength("MM", font=FONT)  # ~2 char cells
    return 0.0


def _row_width(d, row):
    return sum(_tok_width(d, t) for t in row)


def _draw_row(d, row, y):
    x = PAD_L
    for tok in row:
        k = tok[0]
        if k == "t":
            _, s, col, bold = tok
            d.text((x, y), s, font=FONT_B if bold else FONT, fill=col)
        elif k == "dot":
            cy = y + LH / 2 - 2
            d.ellipse([x + 2, cy - 6, x + 14, cy + 6], fill=tok[1])
        elif k == "ok":
            cy = y + LH / 2 - 1
            d.line([(x + 2, cy + 1), (x + 6, cy + 6), (x + 15, cy - 6)], fill=tok[1], width=2)
        elif k == "no":
            cy = y + LH / 2 - 1
            d.line([(x + 3, cy - 6), (x + 14, cy + 6)], fill=tok[1], width=2)
            d.line([(x + 3, cy + 6), (x + 14, cy - 6)], fill=tok[1], width=2)
        x += _tok_width(d, tok)
    return x


def render_gif(out_path):
    rows = build_rows()
    # measure
    tmp = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    W = int(max(_row_width(tmp, r) for r in rows)) + PAD_L + PAD_R
    H = BAR_H + PAD_T + LH * len(rows) + PAD_B

    def frame(nrows, cursor=False):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, BAR_H], fill=BAR)
        for i, c in enumerate(DOTS):
            cx = 22 + i * 22
            d.ellipse([cx - 6, BAR_H // 2 - 6, cx + 6, BAR_H // 2 + 6], fill=c)
        d.text((W // 2, BAR_H // 2), "nexus \u2014 evidence gate", font=FONT, fill=DIM, anchor="mm")
        y = BAR_H + PAD_T
        lastx, lasty = PAD_L, y
        for r in range(nrows):
            if rows[r] and rows[r][0][0] != "gap":
                lastx = _draw_row(d, rows[r], y)
                lasty = y
            y += LH
        if cursor:
            d.rectangle([lastx + 2, lasty + 3, lastx + 12, lasty + LH - 6], fill=FG)
        return img

    frames, durs = [], []

    def add(img, ms):
        frames.append(img)
        durs.append(ms)

    add(frame(1, True), 650)                       # command typed
    for n in range(2, len(rows) + 1):
        is_gap = rows[n - 1] and rows[n - 1][0][0] == "gap"
        add(frame(n, True), 55 if is_gap else 150)
        # dwell on the three beats
        if n - 1 == 9:                             # last model claim
            add(frame(n, True), 650)
        if n - 1 == 17:                            # last verdict
            add(frame(n, True), 750)
    end = frame(len(rows), False)
    end_c = frame(len(rows), True)
    for _ in range(2):                             # blink + hold on the punchline
        add(end_c, 500)
        add(end, 500)
    add(end_c, 2200)

    # save last frame as PNG for inspection, and the GIF
    end_c.save(os.path.splitext(out_path)[0] + ".png")
    pal = frames[0].quantize(colors=64, method=Image.MEDIANCUT)
    q = [pal] + [f.quantize(palette=pal, dither=Image.NONE) for f in frames[1:]]
    q[0].save(out_path, save_all=True, append_images=q[1:], duration=durs,
              loop=0, optimize=True, disposal=1)
    return W, H, len(frames)
