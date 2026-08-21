"""retest.py — compare two assessments and report what changed (the retest phase of an engagement).

A pentest is rarely one-shot: you assess, the client remediates, and you RETEST to prove the fixes
landed. This module diffs a previous run against a current one and reports each finding as
**fixed** (was there, now gone), **still open** (present in both), or **new** (appeared since).

It is a pure, deterministic projection over the same evidence-gated findings the rest of the tool
produces (`findings.structured()` / the `--format json` artefact) — a finding's identity is
`(id, location)`, so "same class at same place" is the same finding. No model prose, stdlib only,
so a retest runs offline on the two saved JSON reports. CVSS and styling are reused from
`deliverable` so the retest document matches the client deliverable.
"""

from __future__ import annotations

import datetime
import json

from . import deliverable


def _key(it: dict):
    return (it.get("id"), it.get("location"))


def load_findings(path: str):
    """Load findings + target from a Nexus `--format json` artefact (or a bare findings list)."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if isinstance(doc, dict):
        return doc.get("findings", []) or [], doc.get("target", "") or ""
    if isinstance(doc, list):
        return doc, ""
    return [], ""


def diff(old: list, new: list) -> dict:
    """Compare two findings lists by (id, location). Returns fixed / still_open / new lists, each
    CVSS-enriched and ordered most-severe first, plus a small stats block."""
    o = {_key(i): i for i in old}
    n = {_key(i): i for i in new}
    fixed = deliverable.enrich([o[k] for k in o if k not in n])
    still = deliverable.enrich([n[k] for k in n if k in o])
    added = deliverable.enrich([n[k] for k in n if k not in o])
    prior = len(fixed) + len(still)   # findings that existed in the old run
    rate = (len(fixed) / prior) if prior else None
    return {"fixed": fixed, "still_open": still, "new": added,
            "stats": {"fixed": len(fixed), "still_open": len(still), "new": len(added),
                      "prior": prior, "remediation_rate": rate}}


def _headline(target: str, s: dict) -> str:
    if s["prior"] == 0 and s["new"] == 0:
        return f"Retest of {target}: no findings in either assessment."
    bits = []
    if s["prior"]:
        pct = f" ({s['remediation_rate']*100:.0f}%)" if s["remediation_rate"] is not None else ""
        bits.append(f"{s['fixed']} of {s['prior']} prior finding"
                    f"{'s' if s['prior'] != 1 else ''} remediated{pct}")
    if s["still_open"]:
        bits.append(f"{s['still_open']} still open")
    if s["new"]:
        bits.append(f"{s['new']} newly introduced")
    return f"Retest of {target}: " + "; ".join(bits) + "."


# --------------------------------------------------------------------- markdown

def _md_finding(it: dict) -> str:
    cv = f" (CVSS {it['cvss']:.1f} {it['band']})" if it.get("cvss") is not None else ""
    return f"- **{it['name']}**{cv} — `{it['location']}`"


def to_markdown(target: str, d: dict) -> str:
    s = d["stats"]
    lines = [f"# Retest / Delta — {target}", "", _headline(target, s), ""]
    lines.append(f"## Fixed ({s['fixed']})")
    lines += [_md_finding(it) for it in d["fixed"]] or ["- (none)"]
    lines += ["", f"## Still open ({s['still_open']})"]
    lines += [_md_finding(it) for it in d["still_open"]] or ["- (none)"]
    lines += ["", f"## New since last assessment ({s['new']})"]
    lines += [_md_finding(it) for it in d["new"]] or ["- (none)"]
    return "\n".join(lines)


# --------------------------------------------------------------------- html

_STATUS_CSS = """
.rt-fixed{color:#3a7d34}.rt-open{color:#b30021}.rt-new{color:#d1491c}
.stat{display:inline-block;margin:0 22px 0 0;text-align:center}
.stat b{display:block;font-size:26px;line-height:1.1}
.stat span{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#5b6472}
.rtrow{padding:8px 0;border-bottom:1px solid #eef0f4}
"""


def _rt_rows(items: list, css: str, mark: str) -> str:
    if not items:
        return '<p class="ev">(none)</p>'
    out = []
    for it in items:
        cv = (f' <span class="ev">CVSS {it["cvss"]:.1f} {it["band"]}</span>'
              if it.get("cvss") is not None else "")
        out.append(f'<div class="rtrow"><span class="{css}">{mark}</span> '
                   f'<strong>{deliverable._esc(it["name"])}</strong>{cv} '
                   f'&mdash; <code>{deliverable._esc(it["location"])}</code></div>')
    return "".join(out)


def to_html(target: str, d: dict, meta: dict | None = None, version: str = "0") -> str:
    """Branded, self-contained retest report (print to PDF). Shares the deliverable's look."""
    meta = meta or {}
    s = d["stats"]
    vendor = meta.get("vendor") or "Nexus Retest Report"
    client = meta.get("client") or ""
    date = meta.get("date") or datetime.date.today().isoformat()
    rate = (f'{s["remediation_rate"]*100:.0f}%' if s["remediation_rate"] is not None else "—")

    h = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         f"<title>Retest — {deliverable._esc(target)}</title>",
         f"<style>{deliverable._CSS}{_STATUS_CSS}</style></head><body><div class='page'>"]
    h.append(f"<h1>{deliverable._esc(vendor)}</h1>")
    if client:
        h.append(f'<p class="meta">Prepared for: {deliverable._esc(client)}</p>')
    h.append(f'<p class="meta">Target: <code>{deliverable._esc(target)}</code></p>')
    h.append(f'<p class="meta">Date: {deliverable._esc(date)}</p>')
    h.append('<span class="conf">CONFIDENTIAL</span>')

    h.append("<h2>Retest summary</h2>")
    h.append(f'<div class="sum">{deliverable._esc(_headline(target, s))}</div>')
    h.append(
        f'<div style="margin:14px 0">'
        f'<div class="stat"><b class="rt-fixed">{s["fixed"]}</b><span>fixed</span></div>'
        f'<div class="stat"><b class="rt-open">{s["still_open"]}</b><span>still open</span></div>'
        f'<div class="stat"><b class="rt-new">{s["new"]}</b><span>new</span></div>'
        f'<div class="stat"><b>{rate}</b><span>remediated</span></div></div>')

    h.append(f"<h2>Fixed &mdash; {s['fixed']}</h2>{_rt_rows(d['fixed'], 'rt-fixed', '&check;')}")
    h.append(f"<h2>Still open &mdash; {s['still_open']}</h2>"
             f"{_rt_rows(d['still_open'], 'rt-open', '&times;')}")
    h.append(f"<h2>New since last assessment &mdash; {s['new']}</h2>"
             f"{_rt_rows(d['new'], 'rt-new', '+')}")

    h.append("<footer>Generated offline by Nexus. Findings are matched by class and location "
             "across the two evidence-gated assessments; nothing here is inferred. "
             f"Engine v{deliverable._esc(version)}.</footer></div></body></html>")
    return "".join(h)
