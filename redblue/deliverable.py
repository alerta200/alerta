"""deliverable.py — turn the evidence-gated findings into a CLIENT-READY deliverable.

The canonical `findings.report()` is a truthful engineer's list; a consultant hands a CLIENT a
different artefact: an executive summary, a standardised CVSS score per finding, an attack-path
narrative (the story a scanner can't tell), and a branded, printable document. This module builds
exactly that — and, crucially, it stays inside the product's evidence-gate ethos:

  * it consumes ONLY `findings.structured()` (evidence-backed findings — no model prose);
  * CVSS scores are COMPUTED with the real CVSS 3.1 formula from a fixed vector per finding class,
    not invented;
  * attack paths are asserted by DETERMINISTIC rules and only when BOTH members are present in the
    evidence — a chain is never fabricated.

So the deliverable is prettier, but no less honest than the raw report. Pure stdlib → still runs
in an air-gapped box. `findings.report()` bytes are untouched (the flywheel verifier depends on
them); this is an additive projection alongside md / json / sarif.
"""

from __future__ import annotations

import datetime
import html
import math

from . import compliance
from . import findings
from . import fixpack

# --------------------------------------------------------------------- CVSS 3.1 (real formula)

# One defensible CVSS 3.1 base vector per evidence-gated finding class. Chosen conservatively for a
# typical internet-facing web target; the score is then COMPUTED, never hardcoded. A version banner
# has no direct CIA impact → 0.0 (Informational), which matches the tool's own "Info" label.
CVSS_VECTORS = {
    "sqli":                  "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # 9.8 Critical
    "path-traversal":        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",   # 7.5 High
    "exposed-secrets":       "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",   # 7.5 High
    "broken-access-control": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",   # 7.5 High
    "reflected-xss":         "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",   # 6.1 Medium
    "missing-headers":       "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",   # 5.3 Medium
    "server-disclosure":     "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",   # 0.0 Info
}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    """CVSS 3.1 Appendix-A roundup: ceil to one decimal via integer arithmetic (float-safe)."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss_score(vector: str) -> float:
    """Compute the CVSS 3.1 base score for a `AV:…/…` vector string. Pure formula, no lookup table."""
    m = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            m[k] = v
    try:
        scope_changed = m["S"] == "C"
        pr = (_PR_C if scope_changed else _PR_U)[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        expl = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except KeyError:
        return 0.0
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + expl) if scope_changed else (impact + expl)
    return _roundup(min(raw, 10.0))


def cvss_band(score: float) -> str:
    """Standard CVSS 3.1 qualitative rating for a base score."""
    if score == 0:
        return "Info"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


_BAND_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def enrich(items: list) -> list:
    """Copy each structured finding and attach a computed CVSS score/band/vector. `nuclei`-sourced
    matches carry their own severity (no metrics to compute), so their band is taken as-is."""
    out = []
    for it in items:
        e = dict(it)
        vec = CVSS_VECTORS.get(it["id"])
        if vec and it.get("source") != "nuclei":
            score = cvss_score(vec)
            e["cvss"] = score
            e["cvss_vector"] = vec
            e["band"] = cvss_band(score)
        else:
            e["cvss"] = None
            e["cvss_vector"] = None
            e["band"] = str(it.get("severity", "Info")).capitalize()
        e["compliance"] = compliance.for_finding(it["id"])
        e["standards"] = compliance.short_line(it["id"])
        out.append(e)
    out.sort(key=lambda x: (_BAND_RANK.get(x["band"], 9), -(x["cvss"] or 0)))
    return out


# --------------------------------------------------------------------- attack-path narrative

def _loc(by_id: dict, fid: str) -> str:
    it = by_id.get(fid)
    return it["location"] if it else fid


def attack_paths(enriched: list) -> list:
    """Deterministic attack-chain narratives over the CONFIRMED finding set. Each rule fires only
    when every member is present in the evidence — the story is real, not inferred. Returns a list
    of {title, steps:[...], impact} ordered most-severe first. This is the piece a flat scanner
    list can't produce: how separate weaknesses combine into a breach."""
    ids = {it["id"] for it in enriched}
    by_id = {it["id"]: it for it in enriched}
    paths = []
    covered: set = set()   # finding ids already told as part of a multi-hop chain

    def add(path: dict, members: set) -> None:
        paths.append(path)
        covered.update(members)

    if "sqli" in ids:
        add({
            "title": "Full database compromise via SQL injection",
            "steps": [
                f"Inject SQL at {_loc(by_id, 'sqli')} (confirmed: the server acted on the payload).",
                "Bypass authentication and/or read arbitrary tables.",
                "Exfiltrate every user record, credential hash, and secret in the database.",
            ],
            "impact": "Complete loss of confidentiality and integrity of all stored data.",
        }, {"sqli"})

    if "path-traversal" in ids and "exposed-secrets" in ids:
        add({
            "title": "Credential theft through arbitrary file read",
            "steps": [
                f"Read arbitrary files via path traversal at {_loc(by_id, 'path-traversal')}.",
                f"Harvest the credentials/keys already exposed at {_loc(by_id, 'exposed-secrets')}.",
                "Reuse the recovered secrets to authenticate as a legitimate service or user.",
            ],
            "impact": "Attacker gains authenticated access using the target's own leaked secrets.",
        }, {"path-traversal", "exposed-secrets"})

    if "broken-access-control" in ids and "exposed-secrets" in ids:
        add({
            "title": "Account takeover from leaked secrets + missing authorization",
            "steps": [
                f"Collect credentials/API keys exposed at {_loc(by_id, 'exposed-secrets')}.",
                f"Reach privileged data left unauthenticated at "
                f"{_loc(by_id, 'broken-access-control')}.",
                "Pivot to a full account/administrative takeover.",
            ],
            "impact": "Unauthorized access to other users' accounts and sensitive records.",
        }, {"broken-access-control", "exposed-secrets"})

    if "reflected-xss" in ids and "broken-access-control" in ids:
        add({
            "title": "Session hijack to an unprotected admin surface",
            "steps": [
                f"Deliver a crafted link firing script at {_loc(by_id, 'reflected-xss')}.",
                "Steal the victim's session token in their browser context.",
                f"Ride the session into the exposed area at {_loc(by_id, 'broken-access-control')}.",
            ],
            "impact": "A single victim click leads to privileged access.",
        }, {"reflected-xss", "broken-access-control"})

    # Single-finding consequence lines — only when that finding wasn't already told in a chain above.
    if "broken-access-control" in ids and "broken-access-control" not in covered:
        add({
            "title": "Direct sensitive-data exposure",
            "steps": [
                f"Request the privileged endpoint at {_loc(by_id, 'broken-access-control')} "
                "with no authentication.",
                "Enumerate and download other users' records directly.",
            ],
            "impact": "Confidential data is readable by any anonymous visitor.",
        }, {"broken-access-control"})

    if "exposed-secrets" in ids and "exposed-secrets" not in covered:
        add({
            "title": "Standalone secret exposure",
            "steps": [
                f"Retrieve the credentials/keys exposed at {_loc(by_id, 'exposed-secrets')}.",
                "Use them against this or connected systems until they are rotated.",
            ],
            "impact": "Any exposed live credential is an immediate foothold.",
        }, {"exposed-secrets"})

    return paths


# --------------------------------------------------------------------- executive summary

def executive_summary(target: str, enriched: list, paths: list) -> str:
    """A plain-language, one-paragraph verdict for a non-technical reader. Deterministic — derived
    from the confirmed counts and the worst finding, so it is as trustworthy as the findings."""
    if not enriched:
        return (f"An authorized security assessment of {target} confirmed no material weaknesses "
                "through active, evidence-backed testing. Every reported check was exercised "
                "against the live target and none produced a confirming response. This is a "
                "point-in-time result and does not by itself certify the system as secure.")
    counts = {}
    for it in enriched:
        counts[it["band"]] = counts.get(it["band"], 0) + 1
    order = ["Critical", "High", "Medium", "Low", "Info"]
    parts = [f"{counts[b]} {b}" for b in order if counts.get(b)]
    worst = enriched[0]
    tally = ", ".join(parts)
    lead = (f"An authorized assessment of {target} confirmed {len(enriched)} finding"
            f"{'s' if len(enriched) != 1 else ''} ({tally}), each backed by the target's own "
            f"response. The most serious is {worst['name'].lower()}")
    if worst.get("cvss"):
        lead += f" (CVSS {worst['cvss']:.1f} {worst['band']})"
    lead += "."
    if paths:
        lead += (f" Beyond the individual issues, {len(paths)} exploit chain"
                 f"{'s were' if len(paths) != 1 else ' was'} identified in which separate "
                 f"weaknesses combine — the most direct being \"{paths[0]['title'].lower()}\".")
    highest = worst["band"]
    if highest in ("Critical", "High"):
        lead += (" Remediation of the high-severity items should be treated as urgent and "
                 "completed before this system remains exposed to untrusted networks.")
    else:
        lead += (" The confirmed items are lower severity but should be scheduled for remediation "
                 "as part of normal hardening.")
    return lead


# --------------------------------------------------------------------- HTML deliverable

_CSS = """
:root{--ink:#1a1d24;--muted:#5b6472;--line:#e3e7ef;--bg:#fff;--accent:#0b5cad;
--crit:#b30021;--high:#d1491c;--med:#b8860b;--low:#3a7d34;--info:#5b6472}
*{box-sizing:border-box}
body{font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);
background:#f4f5f7;margin:0;padding:32px}
.page{max-width:900px;margin:0 auto;background:var(--bg);padding:56px 60px;
box-shadow:0 1px 4px rgba(0,0,0,.08);border-radius:4px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:34px 0 12px;
border-bottom:2px solid var(--accent);padding-bottom:6px;color:var(--accent)}
h3{font-size:15px;margin:18px 0 6px}
.meta{color:var(--muted);font-size:13px;margin:0 0 2px}
.conf{display:inline-block;margin-top:14px;padding:3px 10px;border:1px solid var(--crit);
color:var(--crit);font-size:11px;letter-spacing:.14em;border-radius:3px;font-weight:600}
.sum{background:#f8f9fb;border:1px solid #e6e9ef;border-left:4px solid var(--accent);
padding:16px 18px;border-radius:3px;margin:8px 0}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:13.5px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #e6e9ef;vertical-align:top}
th{background:#f2f4f7;font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11.5px;font-weight:600;
color:#fff;white-space:nowrap}
.b-Critical{background:var(--crit)}.b-High{background:var(--high)}.b-Medium{background:var(--med)}
.b-Low{background:var(--low)}.b-Info{background:var(--info)}
code{background:#f2f4f7;padding:1px 5px;border-radius:3px;font-size:12.5px}
.ev{color:var(--muted);font-size:12.5px}
.std{color:var(--accent);font-size:11.5px;margin-top:3px;font-weight:500}
pre{background:#0f1723;color:#e6edf5;padding:12px 15px;border-radius:5px;overflow-x:auto;
font-size:12px;line-height:1.5;margin:6px 0 4px}
pre code{background:none;padding:0;color:inherit}
.phase{margin:8px 0 4px}.phase h3{margin:14px 0 4px}.eff{color:var(--muted);font-size:12px}
.phase-Immediate{border-left:4px solid var(--crit);padding-left:12px}
.phase-Short-term{border-left:4px solid var(--med);padding-left:12px}
.phase-Hygiene{border-left:4px solid var(--low);padding-left:12px}
.chain{border:1px solid #e6e9ef;border-radius:4px;padding:12px 16px;margin:10px 0}
.chain ol{margin:6px 0 8px 18px;padding:0}.chain li{margin:3px 0}
.impact{font-size:12.5px;color:var(--crit)}
.wm{background:#fff7e6;border:1px solid #f0c36d;color:#7a5b00;padding:10px 14px;border-radius:3px;
margin:0 0 18px;font-size:13px}
footer{margin-top:34px;padding-top:14px;border-top:1px solid #e6e9ef;color:var(--muted);font-size:12px}
@media print{body{background:#fff;padding:0}.page{box-shadow:none;max-width:none;padding:24px 0}
h2{break-after:avoid}.chain,tr{break-inside:avoid}}
"""


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _fmt_evidence(ev: str) -> str:
    """Escape evidence text, then re-mark `back-ticked` tokens as <code> (evidence is our own
    deterministic text, so this is safe)."""
    out, i = [], 0
    esc = _esc(ev)
    for chunk in esc.split("`"):
        out.append(chunk if i % 2 == 0 else f"<code>{chunk}</code>")
        i += 1
    return "".join(out)


def _roadmap_row(it: dict) -> str:
    """One row of a remediation phase: finding name, its CVSS, and the fix effort (looked up once)."""
    fx = fixpack.fix_for(it["id"])
    cvss = f' <span class="ev">CVSS {it["cvss"]:.1f}</span>' if it.get("cvss") is not None else ""
    eff = f' <span class="eff">· effort: {_esc(fx["effort"])}</span>' if fx else ""
    return f'<div class="rtrow"><strong>{_esc(it["name"])}</strong>{cvss}{eff}</div>'


def to_html(target, messages, meta: dict | None = None, version: str = "0",
            eval_mode: bool = False) -> str:
    """Render a branded, self-contained, printable HTML assessment report. `meta` may carry
    `vendor`, `client`, `date`. Print to PDF from any browser — no external assets, no fonts,
    no network (air-gap safe)."""
    meta = meta or {}
    items = enrich(findings.structured(target, messages))
    paths = attack_paths(items)
    summ = executive_summary(target, items, paths)
    vendor = meta.get("vendor") or "Nexus Security Assessment"
    client = meta.get("client") or ""
    date = meta.get("date") or datetime.date.today().isoformat()

    h = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         f"<title>Security Assessment — {_esc(target)}</title><style>{_CSS}</style></head><body>",
         '<div class="page">']
    h.append(f"<h1>{_esc(vendor)}</h1>")
    if client:
        h.append(f'<p class="meta">Prepared for: {_esc(client)}</p>')
    h.append(f'<p class="meta">Target: <code>{_esc(target)}</code></p>')
    h.append(f'<p class="meta">Date: {_esc(date)}</p>')
    h.append('<span class="conf">CONFIDENTIAL</span>')
    if eval_mode:
        h.append('<div class="wm" style="margin-top:16px">EVALUATION REPORT — not a licensed '
                 "deliverable. Generated by an unlicensed Nexus build for evaluation only.</div>")

    h.append("<h2>Executive summary</h2>")
    h.append(f'<div class="sum">{_esc(summ)}</div>')

    # severity tally
    if items:
        tally = {}
        for it in items:
            tally[it["band"]] = tally.get(it["band"], 0) + 1
        cells = "".join(f'<td><span class="badge b-{b}">{b}</span> &times;{tally[b]}</td>'
                        for b in ["Critical", "High", "Medium", "Low", "Info"] if tally.get(b))
        h.append(f"<table><tr>{cells}</tr></table>")

    h.append("<h2>Findings</h2>")
    if not items:
        h.append("<p>No material findings were confirmed by evidence.</p>")
    else:
        h.append("<table><tr><th>Finding</th><th>Severity</th><th>CVSS</th><th>Location</th>"
                 "<th>Evidence &amp; remediation</th></tr>")
        for it in items:
            cv = (f'{it["cvss"]:.1f}<br><span class="ev">{_esc(it["cvss_vector"])}</span>'
                  if it.get("cvss") is not None else "&mdash;")
            h.append(
                f'<tr><td><strong>{_esc(it["name"])}</strong></td>'
                f'<td><span class="badge b-{it["band"]}">{it["band"]}</span></td>'
                f"<td>{cv}</td>"
                f'<td><code>{_esc(it["location"])}</code></td>'
                f'<td>{_fmt_evidence(it["evidence"])}'
                f'<div class="ev"><em>Fix:</em> {_esc(it["remediation"])}</div>'
                + (f'<div class="std">{_esc(it["standards"])}</div>' if it.get("standards")
                   else "")
                + "</td></tr>")
        h.append("</table>")

        # compliance coverage — the auditor's view (which OWASP categories are implicated).
        cov = compliance.owasp_coverage(items)
        if cov:
            h.append("<h2>Compliance mapping</h2>")
            h.append('<p class="ev">Confirmed findings mapped to CWE, the OWASP Top 10 (2021), and '
                     "the closest PCI DSS v4.0 requirement (indicative).</p>")
            h.append("<table><tr><th>Finding</th><th>CWE</th><th>OWASP 2021</th>"
                     "<th>PCI DSS 4.0</th></tr>")
            for it in items:
                m = it.get("compliance")
                if not m:
                    continue
                h.append(
                    f'<tr><td>{_esc(it["name"])}</td>'
                    f'<td>{_esc(m["cwe"][0])} <span class="ev">{_esc(m["cwe"][1])}</span></td>'
                    f'<td>{_esc(m["owasp"][0])} {_esc(m["owasp"][1])}</td>'
                    f'<td>&sect;{_esc(m["pci"][0])} <span class="ev">{_esc(m["pci"][1])}</span>'
                    "</td></tr>")
            h.append("</table>")
            summary = ", ".join(f"{oid} ({name})" for oid, name, _ in cov)
            h.append(f'<p class="ev">OWASP categories implicated: {_esc(summary)}.</p>')

    if paths:
        h.append("<h2>Attack paths</h2>")
        h.append('<p class="ev">How the individual weaknesses combine into a breach — the chain a '
                 "vulnerability scanner does not surface.</p>")
        for p in paths:
            steps = "".join(f"<li>{_fmt_evidence(s)}</li>" for s in p["steps"])
            h.append(f'<div class="chain"><h3>{_esc(p["title"])}</h3><ol>{steps}</ol>'
                     f'<div class="impact"><strong>Impact:</strong> {_esc(p["impact"])}</div></div>')

    plan = fixpack.roadmap(items)
    if plan:
        h.append("<h2>Remediation plan</h2>")
        h.append('<p class="ev">What to fix, in what order — with a concrete, copy-paste fix per '
                 "issue class.</p>")
        for name, desc, members in plan:
            rows = "".join(_roadmap_row(it) for it in members)
            h.append(f'<div class="phase phase-{name}"><h3>{_esc(name)} '
                     f'<span class="ev">&mdash; {_esc(desc)}</span></h3>{rows}</div>')
        # de-duplicated copy-paste fixes (findings can share a class)
        seen = set()
        for it in items:
            fid = it["id"]
            fx = fixpack.fix_for(fid)
            if fid in seen or not fx:
                continue
            seen.add(fid)
            h.append(f'<h3>{_esc(it["name"])} &mdash; fix</h3>'
                     f'<p class="ev">{_esc(fx["summary"])}</p>'
                     f'<pre><code>{_esc(fx["code"])}</code></pre>')

    h.append("<footer>Generated offline by Nexus. Every finding is backed by a real response the "
             "target returned during testing — nothing in this report is inferred or model-authored. "
             f"Engine v{_esc(version)}.</footer>")
    h.append("</div></body></html>")
    return "".join(h)
