"""copilot.py — an offline, evidence-grounded Q&A layer over a completed assessment.

The autonomous scan produces evidence-gated findings; a consultant then wants to *interrogate* them
in plain language — "what's most urgent?", "explain the SQLi", "how do these chain?", "how do I fix
the exposed secret?", "draft the client summary". This module answers those questions
DETERMINISTICALLY from the findings themselves, reusing the very same CVSS / attack-path /
compliance / fix-pack projections that build the deliverable. So a co-pilot answer can never
fabricate a finding the target didn't confirm — the product's evidence-gate ethos, extended from
the report to the conversation.

Why deterministic rather than "ask the LLM about the findings"? The whole moat is *never fabricate*.
The AI in this product is the red-team agent that FINDS things; the co-pilot that helps you USE the
findings is most valuable to a consultant precisely when it cannot hallucinate about a client's
posture. Ask about a class that isn't in evidence and it says so — it does not invent one.

`grounding()` is the seam for a future LLM free-form mode (inject it, constrain the model to it);
today the engine is pure, deterministic, offline stdlib.
"""

from __future__ import annotations

import re

from . import compliance
from . import deliverable
from . import fixpack

# A finding class the user can name in a question → the keywords that point at it. Matched against
# ALL classes (not just present ones) so that asking about an ABSENT class gets an honest "not
# confirmed" rather than silence — the evidence gate, spoken.
_CLASS_KW = [
    ("sqli",                  ("sql injection", "sqli", "sql-injection")),
    ("reflected-xss",         ("xss", "cross-site scripting", "cross site scripting")),
    ("path-traversal",        ("path traversal", "directory traversal", "traversal", "lfi",
                               "local file inclusion")),
    ("exposed-secrets",       ("exposed secret", "secrets", "secret", "credential", "leaked",
                               "api key", ".env", "password file")),
    ("broken-access-control", ("broken access", "access control", "idor", "authorization bypass",
                               "auth bypass", "unauthenticated", "privilege escalation")),
    ("server-disclosure",     ("server disclosure", "version banner", "server banner",
                               "version disclosure", "fingerprint")),
    ("missing-headers",       ("missing header", "security header", "headers", "header", "csp",
                               "hsts", "x-frame")),
]

_TRIAGE = ("first", "priorit", "urgent", "escalat", "worst", "most serious", "most critical",
           "where do i start", "start with", "order", "biggest risk")
_PATHS = ("attack path", "attack-path", "chain", "combine", "pivot", "blast radius", "how bad",
          "kill chain", "exploit path", "work together")
_COMPLIANCE = ("complian", "cwe", "owasp", "pci", "standard", "audit", "soc2", "soc 2", "iso", "map")
_FIX = ("fix", "remediat", "patch", "mitigat", "resolve", "plan", "harden")
_EMAIL = ("email", "draft", "client summary", "write up", "write-up", "letter", "message to client",
          "note to client", "report to client")
_COUNT = ("how many", "count", "number of")
_SUMMARY = ("summary", "overview", "verdict", "what did you find", "findings", "results", "recap",
            "tldr", "tl;dr", "brief")
_EXPLAIN = ("explain", "tell me about", "detail", "what is", "what's the", "describe", "about the")


def _has(q: str, words) -> bool:
    return any(w in q for w in words)


def _named_class(q: str) -> str | None:
    """The finding class the question refers to (by keyword), or None. Longest keyword wins so
    'security header' beats a stray 'header' inside another word."""
    best, best_len = None, 0
    for fid, kws in _CLASS_KW:
        for kw in kws:
            if kw in q and len(kw) > best_len:
                best, best_len = fid, len(kw)
    return best


def _present(fid: str | None, enriched: list) -> dict | None:
    """The first enriched finding of class `fid` actually present in this assessment, or None."""
    if not fid:
        return None
    for it in enriched:
        if it.get("id") == fid:
            return it
    return None


def _by_index(q: str, enriched: list) -> dict | None:
    """Resolve 'finding 2' / '#2' / 'number 2' against the severity-ordered list (1-based)."""
    m = re.search(r"(?:finding|number|no\.?|#)\s*(\d{1,2})\b", q)
    if not m:
        return None
    i = int(m.group(1))
    return enriched[i - 1] if 1 <= i <= len(enriched) else None


def _band(it: dict) -> str:
    b = it.get("band") or "Info"
    return f"{b}, CVSS {it['cvss']:.1f}" if it.get("cvss") is not None else b


# ------------------------------------------------------------------ deterministic answers

def _explain(it: dict) -> str:
    fx = fixpack.fix_for(it["id"])
    lines = [f"{it['name']} ({_band(it)})",
             f"  Location:   {it.get('location', '—')}",
             f"  What we saw: {it.get('evidence', '—')}"]
    if it.get("standards"):
        lines.append(f"  Standards:  {it['standards']}")
    if fx:
        lines.append(f"  Fix:        {fx['summary']} (effort: {fx['effort']})")
    return "\n".join(lines)


def _fix_one(it: dict) -> str:
    fx = fixpack.fix_for(it["id"])
    if not fx:
        return f"{it['name']}: {it.get('remediation', 'no curated fix available.')}"
    lang = fx["lang"].split(" ")[0]
    return (f"{it['name']} — {fx['summary']}\n\n```{lang}\n{fx['code']}\n```")


def _triage(target: str, enriched: list) -> str:
    first = enriched[0]
    plan = fixpack.roadmap(enriched)
    phase = plan[0] if plan else None
    out = [f"Fix first: {first['name']} — {_band(first)} at {first.get('location', '—')}.",
           "  Why: it is the highest-severity finding the target actually confirmed."]
    if phase:
        out.append(f"  Phase: {phase[0]} — {phase[1]}")
    rest = enriched[1:4]
    if rest:
        out.append("Then, in order:")
        for n, it in enumerate(rest, start=2):
            out.append(f"  {n}. {it['name']} ({_band(it)})")
    return "\n".join(out)


def _paths(target: str, enriched: list) -> str:
    paths = deliverable.attack_paths(enriched)
    if not paths:
        return ("The confirmed findings are independent — no multi-step exploit chain links them "
                "in this assessment.")
    out = [f"{len(paths)} exploit chain{'s' if len(paths) != 1 else ''} — how separate weaknesses "
           "combine:"]
    for p in paths:
        out.append(f"\n{p['title']}")
        for n, step in enumerate(p["steps"], 1):
            out.append(f"  {n}. {step}")
        out.append(f"  → Impact: {p['impact']}")
    return "\n".join(out)


def _compliance(target: str, enriched: list) -> str:
    out = ["Standards mapping (CWE / OWASP 2021 / PCI DSS v4.0):"]
    for it in enriched:
        if it.get("standards"):
            out.append(f"  - {it['name']}: {it['standards']}")
    cov = compliance.owasp_coverage(enriched)
    if cov:
        out.append("OWASP categories implicated: "
                   + ", ".join(f"{oid} ({name})" for oid, name, *_ in cov) + ".")
    return "\n".join(out)


def _email(target: str, enriched: list) -> str:
    paths = deliverable.attack_paths(enriched)
    body = [f"Subject: Security assessment results — {target}", "",
            "Hello,", "",
            deliverable.executive_summary(target, enriched, paths), ""]
    if enriched:
        body.append("Confirmed findings:")
        for it in enriched:
            body.append(f"  - {it['name']} ({_band(it)})")
        body.append("")
    body += ["Full evidence and step-by-step remediation are in the attached report. We're happy to "
             "walk through the fixes and retest once they're in place.", "",
             "Regards,"]
    return "\n".join(body)


def _summary(target: str, enriched: list) -> str:
    paths = deliverable.attack_paths(enriched)
    out = [deliverable.executive_summary(target, enriched, paths)]
    if enriched:
        out.append("")
        for n, it in enumerate(enriched, 1):
            out.append(f"  {n}. {it['name']} ({_band(it)}) — {it.get('location', '—')}")
    return "\n".join(out)


def _absent(fid: str) -> str:
    name = dict((i, _l) for i, _l, _s in _finding_labels()).get(fid, fid)
    return (f"No {name.lower()} was confirmed in this assessment — I only answer from findings the "
            "target actually returned, and there is no evidence for that here.")


def _finding_labels():
    # findings._SPEC is (id, label, severity); imported lazily to avoid a cycle at module load.
    from . import findings
    return findings._SPEC


# ------------------------------------------------------------------ public API

_INTENTS = ("summary / verdict", "what to fix first (triage)", "explain <finding>",
            "attack paths / chaining", "compliance mapping", "how to fix <finding>",
            "draft a client summary")


def menu() -> str:
    """The honest 'here's what I can answer' fallback — printed instead of guessing."""
    return "I can answer, grounded in the confirmed findings:\n  - " + "\n  - ".join(_INTENTS)


def answer(question: str, target: str, enriched: list) -> str | None:
    """Answer a natural-language question about the assessment, deterministically and only from the
    evidence-gated findings. Returns the answer text, or None if the question matches no known
    intent (the caller then shows `menu()` or, in an interactive session, hands it to a grounded
    chat model). `enriched` = deliverable.enrich(findings)."""
    q = (question or "").strip().lower()
    if not q:
        return None

    named = _named_class(q)
    finding = _by_index(q, enriched) or _present(named, enriched)

    # A named-but-absent class, asked about specifically → honest "not in evidence" (never invent).
    if named and finding is None and _has(q, _EXPLAIN + _FIX):
        return _absent(named)

    if finding is not None and _has(q, _EXPLAIN):
        return _explain(finding)
    if _has(q, _TRIAGE) and enriched:
        return _triage(target, enriched)
    if _has(q, _PATHS):
        return _paths(target, enriched)
    if _has(q, _COMPLIANCE) and enriched:
        return _compliance(target, enriched)
    if _has(q, _EMAIL):
        return _email(target, enriched)
    if _has(q, _FIX):
        return _fix_one(finding) if finding is not None else fixpack.to_markdown(target, enriched)
    if _has(q, _COUNT) or _has(q, _SUMMARY):
        return _summary(target, enriched)
    # A bare finding reference with no verb ("the sqli?") → explain it.
    if finding is not None:
        return _explain(finding)
    return None


def grounding(target: str, enriched: list) -> str:
    """A compact, evidence-only context block for a future LLM free-form mode: the target and each
    confirmed finding (name / band / location / evidence), plus the gate instruction. Injecting this
    and constraining the model to it keeps a conversational answer as honest as the findings."""
    lines = [f"CONFIRMED FINDINGS for {target} (evidence-gated — the only ground truth):"]
    if not enriched:
        lines.append("  (none — the assessment confirmed no material weaknesses.)")
    for n, it in enumerate(enriched, 1):
        lines.append(f"  {n}. {it['name']} [{_band(it)}] at {it.get('location', '—')} — "
                     f"{it.get('evidence', '')}")
    lines.append("Answer ONLY from the findings above. If the question is not answered by them, say "
                 "so — do not speculate or invent findings.")
    return "\n".join(lines)
