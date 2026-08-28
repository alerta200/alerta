"""Evidence-gate demo — the one claim Nexus makes that competitors can't.

Scenario: a small offline model probes a target and, in its final message, CONFIDENTLY
writes up 5 vulnerabilities. Nexus reports 1 — the only one the target's own response
proves. The other 4 (a "user-database dump" the server actually answered 401 to, plus a
fabricated AWS key, a TLS claim, and a stack-trace claim that no tool ever observed) never
reach the report.

They are not filtered out afterward. They are structurally excluded: the report is derived
from the transcript's tool RESULTS (redblue/findings.py), never from the model's prose. So a
fabricated finding cannot enter it — by construction.

This drives the REAL gate. Which claims survive is computed from findings.analyze(), not
hard-coded here, so the demo is self-verifying.

    python lab/evidence_gate_demo.py                 # print to terminal
    python lab/evidence_gate_demo.py --gif out.gif   # render a shareable GIF
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from redblue import findings  # noqa: E402

TARGET = "http://localhost:3000"  # OWASP Juice Shop, run locally (authorized)


def _msgs(*calls):
    """(name, input, result) tuples -> the assistant/user transcript the agent produces."""
    out = []
    for i, (name, tin, res) in enumerate(calls):
        tid = f"c{i}"
        out.append({"role": "assistant",
                    "content": [{"type": "tool_use", "id": tid, "name": name, "input": tin}]})
        out.append({"role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": tid,
                                 "content": json.dumps(res), "is_error": False}]})
    return out


# --- the real run: tool calls + the live results they got back -----------------------------
TRANSCRIPT = _msgs(
    ("login_test",
     {"base_url": TARGET, "login_path": "/rest/user/login"},
     {"login_path": "/rest/user/login", "bypassed": True, "token_captured": True,
      "status": 200, "field": "email",
      "body_preview": '{"authentication":{"token":"eyJhbGci...","umail":"admin@juice-sh.op"}}'}),
    ("read_collection",
     {"base_url": TARGET, "path": "/api/Users"},
     {"path": "/api/Users", "carried_token": False, "status": 401,
      "body_preview": '{"error":"Unauthorized"}'}),
    ("http_probe",
     {"url": TARGET + "/", "method": "GET"},
     {"status": 200, "headers": {},
      "body_preview": "<!DOCTYPE html><title>OWASP Juice Shop</title>"}),
)

# --- what the model WROTE in its final report (prose). (class-id, severity, text) ----------
# The class-id is only used to ask the gate "did you actually confirm this?" — the verdict is
# the gate's, not ours.
MODEL_CLAIMS = [
    ("sqli",                  "CRITICAL", "SQL injection — auth bypass on /rest/user/login"),
    ("broken-access-control", "CRITICAL", "Broken access — dumped all users from /api/Users"),
    ("exposed-secrets",       "HIGH",     "Exposed AWS key AKIAIOSFODNN7EXAMPLE in /ftp/coupons.zip"),
    ("missing-headers",       "MEDIUM",   "Weak TLS 1.0 and missing HSTS header"),
    ("server-disclosure",     "MEDIUM",   "Verbose Express stack traces leak internal paths"),
]

# Short reason each claim survived or died, keyed to the real transcript above.
CLAIM_REASON = {
    "sqli":                  ("proven",  "login returned a token for ' OR 1=1--"),
    "broken-access-control": ("refused", "/api/Users answered 401 Unauthorized"),
    "exposed-secrets":       ("no evidence", "no tool ever fetched /ftp/coupons.zip"),
    "missing-headers":       ("no evidence", "TLS/headers were never tested"),
    "server-disclosure":     ("no evidence", "no stack trace ever observed"),
}


def verdicts():
    """Ask the REAL gate which claimed classes it confirmed. Returns (found_set, report_text)."""
    found, _ev = findings.analyze(TRANSCRIPT)
    return found, findings.report(TARGET, TRANSCRIPT)


# ---------------------------------------------------------------------------------------------
# terminal rendering
# ---------------------------------------------------------------------------------------------
C = {
    "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "red": "\033[91m", "yellow": "\033[93m", "green": "\033[92m",
    "cyan": "\033[96m", "grey": "\033[90m", "white": "\033[97m",
}
SEV_COLOR = {"CRITICAL": C["red"], "HIGH": C["red"], "MEDIUM": C["yellow"]}


def _sev_dot(sev):
    return "\U0001f534" if sev in ("CRITICAL", "HIGH") else "\U0001f7e0"


def print_demo(delay=0.0):
    found, report = verdicts()

    def line(s="", d=None):
        print(s)
        if delay:
            time.sleep(d if d is not None else delay)

    line(f"{C['grey']}$ {C['reset']}{C['white']}nexus --target {TARGET} "
         f"--scope localhost --authorized{C['reset']}")
    line(f"{C['dim']}  agent probes the target, then writes its report…{C['reset']}", 0.4)
    line()

    line(f"{C['bold']}▌ What the model wrote in its report {C['reset']}"
         f"{C['dim']}(free-form prose){C['reset']}")
    for cid, sev, text in MODEL_CLAIMS:
        col = SEV_COLOR.get(sev, C["yellow"])
        line(f"   {_sev_dot(sev)} {col}{sev:<8}{C['reset']} {text}")
    line(f"   {C['dim']}→ 5 vulnerabilities claimed.{C['reset']}", 0.5)
    line()

    line(f"{C['bold']}▌ Evidence gate reads the transcript {C['reset']}"
         f"{C['dim']}(tool results — not prose){C['reset']}")
    for cid, sev, text in MODEL_CLAIMS:
        kind, why = CLAIM_REASON[cid]
        if cid in found:
            mark = f"{C['green']}✔ proven{C['reset']}"
        else:
            mark = f"{C['red']}✘ {kind}{C['reset']}"
        line(f"   {C['grey']}{why:<42}{C['reset']} {mark}")
    line()

    line(f"{C['bold']}{C['green']}▌ Nexus report {C['reset']}"
         f"{C['dim']}(evidence-only){C['reset']}")
    for r in report.splitlines():
        if r.startswith("- **"):
            line(f"   {C['green']}{r}{C['reset']}")
        elif r.startswith("#"):
            line(f"   {C['bold']}{r}{C['reset']}")
        else:
            line(f"   {C['grey']}{r}{C['reset']}")
    line()

    kept = sum(1 for cid, _, _ in MODEL_CLAIMS if cid in found)
    dropped = len(MODEL_CLAIMS) - kept
    line(f"{C['white']}{len(MODEL_CLAIMS)} claimed · {C['green']}{kept} proven "
         f"by a live response{C['reset']}{C['white']} · {C['red']}{dropped} dropped{C['reset']}.")
    line(f"{C['dim']}The {dropped} aren't filtered out — they're structurally excluded:{C['reset']}")
    line(f"{C['dim']}the report is derived from tool results, never the model's prose.{C['reset']}")
    line(f"{C['cyan']}A fabricated finding cannot reach it. By construction.{C['reset']}")


if __name__ == "__main__":
    if "--gif" in sys.argv:
        from evidence_gate_gif import render_gif  # local module, same dir
        out = sys.argv[sys.argv.index("--gif") + 1]
        render_gif(out)
        print(f"wrote {out}")
    else:
        print_demo(delay=0.0)
