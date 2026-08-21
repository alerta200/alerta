"""blue.py — the defender's BRAIN. Nexus's red side finds holes; this puts the model on the
OTHER side of the table: given the live, evidence-gated host posture (host.py) and the
deterministic fix proposals (remediate.py), the AI reasons like a blue-team lead — triage by
blast radius, name the risk if a hole stays open, and spot attack CHAINS between findings
that a per-finding scanner never sees.

This is the "AI defends from inside" step, and it is deliberately MEASURABLE: the posture it
reasons over is fixed and verifier-gated, so the quality of the model's defensive reasoning
can be read honestly (and, if weak, grown with the same verifier-gated flywheel as the red
side). Read-only throughout — reasoning and prioritisation, never a system change.
"""
from __future__ import annotations

import json
import re

from . import host as host_mod
from . import remediate
from .scope import Scope

_SYS = """You are Nexus operating as a blue-team defence lead. You are given the CURRENT,
evidence-confirmed security posture of a host you are authorised to defend. Every finding
below was proven by a real check — treat them as true, do not second-guess them, and do NOT
invent findings that are not listed.

Produce a tight defensive brief, in this order:
1. TRIAGE — order the findings by real-world blast radius (what an attacker gains first),
   not just by severity label. State which ONE to fix first and why.
2. RISK — for each finding, one concrete sentence: what an attacker does with it if it stays open.
3. ATTACK CHAINS — call out where two findings combine into something worse than either alone
   (e.g. a network-exposed service + a privilege-escalation path). If none, say so plainly.
4. FIRST MOVE — the single highest-value hardening action to take right now.

Be concrete and specific to THIS host. No preamble, no filler, no restating these instructions."""


def _posture_text(findings_set: set, evidence: dict, proposals: list) -> str:
    """Render the verifier-gated posture + investigated proposals into the brief prompt."""
    lines = ["HOST POSTURE — evidence-confirmed findings:\n"]
    rank = {"High": 0, "Medium": 1, "Low": 2}
    for p in sorted(proposals, key=lambda p: rank.get(p.severity, 3)):
        lines.append(f"[{p.severity}] {host_mod._LABEL.get(p.fid, p.fid)}")
        lines.append(f"    evidence: {evidence.get(p.fid, '(n/a)')}")
        if p.note:
            lines.append(f"    investigation: {p.note}")
        lines.append("")
    return "\n".join(lines)


def defensive_brief(brain, findings_set: set, evidence: dict, proposals: list) -> str:
    """One reasoning pass: the model triages the posture like a blue-team lead. Returns text."""
    prompt = _posture_text(findings_set, evidence, proposals)
    resp = brain.complete(_SYS, [{"role": "user", "content": prompt}])
    blocks = resp.get("content", []) if isinstance(resp, dict) else resp
    return " ".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()


def assess_host(brain, include_secrets: bool = False) -> tuple[str, set]:
    """Sweep the local host, investigate, and hand the posture to the model. Returns
    (brief, findings_set). Read-only."""
    scope = Scope(["127.0.0.1"])
    findings_set, evidence = host_mod.host_sweep("localhost", scope, include_secrets=include_secrets)
    proposals = remediate.plan({fid: evidence.get(fid, "") for fid in findings_set})
    if not findings_set:
        return "Host posture is clean — no evidence-gated findings to defend.", findings_set
    return defensive_brief(brain, findings_set, evidence, proposals), findings_set


# ------------------------------------------------------ acting defender (tool-use loop)

_AGENT_SYS = """You are Nexus as a blue-team defence lead, investigating a host you are
authorised to defend. Below is its evidence-confirmed posture. You have READ-ONLY tools to
dig deeper — use them to CONFIRM blast radius before concluding:
- live_connections(port): is anyone actually connected to an exposed service right now?
- service_detail(name): a service's real path, account, and whether its path is unquoted.
- path_writable(path): can a non-admin write here? (turns an unquoted path from theory to real)
- list_admins(): who holds local administrator rights.

Investigate what matters, then STOP calling tools and write the final brief:
1. TRIAGE — findings ordered by real blast radius; which ONE to fix first and why.
2. RISK — one concrete sentence per finding.
3. ATTACK CHAINS — where findings combine into something worse; say "none" if so.
4. FIRST MOVE — the single highest-value hardening action now.
Do not invent findings. These tools never change the system; fixes are proposed separately
for human approval. Be specific to THIS host; no filler."""

_BLUE_TOOLS = [
    {"name": "live_connections",
     "description": "Read-only: how many established connections (and remote addresses) are on "
                    "a local TCP port right now — e.g. is anyone using exposed RDP/SMB.",
     "input_schema": {"type": "object", "properties": {"port": {"type": "integer"}},
                      "required": ["port"]}},
    {"name": "service_detail",
     "description": "Read-only: a Windows service's ImagePath, start account, and state — to "
                    "judge whether an unquoted path is genuinely hijackable.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}},
                      "required": ["name"]}},
    {"name": "path_writable",
     "description": "Read-only: whether an unprivileged user can write to a filesystem path "
                    "(icacls) — the deciding factor for an unquoted-service-path escalation.",
     "input_schema": {"type": "object", "properties": {"path": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "list_admins",
     "description": "Read-only: members of the local Administrators group (by well-known SID, "
                    "locale-independent).",
     "input_schema": {"type": "object", "properties": {}}},
]


def _dispatch_blue(name: str, inp: dict) -> str:
    """Run one read-only host-investigation tool. Args are model-controlled, so they are
    strictly sanitised before ever reaching PowerShell. Returns a JSON string."""
    try:
        if name == "live_connections":
            port = int(inp.get("port", 0))
            if not (0 < port < 65536):
                return json.dumps({"error": "bad port"})
            n = remediate._live_connections(port)
            who = remediate._ps(
                f"(Get-NetTCPConnection -State Established -LocalPort {port} -EA SilentlyContinue |"
                f" Select-Object -First 6 -Expand RemoteAddress) -join ', '")
            return json.dumps({"port": port, "established": n, "remote_addresses": who or "none"})
        if name == "service_detail":
            svc = str(inp.get("name", ""))
            if not re.match(r"^[A-Za-z0-9_.\- ]{1,64}$", svc):
                return json.dumps({"error": "bad service name"})
            out = remediate._ps(
                f"$s=Get-CimInstance Win32_Service -Filter \"Name='{svc}'\" -EA SilentlyContinue;"
                f" if($s){{ ($s.PathName)+'||'+([string]$s.StartName)+'||'+$s.State }} else {{'not found'}}")
            path = out.split("||")[0] if "||" in out else out
            unquoted = bool(path) and not path.strip().startswith('"') and " " in path
            return json.dumps({"service": svc, "detail": out, "unquoted_path": unquoted})
        if name == "path_writable":
            path = str(inp.get("path", ""))
            # Model-controlled → must carry NO PowerShell-active metacharacter. Exclude quotes,
            # pipe/redirects, newlines, and — crucially — `$` and backtick (subexpression /
            # variable / escape), so a path like `C:\x$(...)` can never execute. Parens stay
            # allowed: `C:\Program Files (x86)` is a real path and is inert without a `$`.
            if not re.match(r"^[A-Za-z]:\\[^\"|<>$`\r\n]{0,200}$", path):
                return json.dumps({"error": "bad path"})
            # Defence in depth: pass it inside a PowerShell single-quoted string (which does NO
            # interpolation at all), doubling any embedded quote — so nothing in the path is ever
            # evaluated even if the allowlist above is one day loosened.
            out = remediate._ps("icacls '%s'" % path.replace("'", "''"))
            who = ("Пользователи", "Users", "Authenticated Users", "Everyone", "Все")
            rights = (":(W)", ":(M)", ":(F)", "(WD)", "(AD)")
            writable = bool(out) and any(w in ln and any(r in ln for r in rights)
                                         for ln in out.splitlines() for w in who)
            return json.dumps({"path": path, "writable_by_nonadmin": writable})
        if name == "list_admins":
            out = remediate._ps(
                "try{$g=Get-LocalGroup -SID 'S-1-5-32-544' -EA Stop;"
                " ((Get-LocalGroupMember -Group $g.Name -EA Stop)|%{$_.Name}) -join ', '}"
                "catch{'n/a'}")
            return json.dumps({"local_admins": out or "n/a"})
        return json.dumps({"error": f"unknown tool {name}"})
    except Exception as e:  # noqa: BLE001 — a tool failure is data for the model, not a crash
        return json.dumps({"error": f"{type(e).__name__}: {e}"})


def defend_agent(brain, findings_set, evidence, proposals, max_steps=6, on_step=None) -> str:
    """The acting defender: the model drives the read-only host tools to confirm blast radius,
    then writes its brief. Read-only — no system change. Returns the final brief text."""
    system = _AGENT_SYS
    messages = [{"role": "user", "content": _posture_text(findings_set, evidence, proposals)
                 + "\nInvestigate with the tools where it changes the picture, then give the brief."}]
    for step in range(max_steps):
        resp = brain.complete(system, messages, tools=_BLUE_TOOLS)
        content = resp.get("content", []) if isinstance(resp, dict) else resp
        messages.append({"role": "assistant", "content": content})
        tool_uses = [b for b in content if b.get("type") == "tool_use"]
        text = " ".join(b.get("text", "") for b in content if b.get("type") == "text").strip()
        if on_step:
            on_step(step, text, tool_uses)
        if not tool_uses:
            return text
        results = []
        for tu in tool_uses:
            out = _dispatch_blue(tu.get("name", ""), tu.get("input", {}) or {})
            results.append({"type": "tool_result", "tool_use_id": tu.get("id", ""), "content": out})
        messages.append({"role": "user", "content": results})
    # Budget spent — ask for the brief with no more tools so the run always concludes.
    messages.append({"role": "user", "content": "Stop investigating and give your final brief now."})
    resp = brain.complete(system, messages, tools=None)
    content = resp.get("content", []) if isinstance(resp, dict) else resp
    return " ".join(b.get("text", "") for b in content if b.get("type") == "text").strip()


# --------------------------------------------------------- autonomous guardian (two-tier)

def guard(brain, state_path="data/guardian_state.json", interval: float = 0.0,
          include_secrets: bool = False, emit=print) -> int:
    """Autonomous defender: cheap, deterministic host sweeps on a timer, and the (expensive) AI
    brain engaged ONLY when the posture CHANGES — a new finding. Two tiers on purpose: continuous
    watching stays free, the model is spent only where it earns its keep. A quiet patrol says so
    and does not call the model; a NEW hole triggers a defensive brief on exactly what changed."""
    import socket
    import sys
    import time
    from .sentinel import patrol_once, _fmt_posture

    if emit is print:  # keep the glyph-rich posture readable on a legacy-codepage console
        for _s in (sys.stdout, sys.stderr):
            try:
                _s.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, ValueError):
                pass
    kind = host_mod.make_kind(include_secrets)
    scope = Scope(["127.0.0.1"])
    asset = socket.gethostname()
    emit(f"guardian: watching {asset} · AI escalates only on change · "
         f"interval {interval or 'once'}")
    try:
        while True:
            diff = patrol_once(kind, asset, scope, state_path)
            if diff["new"]:
                emit(_fmt_posture(kind, diff))
                new_fids = set(diff["new"])
                evidence = diff["evidence"]
                proposals = remediate.plan({fid: evidence.get(fid, "") for fid in new_fids})
                emit("\n── AI defence brief · what changed and what to do ──")
                emit(defensive_brief(brain, new_fids, evidence, proposals))
            else:
                emit(f"[{diff['at']}] {asset}: stable — no change, AI idle "
                     f"({len(diff['persisting'])} known open).")
            if interval <= 0:
                return 0
            time.sleep(interval)
    except KeyboardInterrupt:
        emit("\nguardian: stopped.")
        return 0


def _build_brain(model: str, ollama_url: str):
    from .local import Ollama
    return Ollama(model=model, url=ollama_url)


def main(argv=None) -> int:
    import argparse
    import sys
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(
        prog="nexus-blue",
        description="Defensive brain: the model triages the live, evidence-gated host posture "
                    "like a blue-team lead (read-only).")
    p.add_argument("--model", default="qwen2.5:7b", help="Ollama model to reason with")
    p.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    p.add_argument("--include-secrets", action="store_true",
                   help="also fold in the credential-file check (opt-in; sensitive)")
    p.add_argument("--oneshot", action="store_true",
                   help="one reasoning pass over the posture instead of the acting agent")
    p.add_argument("--apply", metavar="FINDING",
                   help="apply the fix for one finding id (e.g. exposed-service). Dry-run "
                        "unless --yes is also given.")
    p.add_argument("--yes", action="store_true",
                   help="with --apply, actually run the fix (a real, confirmed system change)")
    p.add_argument("--authorized", action="store_true",
                   help="affirm you are authorised to inspect this host (required)")
    p.add_argument("--guard", action="store_true",
                   help="autonomous guardian: continuous deterministic sweeps, AI engaged only "
                        "when the posture changes (a new finding)")
    p.add_argument("--interval", type=float, default=0.0,
                   help="with --guard, seconds between sweeps (0 = one pass and exit)")
    args = p.parse_args(argv)
    if not args.authorized:
        print("refusing: pass --authorized to affirm you may inspect this host.", file=sys.stderr)
        return 2

    brain = _build_brain(args.model, args.ollama_url)

    if args.guard:
        return guard(brain, interval=args.interval, include_secrets=args.include_secrets)

    scope = Scope(["127.0.0.1"])
    found, evidence = host_mod.host_sweep("localhost", scope, include_secrets=args.include_secrets)
    if not found:
        print("Host posture is clean — no evidence-gated findings to defend.")
        return 0
    proposals = remediate.plan({fid: evidence.get(fid, "") for fid in found})

    if args.apply:
        prop = next((p for p in proposals if p.fid == args.apply), None)
        if prop is None:
            print(f"no open finding '{args.apply}' — nothing to apply. "
                  f"open: {', '.join(sorted(found))}")
            return 1
        if not args.yes:
            print(f"DRY RUN — fix for {args.apply}:\n  command:  {prop.command}\n"
                  f"  rollback: {prop.rollback}\n  risk:     {prop.risk}\n"
                  f"Re-run with --yes to actually apply (this changes your system).")
            return 0
        print(f"applying fix for {args.apply}…", flush=True)
        res = remediate.apply(prop, confirm=True)
        if not res.get("applied"):
            print(f"  not applied: {res.get('reason')}")
            return 1
        verdict = {True: "✓ verified fixed (re-sweep confirms it is gone)",
                   False: "✗ still present after apply — check the command",
                   None: f"? could not verify ({res.get('verify_error')})"}[res.get("verified_fixed")]
        print(f"  applied. {verdict}\n  rollback if needed: {res['rollback']}")
        return 0

    if args.oneshot:
        print(f"nexus-blue: reasoning over this host with {args.model}…\n", flush=True)
        print(defensive_brief(brain, found, evidence, proposals))
    else:
        print(f"nexus-blue: {args.model} is investigating this host (read-only)…\n", flush=True)

        def on_step(step, text, tool_uses):
            for tu in tool_uses:
                print(f"  → {tu.get('name')}({tu.get('input', {})})", flush=True)
        brief = defend_agent(brain, found, evidence, proposals, on_step=on_step)
        print("\n" + brief)
    print(f"\n[{len(found)} evidence-gated finding(s) triaged]", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
