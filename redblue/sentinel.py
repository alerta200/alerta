"""sentinel.py — Nexus turned from attacker to defender.

The offensive engine is a brain (Claude/adapter) driving tools past a perfect verifier.
Defence needs the same verifier but *not* the brain on every tick: a live estate has to be
watched continuously, and paying an LLM to re-derive the same recon every minute is absurd.

So the sentinel runs a fixed deterministic SWEEP, grades the transcript through the very
same evidence gate the red side uses, and then does the one thing a one-shot pentest never
does: it DIFFS this sweep against the last one. That diff is the whole point of defence —

    NEW         a hole that was not here last time (a regression, or fresh surface),
    STILL-OPEN  a known hole nobody has fixed yet (age is the pressure),
    FIXED       a hole that is gone — proof the hardening actually worked.

The diff/state/posture machinery is ASSET-AGNOSTIC: a `SweepKind` bundles a sweep function
with its finding vocabulary, so the same defender loop watches a *website from outside*
(kind=web, redblue.tools) and a *host from inside* (kind=host, redblue.host). The brain is
escalated separately (redblue.agent) only against surface a sweep flags, so the continuous
tier stays free and the expensive tier stays rare. Everything is deterministic and
scope-gated: same authorisation model as the rest of Nexus.
"""
from __future__ import annotations

import json
import os
import time
from collections import namedtuple
from datetime import datetime, timezone

from . import findings
from .scope import Scope, ScopeError
from . import tools

# Shared severity vocabulary across every asset kind, worst-first, so posture reports rank
# identically whether the finding came from a web sweep or a host sweep.
_SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# A pluggable asset kind: how to sweep it and how to name/grade/fix what turns up.
#   sweep(asset, scope) -> (findings:set[str], evidence:dict[str,str])
SweepKind = namedtuple("SweepKind", "name sweep label severity remediation")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ----------------------------------------------------------------------------- web sweep

def _tool_call(transcript: list, name: str, tin: dict, scope: Scope) -> dict:
    """Run one tool and append a well-formed tool_use/tool_result pair to `transcript`
    (the exact shape findings.analyze parses). Returns the parsed result dict (or {})."""
    out, is_error = tools.dispatch(name, tin, scope)
    uid = f"{name}-{len(transcript)}"
    transcript.append({"role": "assistant",
                       "content": [{"type": "tool_use", "id": uid, "name": name, "input": tin}]})
    transcript.append({"role": "user",
                       "content": [{"type": "tool_result", "tool_use_id": uid,
                                    "content": out, "is_error": is_error}]})
    if is_error:
        return {}
    try:
        return json.loads(out)
    except (json.JSONDecodeError, TypeError):
        return {}


def web_sweep(target: str, scope: Scope) -> tuple[set, dict]:
    """One deterministic pass over a web `target`. Drives the core recon/exploit tools, then
    opportunistically chases login-bypass + broken-access surface that discovery reveals,
    and grades the whole transcript through the evidence gate. No LLM involved."""
    t: list = []
    _tool_call(t, "security_headers", {"url": target}, scope)
    _tool_call(t, "http_probe", {"url": target}, scope)
    disc = _tool_call(t, "content_discovery", {"base_url": target}, scope)
    _tool_call(t, "fuzz_params", {"base_url": target}, scope)

    # Opportunistic deep checks: a login endpoint invites an auth-bypass probe, and any
    # collection-shaped path invites a broken-access read (carrying any token the bypass won).
    # Purely driven by what discovery actually found — no target-specific knowledge baked in.
    paths = [(d.get("path") or "") for d in disc.get("discovered", [])]
    for p in paths:
        if any(k in p.lower() for k in ("login", "signin", "session", "auth")):
            _tool_call(t, "login_test", {"base_url": target, "login_path": p}, scope)
    for p in paths:
        if any(k in p.lower() for k in ("user", "account", "customer", "order", "admin", "api")):
            _tool_call(t, "read_collection", {"base_url": target, "path": p}, scope)

    return findings.analyze(t)


# The built-in web asset kind: finding names/severities/fixes come straight from the pentest
# report's single source of truth (findings._SPEC / _REMEDIATION) so red and blue agree.
WEB = SweepKind(
    name="web",
    sweep=web_sweep,
    label={fid: lab for fid, lab, _sev in findings._SPEC},
    severity={fid: sev for fid, _lab, sev in findings._SPEC},
    remediation=dict(findings._REMEDIATION),
)


# ----------------------------------------------------------------------------- diff engine

def _load_state(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_state(path: str, state: dict) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, ensure_ascii=False)


def patrol_once(kind: SweepKind, asset: str, scope: Scope, state_path: str) -> dict:
    """Run one sweep of `asset`, diff it against the persisted estate state, update the
    state, and return the diff {new, persisting, fixed} — each a list of finding ids."""
    open_now, evidence = kind.sweep(asset, scope)
    estate = _load_state(state_path)
    # Namespace the state by kind so a web target and a host of the same name never collide.
    per_asset = estate.setdefault(f"{kind.name}:{asset}", {})
    open_before = {fid for fid, rec in per_asset.items() if rec.get("status") == "open"}

    new = sorted(open_now - open_before)
    persisting = sorted(open_now & open_before)
    fixed = sorted(open_before - open_now)
    ts = _now()

    for fid in open_now:
        rec = per_asset.setdefault(fid, {"first_seen": ts, "sightings": 0})
        rec["status"] = "open"
        rec["last_seen"] = ts
        rec["sightings"] = rec.get("sightings", 0) + 1
        rec["evidence"] = evidence.get(fid, rec.get("evidence", ""))
        rec["severity"] = kind.severity.get(fid, "Info")
    for fid in fixed:
        per_asset[fid]["status"] = "fixed"
        per_asset[fid]["fixed_at"] = ts

    _save_state(state_path, estate)
    return {"kind": kind.name, "asset": asset, "at": ts, "new": new,
            "persisting": persisting, "fixed": fixed, "evidence": evidence, "state": per_asset}


def _fmt_posture(kind: SweepKind, diff: dict) -> str:
    """Render one patrol tick as a defender would read it: severity-ranked, diff-tagged."""
    def _rank(fid: str) -> int:
        return _SEV_RANK.get(kind.severity.get(fid, "Info"), 4)

    def _line(fid: str, tag: str) -> str:
        sev = kind.severity.get(fid, "Info")
        label = kind.label.get(fid, fid)
        rec = diff["state"].get(fid, {})
        age = f" ×{rec.get('sightings', 1)}" if tag == "STILL-OPEN" else ""
        ev = diff["evidence"].get(fid) or rec.get("evidence", "")
        fix = kind.remediation.get(fid, "")
        head = f"  [{tag:9}] {sev:8} {label}{age}"
        body = f"\n      evidence: {ev}" if ev else ""
        remed = f"\n      fix:      {fix}" if tag != "FIXED" and fix else ""
        return head + body + remed

    rows = [_line(fid, "NEW") for fid in sorted(diff["new"], key=_rank)]
    rows += [_line(fid, "STILL-OPEN") for fid in sorted(diff["persisting"], key=_rank)]
    rows += [_line(fid, "FIXED") for fid in diff["fixed"]]

    open_ct = len(diff["new"]) + len(diff["persisting"])
    header = (f"[{diff['at']}] {kind.name}:{diff['asset']}  ·  {open_ct} open "
              f"(+{len(diff['new'])} new, {len(diff['fixed'])} fixed)")
    if not rows:
        return header + "\n  clean — no evidence-gated findings this sweep."
    return header + "\n" + "\n".join(rows)


# ----------------------------------------------------------------------------- CLI

def run_patrol(kind: SweepKind, asset: str, scope: Scope, state_path: str,
               interval: float, emit=print) -> int:
    """The shared patrol loop for any asset kind. interval<=0 = one tick and exit."""
    emit(f"sentinel[{kind.name}]: watching {asset} · state {state_path} · "
         f"interval {interval or 'once'}")
    try:
        while True:
            diff = patrol_once(kind, asset, scope, state_path)
            emit(_fmt_posture(kind, diff))
            if interval <= 0:
                return 0
            time.sleep(interval)
    except KeyboardInterrupt:
        emit("\nsentinel: stopped.")
        return 0


def main(argv=None) -> int:
    import argparse
    import sys
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(
        prog="nexus-sentinel",
        description="Continuous defensive patrol: sweep an owned web target, grade through "
                    "the evidence gate, and diff against the last sweep (new/still-open/fixed). "
                    "For host-internal posture see `python -m redblue.host`.")
    p.add_argument("--target", required=True, help="base URL of the asset you own and defend")
    p.add_argument("--scope", action="append", default=[],
                   help="authorised host/CIDR (repeatable). Defaults to the target's host.")
    p.add_argument("--state", default="data/sentinel_state.json",
                   help="estate state file (finding history + status across sweeps)")
    p.add_argument("--interval", type=float, default=0.0,
                   help="seconds between sweeps; 0 = a single patrol tick and exit")
    p.add_argument("--authorized", action="store_true",
                   help="affirm you are authorised to scan the target (required)")
    args = p.parse_args(argv)

    if not args.authorized:
        print("refusing: pass --authorized to affirm you own / may scan this target.",
              file=sys.stderr)
        return 2

    entries = list(args.scope)
    if not entries:
        from urllib.parse import urlparse
        host = urlparse(args.target if "://" in args.target else "http://" + args.target).hostname
        if host:
            entries.append(host)
    try:
        scope = Scope(entries)
    except ScopeError as e:
        print(f"bad scope: {e}", file=sys.stderr)
        return 2

    return run_patrol(WEB, args.target, scope, args.state, args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
