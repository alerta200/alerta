"""estate.py — Nexus defender: defend the WHOLE infrastructure, not one asset.

The sentinel watches a web target; host.py watches a machine. Real infrastructure is many
of each. This layer is the spine that ties them into ONE estate: a declared set of assets
(web services + hosts), each swept and diffed through the shared engine, rolled up into a
single posture with the one line a defender actually acts on —

    what changed since the last patrol.

That delta is the autonomy signal: a NEW High finding is the thing to wake someone for; an
all-quiet patrol is the thing that lets them sleep. The estate reuses the asset-agnostic
diff engine (redblue.sentinel) and the shared, kind:asset-namespaced state file, so a host
and a web service of the same name never collide and each carries its own history.

Read-only throughout: the estate detects and tracks; it never changes a system. Remediation
stays the separate, confirm-first act in redblue.remediate.
"""
from __future__ import annotations

import json

from . import host as host_mod
from .scope import Scope, ScopeError
from .sentinel import (WEB, SweepKind, _SEV_RANK, _fmt_posture, patrol_once)

_HIGH = {"Critical", "High"}


def resolve_kind(name: str, include_secrets: bool = False) -> SweepKind:
    """Map an asset-kind string from an estate config to its SweepKind."""
    if name == "web":
        return WEB
    if name == "host":
        return host_mod.make_kind(include_secrets)
    raise ValueError(f"unknown asset kind {name!r} (expected 'web' or 'host')")


def load_estate(path: str, include_secrets: bool = False) -> list:
    """Read an estate config → [(kind, asset, scope)]. Config shape:
        {"assets": [{"kind": "host", "asset": "PC", "scope": ["127.0.0.1"]},
                    {"kind": "web",  "asset": "http://svc", "scope": ["svc"]}]}
    A web asset with no scope defaults to its own host; a host asset to loopback."""
    with open(path, encoding="utf-8") as f:
        spec = json.load(f)
    out = []
    for a in spec.get("assets", []):
        kind = resolve_kind(a["kind"], include_secrets)
        asset = a["asset"]
        entries = list(a.get("scope") or [])
        if not entries:
            if a["kind"] == "web":
                from urllib.parse import urlparse
                h = urlparse(asset if "://" in asset else "http://" + asset).hostname
                entries = [h] if h else []
            else:
                entries = ["127.0.0.1"]
        out.append((kind, asset, Scope(entries)))
    return out


def patrol_estate(assets: list, state_path: str) -> list:
    """Sweep every asset once; return [(kind, diff)] so callers keep each finding's severity."""
    results = []
    for kind, asset, scope in assets:
        results.append((kind, patrol_once(kind, asset, scope, state_path)))
    return results


def _headline(pairs: list) -> str:
    open_ct = new_ct = fixed_ct = high_ct = 0
    for kind, d in pairs:
        opens = d["new"] + d["persisting"]
        open_ct += len(opens)
        new_ct += len(d["new"])
        fixed_ct += len(d["fixed"])
        high_ct += sum(1 for fid in opens if kind.severity.get(fid, "Info") in _HIGH)
    return (f"{len(pairs)} assets · {open_ct} open ({high_ct} High) · "
            f"+{new_ct} new, {fixed_ct} fixed since last patrol")


def _changes(pairs: list) -> str:
    """The alert section: every NEW and FIXED finding across the estate, worst-first."""
    news, fixes = [], []
    for kind, d in pairs:
        for fid in d["new"]:
            sev = kind.severity.get(fid, "Info")
            news.append((_SEV_RANK.get(sev, 4), sev, kind.label.get(fid, fid),
                         f"{kind.name}:{d['asset']}"))
        for fid in d["fixed"]:
            fixes.append((kind.label.get(fid, fid), f"{kind.name}:{d['asset']}"))
    if not news and not fixes:
        return "  no changes since last patrol — estate stable."
    lines = []
    for _rank, sev, label, where in sorted(news):
        lines.append(f"  NEW    {sev:8} {label:42} @ {where}")
    for label, where in fixes:
        lines.append(f"  FIXED  {'':8} {label:42} @ {where}")
    return "\n".join(lines)


def format_estate(pairs: list) -> str:
    from datetime import datetime, timezone
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    out = [f"════ ESTATE POSTURE ════  [{ts}]",
           _headline(pairs),
           "",
           "── CHANGES SINCE LAST PATROL ──",
           _changes(pairs),
           "",
           "── PER-ASSET DETAIL ──"]
    for kind, d in pairs:
        out.append(_fmt_posture(kind, d))
    return "\n".join(out)


def run_estate(assets: list, state_path: str, interval: float, emit=print) -> int:
    import time
    emit(f"estate: defending {len(assets)} asset(s) · state {state_path} · "
         f"interval {interval or 'once'}")
    try:
        while True:
            emit(format_estate(patrol_estate(assets, state_path)))
            if interval <= 0:
                return 0
            time.sleep(interval)
    except KeyboardInterrupt:
        emit("\nestate: stopped.")
        return 0


def main(argv=None) -> int:
    import argparse
    import socket
    import sys
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(
        prog="nexus-estate",
        description="Defend a whole infrastructure: sweep every declared asset (hosts + web "
                    "services), roll up one posture, and surface what changed since last patrol.")
    p.add_argument("--config", help="estate config JSON (assets[]). Omit = just this host.")
    p.add_argument("--state", default="data/sentinel_state.json")
    p.add_argument("--interval", type=float, default=0.0,
                   help="seconds between patrols; 0 = one patrol and exit")
    p.add_argument("--include-secrets", action="store_true",
                   help="host assets also check credential files (opt-in; sensitive)")
    p.add_argument("--authorized", action="store_true",
                   help="affirm you are authorised to inspect every asset in scope (required)")
    args = p.parse_args(argv)

    if not args.authorized:
        print("refusing: pass --authorized to affirm you own / may scan every asset.",
              file=sys.stderr)
        return 2
    try:
        if args.config:
            assets = load_estate(args.config, args.include_secrets)
        else:
            # No config: the estate is just this machine — works out of the box.
            assets = [(host_mod.make_kind(args.include_secrets),
                       socket.gethostname(), Scope(["127.0.0.1"]))]
    except (OSError, ValueError, KeyError, ScopeError) as e:
        print(f"bad estate config: {e}", file=sys.stderr)
        return 2

    return run_estate(assets, args.state, args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
