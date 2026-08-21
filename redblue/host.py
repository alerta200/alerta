"""host.py — Nexus defender, Layer B: attach to the system from the INSIDE.

The web sentinel looks at a site from outside, like an attacker. That is the weakest form
of "hooking in". Real defence walks the host: which services face the network, is Defender
actually on, is the firewall up, which service paths are hijackable. This module runs those
read-only checks and feeds the SAME diff engine (redblue.sentinel) so host posture gets the
same new / still-open / fixed tracking a web target does.

Discipline carried from the red side: ZERO false positives. A check emits a finding only on
a concrete, evidence-backed bad condition — Defender being ON produces nothing, an enabled
firewall produces nothing. We report holes, not inventory.

Everything here is read-only Windows introspection (no state is changed). Remediation
(closing a port, quoting a path) is a later, opt-in, confirm-first layer — never automatic.
The secret-file check is OFF by default and only runs under an explicit opt-in, because
enumerating credential locations is sensitive even on your own machine.
"""
from __future__ import annotations

import json
import socket
import subprocess

from .scope import Scope, ScopeError
from .sentinel import SweepKind, run_patrol, patrol_once, _fmt_posture
from . import remediate

# Host-layer finding vocabulary (kept here, not in findings._SPEC, which is the web classes).
_LABEL = {
    "exposed-service": "Network-exposed sensitive service",
    "defender-disabled": "Endpoint protection disabled",
    "firewall-disabled": "Host firewall disabled",
    "unquoted-service-path": "Unquoted service path (privilege escalation)",
    "exposed-secret-file": "Secret file in a default location",
    "smbv1-enabled": "SMBv1 protocol enabled (wormable)",
}
_SEVERITY = {
    "exposed-service": "High",
    "defender-disabled": "High",
    "firewall-disabled": "High",
    "unquoted-service-path": "Medium",
    "exposed-secret-file": "High",
    "smbv1-enabled": "High",
}
_REMEDIATION = {
    "exposed-service": "Bind sensitive services to loopback/VPN or firewall them to known IPs.",
    "defender-disabled": "Re-enable Microsoft Defender real-time protection.",
    "firewall-disabled": "Enable the Windows Firewall on every profile.",
    "unquoted-service-path": "Quote each service ImagePath so a planted C:\\Program.exe can't hijack it.",
    "exposed-secret-file": "Move the secret out of the default path, tighten its ACL, and rotate it.",
    "smbv1-enabled": "Disable the legacy SMBv1 protocol; modern Windows uses SMBv2/3.",
}

# One read-only PowerShell pass. Emits one compact JSON object per finding on its own line
# ({"id":..., "evidence":...}); a clean host prints nothing. Locale-independent (Defender/
# firewall/service cmdlets don't depend on group names). $INCLUDE_SECRETS is templated in.
_PS = r"""
$ErrorActionPreference='SilentlyContinue'
function Emit($id,$ev){ [Console]::WriteLine((@{id=$id;evidence=$ev} | ConvertTo-Json -Compress)) }

$sens = @{3389='RDP';445='SMB';139='NetBIOS';135='RPC';5985='WinRM-HTTP';5986='WinRM-HTTPS';
          22='SSH';23='Telnet';21='FTP';3306='MySQL';5432='Postgres';6379='Redis';
          27017='Mongo';1433='MSSQL';9200='Elasticsearch';11211='memcached';5900='VNC'}
$exp = Get-NetTCPConnection -State Listen | Where-Object {
        $_.LocalAddress -notin '127.0.0.1','::1' -and $sens.ContainsKey([int]$_.LocalPort) }
if ($exp) {
  $d = ($exp | Sort-Object LocalPort -Unique | ForEach-Object {
          $pn=(Get-Process -Id $_.OwningProcess).ProcessName
          "{0} (TCP/{1}, {2})" -f $sens[[int]$_.LocalPort], $_.LocalPort, $pn }) -join ', '
  Emit 'exposed-service' "network-reachable sensitive services: $d"
}

$mp = Get-MpComputerStatus
if ($mp -and -not $mp.RealTimeProtectionEnabled) {
  Emit 'defender-disabled' 'Microsoft Defender real-time protection is OFF.' }

$off = (Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Name
if ($off) { Emit 'firewall-disabled' ("Windows Firewall disabled on profile(s): " + ($off -join ', ')) }

$uq = Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -and -not $_.PathName.Trim().StartsWith('"') -and
        $_.PathName -match '^\s*[A-Za-z]:\\[^"]* [^"]*\.exe' -and
        (($_.PathName -split '\.exe')[0] -match ' ') }
if ($uq) {
  $n = (($uq | Select-Object -First 10).Name) -join ', '
  Emit 'unquoted-service-path' "unquoted ImagePath with spaces (C:\Program.exe hijack): $n" }

$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
if ($smb1 -eq $true) {
  Emit 'smbv1-enabled' 'SMBv1 (SMB1) server protocol is ENABLED — a legacy wormable protocol (EternalBlue/WannaCry class).' }

if ($INCLUDE_SECRETS) {
  $paths = @('.aws\credentials','.ssh\id_rsa','.ssh\id_ed25519','.git-credentials','.netrc','.kube\config')
  $hit = foreach ($t in $paths) { if (Test-Path (Join-Path $env:USERPROFILE $t)) { $t } }
  if ($hit) { Emit 'exposed-secret-file' ("credential files present in profile: " + ($hit -join ', ')) }
}
"""


def host_sweep(asset: str, scope: Scope, include_secrets: bool = False) -> tuple[set, dict]:
    """Run the read-only host checks and return (findings:set, evidence:dict). Deterministic,
    no LLM, no state change. `asset`/`scope` are the local host (introspection is local-only)."""
    scope.require("127.0.0.1")   # host layer only ever inspects the authorised local machine
    script = _PS.replace("$INCLUDE_SECRETS", "$true" if include_secrets else "$false")
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", script],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        return set(), {"_error": f"host sweep could not run: {e}"}

    evidence: dict = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        fid = rec.get("id")
        if fid in _LABEL:
            evidence[fid] = rec.get("evidence", "")
    return set(evidence), evidence


def make_kind(include_secrets: bool = False) -> SweepKind:
    return SweepKind(
        name="host",
        sweep=lambda asset, scope: host_sweep(asset, scope, include_secrets=include_secrets),
        label=_LABEL, severity=_SEVERITY, remediation=_REMEDIATION)


def main(argv=None) -> int:
    import argparse
    import sys
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    p = argparse.ArgumentParser(
        prog="nexus-host",
        description="Defender Layer B: read-only host posture (exposed services, Defender, "
                    "firewall, hijackable service paths) with the same new/still-open/fixed diff.")
    p.add_argument("--asset", default=socket.gethostname(),
                   help="label for this host in the state file (default: hostname)")
    p.add_argument("--state", default="data/sentinel_state.json")
    p.add_argument("--interval", type=float, default=0.0,
                   help="seconds between sweeps; 0 = one tick and exit")
    p.add_argument("--include-secrets", action="store_true",
                   help="also check for credential files in the user profile (opt-in; sensitive)")
    p.add_argument("--remediate", action="store_true",
                   help="after the sweep, investigate open findings and print fix PROPOSALS "
                        "(read-only; nothing is applied)")
    p.add_argument("--authorized", action="store_true",
                   help="affirm you are authorised to inspect this host (required)")
    args = p.parse_args(argv)

    if not args.authorized:
        print("refusing: pass --authorized to affirm you may inspect this host.", file=sys.stderr)
        return 2
    try:
        scope = Scope(["127.0.0.1"])
    except ScopeError as e:
        print(f"bad scope: {e}", file=sys.stderr)
        return 2

    kind = make_kind(args.include_secrets)
    if not args.remediate:
        return run_patrol(kind, args.asset, scope, args.state, args.interval)

    # Detect -> investigate -> propose, in one pass. Single tick: a remediation plan is a
    # point-in-time decision, not something to loop.
    diff = patrol_once(kind, args.asset, scope, args.state)
    print(_fmt_posture(kind, diff))
    open_findings = {fid: diff["evidence"].get(fid, "")
                     for fid in (diff["new"] + diff["persisting"])}
    print("\n" + remediate.format_plan(remediate.plan(open_findings)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
