"""remediate.py — Nexus defender, Layer D: from a finding to a FIX, proposal-first.

Detection without response leaves the human holding the bag. This layer closes the loop —
but on a hard rule: it NEVER changes the system on its own. For each open host finding it

  1) INVESTIGATES read-only to sharpen the call (is that unquoted path actually writable by
     a low-priv user, or just hygiene? is anyone connected to that open RDP right now?), then
  2) PROPOSES an exact, reversible command with its verify + rollback and a risk grade.

Applying a proposal is a separate, explicit, confirm-first act (`apply`), because closing a
port or disabling a service is outward-facing and hard to undo. The fix commands are curated
and deterministic — never model-generated — so a proposal can't hallucinate a destructive
command. (The LLM brain plugs in later for the *narrative* of an investigation, not for
inventing the commands.)
"""
from __future__ import annotations

import subprocess
from collections import namedtuple

# What a fix looks like: why it matters, the exact command to apply it, how to confirm it
# took, how to undo it, a risk grade, and any investigation note that sharpened the call.
Proposal = namedtuple("Proposal", "fid title severity why command verify rollback risk note")


def _ps(script: str, timeout: int = 20) -> str:
    """Run a PowerShell snippet, return stdout (empty on failure). Forces UTF-8 both ways so
    non-ASCII output — e.g. a Cyrillic account name like `Администратор` — comes back intact
    instead of cp1251 mojibake. Investigation callers are read-only; `apply` changes state."""
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return (p.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


# --------------------------------------------------------------- read-only investigation

def _live_connections(port: int) -> int:
    out = _ps(f"(Get-NetTCPConnection -State Established -LocalPort {port} "
              f"-ErrorAction SilentlyContinue | Measure-Object).Count")
    try:
        return int(out.splitlines()[-1]) if out else 0
    except (ValueError, IndexError):
        return 0


def _root_writable_by_users() -> bool | None:
    """Is C:\\ writable by an unprivileged principal? That is what turns an unquoted service
    path from hygiene into a real C:\\Program.exe hijack. Read-only ACL read via icacls."""
    out = _ps("icacls C:\\")
    if not out:
        return None
    risky_who = ("Пользователи", "Users", "Authenticated Users", "Everyone", "Все")
    risky_rights = (":(W)", ":(M)", ":(F)", "(WD)", "(AD)")   # write / modify / full / add-file
    for line in out.splitlines():
        if any(w in line for w in risky_who) and any(r in line for r in risky_rights):
            return True
    return False


# ------------------------------------------------------------------------ fix builders

def _fix_exposed_service(evidence: str) -> Proposal:
    live = []
    if "RDP" in evidence:
        n = _live_connections(3389)
        live.append(f"RDP has {n} live session(s) right now" if n else "RDP has no live session")
    note = "; ".join(live) if live else ""
    # RDP is the highest-value item; give its exact reversible firewall fix. SMB/WinRM get the
    # same shape. Firewalling (not disabling the service) is the least-disruptive reversible move.
    cmd, verify, rollback = "", "", ""
    if "RDP" in evidence:
        cmd = "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'   # blocks inbound RDP"
        verify = "(Get-NetFirewallRule -DisplayGroup 'Remote Desktop').Enabled  # -> all False"
        rollback = "Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'"
    elif "SMB" in evidence:
        cmd = ("New-NetFirewallRule -DisplayName 'Nexus-block-SMB' -Direction Inbound "
               "-Protocol TCP -LocalPort 445 -Action Block")
        verify = "Get-NetFirewallRule -DisplayName 'Nexus-block-SMB'"
        rollback = "Remove-NetFirewallRule -DisplayName 'Nexus-block-SMB'"
    return Proposal(
        "exposed-service", "Firewall network-reachable sensitive services", "High",
        "Services like RDP/SMB reachable from the network are the #1 lateral-movement and "
        "brute-force surface; they should face only a VPN or an allow-listed set of IPs.",
        cmd or "# Restrict the listed services to loopback/VPN or firewall them to known IPs.",
        verify, rollback,
        "Medium — may cut off legitimate remote access; confirm you have another way in first.",
        note)


def _fix_unquoted_path(evidence: str) -> Proposal:
    writable = _root_writable_by_users()
    if writable is True:
        sev, risk = "High", "Low to apply (quoting is safe), but the flaw is CONFIRMED exploitable."
        note = "C:\\ is writable by unprivileged users → a planted C:\\Program.exe WOULD hijack these."
    elif writable is False:
        sev, risk = "Low", "Low — hardening only; C:\\ root is not user-writable here."
        note = "C:\\ is not user-writable → hygiene, not a confirmed escalation path."
    else:
        sev, risk = "Medium", "Low to apply; exploitability depends on C:\\ ACLs (could not read)."
        note = "Could not read C:\\ ACL — treat as hardening until confirmed."
    return Proposal(
        "unquoted-service-path", "Quote hijackable service ImagePaths", sev,
        "An unquoted service path with a space lets a file planted earlier in the path "
        "(e.g. C:\\Program.exe) run as the service account.",
        "$s='<ServiceName>'; $p=(Get-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$s\")."
        "ImagePath; Set-ItemProperty \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$s\" ImagePath "
        "\"`\"$p`\"\"   # wrap the exe path in quotes (repeat per service)",
        "Get-CimInstance Win32_Service | ? Name -eq '<ServiceName>' | Select PathName  # -> quoted",
        "Restore the original ImagePath value saved before the change.",
        risk, note)


def _fix_defender(evidence: str) -> Proposal:
    return Proposal(
        "defender-disabled", "Re-enable Defender real-time protection", "High",
        "Real-time protection off means malware executes unscanned.",
        "Set-MpPreference -DisableRealtimeMonitoring $false",
        "(Get-MpComputerStatus).RealTimeProtectionEnabled  # -> True",
        "Set-MpPreference -DisableRealtimeMonitoring $true", "Low.", "")


def _fix_firewall(evidence: str) -> Proposal:
    return Proposal(
        "firewall-disabled", "Enable the Windows Firewall", "High",
        "A disabled firewall profile exposes every listening service to its network.",
        "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
        "Get-NetFirewallProfile | Select Name,Enabled  # -> all True",
        "Set-NetFirewallProfile -Profile <name> -Enabled False   # only what was off before",
        "Low to Medium — a misconfigured ruleset could block wanted traffic once on.", "")


def _fix_secret_file(evidence: str) -> Proposal:
    return Proposal(
        "exposed-secret-file", "Protect and rotate exposed credential files", "High",
        "Credentials in default paths are the first thing malware and infostealers grab.",
        "# 1) move the file out of the default path  2) icacls <file> /inheritance:r "
        "/grant:r \"$env:USERNAME:(R)\"  3) ROTATE the credential at its provider.",
        "icacls <file>  # -> only your account listed",
        "Restore from your secrets manager / re-add the path if intentionally shared.",
        "Manual — rotation happens at the credential's provider, not on this host.", "")


def _fix_smbv1(evidence: str) -> Proposal:
    return Proposal(
        "smbv1-enabled", "Disable the SMBv1 protocol", "High",
        "SMBv1 is a legacy, wormable protocol (the EternalBlue/WannaCry class); no modern client "
        "needs it, and it turns any reachable SMB port into remote-code-execution surface.",
        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        "(Get-SmbServerConfiguration).EnableSMB1Protocol  # -> False",
        "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force",
        "Low — SMBv1 is obsolete; only pre-2008/XP-era clients rely on it.", "")


_BUILDERS = {
    "exposed-service": _fix_exposed_service,
    "unquoted-service-path": _fix_unquoted_path,
    "defender-disabled": _fix_defender,
    "firewall-disabled": _fix_firewall,
    "exposed-secret-file": _fix_secret_file,
    "smbv1-enabled": _fix_smbv1,
}


def plan(open_findings: dict) -> list:
    """open_findings: {finding_id -> evidence}. Returns a list of Proposals (investigated)."""
    props = []
    for fid, ev in open_findings.items():
        b = _BUILDERS.get(fid)
        if b:
            props.append(b(ev))
    rank = {"High": 0, "Medium": 1, "Low": 2}
    props.sort(key=lambda p: rank.get(p.severity, 3))
    return props


def format_plan(props: list) -> str:
    if not props:
        return "remediation: nothing open to fix — clean."
    out = ["REMEDIATION PLAN — proposals only, nothing has been applied.\n"]
    for i, p in enumerate(props, 1):
        out.append(f"{i}. [{p.severity}] {p.title}  ({p.fid})")
        out.append(f"   why:      {p.why}")
        if p.note:
            out.append(f"   found:    {p.note}")
        out.append(f"   apply:    {p.command}")
        if p.verify:
            out.append(f"   verify:   {p.verify}")
        if p.rollback:
            out.append(f"   rollback: {p.rollback}")
        out.append(f"   risk:     {p.risk}\n")
    out.append("To apply one, review it and run its `apply` command yourself, or ask me to "
               "run a specific numbered fix — I will not apply anything without your explicit go.")
    return "\n".join(out)


# ----------------------------------------------------------------- apply + verify (Layer D)

def _default_sweep():
    """Re-run the host sweep to verify a fix — the perfect verifier turned on our own hardening."""
    from . import host as host_mod
    from .scope import Scope
    return host_mod.host_sweep("localhost", Scope(["127.0.0.1"]))


def apply(proposal, *, confirm: bool = False, sweep_fn=None) -> dict:
    """Run a fix proposal's command, then VERIFY by re-sweeping the host — but ONLY when
    `confirm=True`. This is the one function here that changes the system, so the gate is
    explicit and unskippable: without confirm it does nothing. After applying, the SAME evidence
    gate that found the hole re-checks it — `verified_fixed` is True only when the finding is
    actually gone. The rollback is returned, never auto-run. A template command (with a
    `<placeholder>`) or a manual-only step (`# …`) is refused, so a literal `<ServiceName>`
    can never reach the shell."""
    if not confirm:
        return {"applied": False,
                "reason": "refused — pass confirm=True to run a real system change"}
    cmd = proposal.command.strip()
    if "<" in cmd and ">" in cmd:
        return {"applied": False,
                "reason": "command is a template — fill in the concrete target first"}
    if cmd.startswith("#"):
        return {"applied": False, "reason": "no runnable command (manual step) for this finding"}
    out = _ps(cmd, timeout=30)
    result = {"applied": True, "fid": proposal.fid, "output": out, "rollback": proposal.rollback}
    sweep = sweep_fn or _default_sweep
    try:
        found, _ = sweep()
        result["verified_fixed"] = proposal.fid not in found
    except Exception as e:  # noqa: BLE001 — a verify failure must not mask that we applied
        result["verified_fixed"] = None
        result["verify_error"] = f"{type(e).__name__}: {e}"
    return result
