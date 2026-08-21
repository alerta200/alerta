"""compliance.py — map each evidence-gated finding to the standard security taxonomies auditors
and GRC teams expect: CWE, the OWASP Top 10 (2021), and PCI DSS v4.0.

This turns a vulnerability list into a *compliance artefact* — the thing a client under SOC 2 / ISO
27001 / PCI needs to file. The mapping is a fixed, curated lookup keyed by the finding class (not
model prose), so it is deterministic and defensible. CWE and OWASP references are precise; the PCI
DSS requirement is the closest applicable control and is labelled indicative.
"""

from __future__ import annotations

# id -> {cwe:(id,name), owasp:(id,name), pci:(req, note)}. One authoritative row per finding class.
COMPLIANCE = {
    "sqli": {
        "cwe": ("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command"),
        "owasp": ("A03:2021", "Injection"),
        "pci": ("6.2.4", "protect against injection attacks in bespoke software"),
    },
    "reflected-xss": {
        "cwe": ("CWE-79", "Improper Neutralization of Input During Web Page Generation (XSS)"),
        "owasp": ("A03:2021", "Injection"),
        "pci": ("6.2.4", "protect against cross-site scripting in bespoke software"),
    },
    "path-traversal": {
        "cwe": ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory"),
        "owasp": ("A01:2021", "Broken Access Control"),
        "pci": ("6.2.4", "protect against attacks on access to files/directories"),
    },
    "exposed-secrets": {
        "cwe": ("CWE-798", "Use of Hard-coded Credentials"),
        "owasp": ("A02:2021", "Cryptographic Failures"),
        "pci": ("3.5.1", "render stored credentials/keys unreadable / protect from exposure"),
    },
    "broken-access-control": {
        "cwe": ("CWE-284", "Improper Access Control"),
        "owasp": ("A01:2021", "Broken Access Control"),
        "pci": ("7.2.1", "restrict access to system components by business need-to-know"),
    },
    "server-disclosure": {
        "cwe": ("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor"),
        "owasp": ("A05:2021", "Security Misconfiguration"),
        "pci": ("2.2.1", "configure system components securely / remove unnecessary disclosure"),
    },
    "missing-headers": {
        "cwe": ("CWE-693", "Protection Mechanism Failure"),
        "owasp": ("A05:2021", "Security Misconfiguration"),
        "pci": ("6.2.4", "apply protective controls (security headers) in bespoke software"),
    },
}


def for_finding(fid: str) -> dict | None:
    """The CWE / OWASP / PCI mapping for a finding class id, or None if unmapped (e.g. a raw
    nuclei template that carries its own metadata)."""
    return COMPLIANCE.get(fid)


def short_line(fid: str) -> str:
    """A one-line standards tag for a finding, e.g. 'CWE-89 · OWASP A03:2021 Injection · PCI DSS 6.2.4'.
    Empty string when the class isn't mapped."""
    m = COMPLIANCE.get(fid)
    if not m:
        return ""
    return (f"{m['cwe'][0]} · OWASP {m['owasp'][0]} {m['owasp'][1]} "
            f"· PCI DSS {m['pci'][0]}")


def owasp_coverage(items: list) -> list:
    """Group a findings list by OWASP Top-10 (2021) category. Returns [(owasp_id, name, [names])]
    ordered by category id — the coverage view an auditor reads."""
    buckets: dict = {}
    for it in items:
        m = COMPLIANCE.get(it.get("id"))
        if not m:
            continue
        key = m["owasp"]
        buckets.setdefault(key, [])
        if it.get("name") not in buckets[key]:
            buckets[key].append(it.get("name"))
    return [(oid, name, names) for (oid, name), names in
            sorted(buckets.items(), key=lambda kv: kv[0][0])]
