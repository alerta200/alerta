"""findings.py — derive findings from EVIDENCE, not from the model's prose.

The small student drives the probing well (it decides what endpoints to test and sends the
right payloads, even on unfamiliar targets), but when asked to *write* the report it pads it
with plausible fabrications (fake TLS/logging findings, claims it never confirmed). For a
security tool, fabricated findings are the worst failure.

So we split responsibility: the model PROBES; this module READS the real tool results it
collected and reports only what the evidence actually shows. A finding is credited only if
the agent genuinely tested for it AND the live response confirms it — making fabrication
impossible and every finding evidence-backed. Detection mirrors the teacher's semantics
(payload reflected unescaped = XSS; 500 / SQL error on a quote = SQLi; passwd on ../ =
traversal; secret regex = exposed creds; admin+no-auth wording = broken access control).
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse, parse_qs, unquote

# An ACTUAL leaked credential, not merely the word "password" in prose (a failed-login
# message like "Invalid email or password." must NOT count as exposed secrets). Matches AWS
# key ids, PEM private keys, Stripe live keys, and env-style assignments where an UPPER_CASE
# key containing KEY/SECRET/PASSWORD/TOKEN/PASS is given a value (`DB_PASSWORD=…`,
# `"STRIPE_API_KEY": …`). Case-sensitive on the env-key so prose "password" doesn't match.
SECRET_RE = re.compile(
    r"AKIA[0-9A-Z]{16}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY"
    r"|sk_live_[0-9a-zA-Z]{6,}"
    r"|[A-Z][A-Z0-9_]*(KEY|SECRET|PASSWORD|TOKEN|PASS)[A-Z0-9_]*[\"']?\s*[:=]")
# A SQL-injection payload carried in a request body (login/auth bypass via POST), e.g.
# {"email": "' OR 1=1--"}. Mirrors the GET-query detection but for JSON/form bodies.
SQLI_PAYLOAD_RE = re.compile(r"'\s*or\s|'\s*--|'\s*#|--\s*$|'\)\)|\bor\s+1\s*=\s*1\b", re.I)
TOKEN_RE = re.compile(r'"(token|authentication|access_token|jwt)"\s*:', re.I)
EMAIL_RE = re.compile(r'"email"\s*:\s*"[^"]+@[^"]+"')
ADMIN_RE = re.compile(
    r"admin panel|admin dashboard|admin console|admin area|no authentication|"
    r"no login required|no auth required|authentication is disabled|open to everyone|"
    r"without authentication|no authentication enforced", re.I)
SQL_ERR_RE = re.compile(r"SQL|psycopg|MySQL|SQLite|ORA-\d|syntax error|unterminated", re.I)
XSS_MARK = "<script>alert(1)</script>"

# Order + human label/severity for the report.
_SPEC = [
    ("sqli", "SQL injection", "Critical"),
    ("path-traversal", "Path traversal", "High"),
    ("reflected-xss", "Reflected XSS", "High"),
    ("exposed-secrets", "Exposed secrets", "High"),
    ("broken-access-control", "Broken access control", "High"),
    ("server-disclosure", "Server/version disclosure", "Info"),
    ("missing-headers", "Missing security headers", "Medium"),
]
_REMEDIATION = {
    "sqli": "Use parameterised queries / prepared statements; never concatenate input.",
    "path-traversal": "Canonicalise and allowlist paths; reject `..` and absolute paths.",
    "reflected-xss": "Apply context-aware output encoding and a strict CSP.",
    "exposed-secrets": "Remove the file from the web root and rotate every exposed credential.",
    "broken-access-control": "Require authentication/authorisation on privileged endpoints.",
    "server-disclosure": "Genericise or suppress the `Server` banner.",
    "missing-headers": "Add CSP, HSTS, and X-Frame-Options.",
}


# Maps each evidence-gated finding id to a curated knowledge topic (redblue/knowledge.py), so the
# report can OPTIONALLY explain the code-level root cause + fix at a senior level — grounded in the
# same authoritative base as the chat, never in the model's prose. Only used when deep=True.
_FINDING_TO_TOPIC = {
    "sqli": "sql-injection",
    "path-traversal": "path-traversal",
    "reflected-xss": "xss",
    "exposed-secrets": "secrets-management",
    "broken-access-control": "broken-access-control",
    "server-disclosure": "security-headers",
    "missing-headers": "security-headers",
}


def explain(fid: str):
    """(title, text) of the curated deep-dive for a finding id, or None. Deterministic lookup in
    the knowledge base — not model prose, so it stays safe to put in a report."""
    from . import knowledge
    topic = knowledge.by_id(_FINDING_TO_TOPIC.get(fid, ""))
    if topic:
        return topic["title"], topic["text"]
    return None


def _pairs(messages):
    """Yield (tool_name, tool_input, parsed_result_dict, raw_result_str) over the run."""
    pending = {}   # tool_use_id -> (name, input)
    for m in messages:
        content = m.get("content")
        if not isinstance(content, list):
            continue
        for b in content:
            t = b.get("type")
            if t == "tool_use":
                pending[b.get("id")] = (b.get("name", ""), b.get("input", {}) or {})
            elif t == "tool_result":
                name, tin = pending.pop(b.get("tool_use_id"), ("", {}))
                raw = b.get("content", "")
                try:
                    parsed = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    parsed = {}
                yield name, tin, parsed, raw


def analyze(messages):
    """Return (findings:set, evidence:dict[id->str]) derived from real tool results."""
    ev = {}
    for name, tin, res, raw in _pairs(messages):
        if name == "security_headers":
            fnd = res.get("findings", [])
            hdrs = {f.get("header") for f in fnd}
            if {"content-security-policy", "strict-transport-security"} & hdrs:
                ev.setdefault("missing-headers",
                              "security_headers reports no Content-Security-Policy / HSTS.")
            # A version/stack-disclosure header graded here is the same finding as a raw
            # http_probe would surface — credit it so disclosure isn't lost when the agent
            # only ran security_headers.
            for f in fnd:
                if f.get("header") in ("server", "x-powered-by", "x-aspnet-version"):
                    issue = f.get("issue", "")
                    ev.setdefault("server-disclosure",
                                  issue or "a version/stack-disclosure header is exposed.")
            continue
        if name == "content_discovery":
            # a browsable directory listing on a real (non-SPA) endpoint exposes files.
            # /.well-known/ is a standard, expected listing — not a secret leak — so skip it.
            for d in res.get("discovered", []):
                path = (d.get("path") or "")
                if d.get("listing") and not path.startswith("/.well-known"):
                    ev.setdefault("exposed-secrets",
                                  f"browsable directory listing at `{path}` exposes files "
                                  "(e.g. backups/keys) to anyone.")
                # An admin/no-auth interface (or leaked secret) visible in a discovered
                # endpoint's body is credited here, without needing a separate http_probe.
                body = d.get("body_preview", "") or ""
                if body:
                    if SECRET_RE.search(body):
                        ev.setdefault("exposed-secrets",
                                      f"`{path or '/'}` leaks credentials/API keys.")
                    elif ADMIN_RE.search(body):
                        ev.setdefault("broken-access-control",
                                      f"`{path or '/'}` serves an admin interface without "
                                      "authentication.")
            continue
        if name == "fuzz_params":
            # The parameter fuzzer already confirmed each hit against the live response
            # (marker reflected / /etc/passwd returned / SQL error) before listing it in
            # `confirmed` — so credit those verdicts directly. Nothing here comes from prose.
            for c in res.get("confirmed", []):
                fid = c.get("type")
                if fid in _REMEDIATION and c.get("evidence"):
                    ev.setdefault(fid, c["evidence"])
            continue
        if name == "login_test":
            # SQLi authentication bypass via the dedicated login tool: credited ONLY when the
            # live server actually issued a token for the injected credential (bypassed=True) —
            # a plain 401/failed login reports bypassed=False and earns nothing.
            if res.get("bypassed") and res.get("token_captured"):
                path = res.get("login_path") or tin.get("login_path") or ""
                ev["sqli"] = (f"`{path}` issued an auth token for a SQL-injection credential "
                              "(`' OR 1=1--`) — authentication bypass.")
            continue
        if name == "read_collection":
            # Broken access control: the carried token (or an open endpoint) returned a
            # collection of OTHER users' records. Same >=2-email + role/password evidence bar
            # as the http_probe path, so a single record or an empty/401 body earns nothing.
            body = res.get("body_preview", "") or ""
            if len(EMAIL_RE.findall(body)) >= 2 and ('"role"' in body or '"password"' in body):
                path = res.get("path") or tin.get("path") or ""
                carried = " (via the login-bypass token)" if res.get("carried_token") else ""
                ev.setdefault("broken-access-control",
                              f"`{path}` returns a collection of user records (emails + roles)"
                              f"{carried} — sensitive data exposed without proper authorization.")
            continue
        if name != "http_probe":
            continue
        url = tin.get("url", "")
        if not isinstance(url, str):
            continue          # a garbage model emitted a non-string url; it errored, no evidence
        body = res.get("body_preview", "") or ""
        status = res.get("status")
        method = str(tin.get("method", "GET")).upper()
        # SQL injection as an AUTHENTICATION BYPASS: a POST whose body carries a SQLi
        # payload and the server answers 200 with an auth token. Evidence = the live token
        # issued from an injected credential; impossible to fabricate from prose.
        if method == "POST":
            req_body = tin.get("body", "")
            req_s = req_body if isinstance(req_body, str) else json.dumps(req_body)
            if (SQLI_PAYLOAD_RE.search(req_s) and status == 200
                    and TOKEN_RE.search(body)):
                ev["sqli"] = (f"`{urlparse(url).path}` issued an auth token for a SQL-"
                              f"injection credential (`{req_s[:60]}`) — authentication bypass.")
        # Broken access control / excessive data exposure: a response that returns a
        # collection of OTHER users' records (>=2 distinct emails alongside role/password
        # fields). Confirmed from the live API body.
        if len(EMAIL_RE.findall(body)) >= 2 and ('"role"' in body or '"password"' in body):
            ev.setdefault("broken-access-control",
                          f"`{urlparse(url).path}` returns a collection of user records "
                          "(emails + roles) — sensitive data exposed without proper "
                          "authorization.")
        server = (res.get("headers", {}) or {}).get("Server", "")
        if server:
            ev.setdefault("server-disclosure", f"`Server: {server.strip()}` exposed in response headers.")

        u = urlparse(url)
        raw_q = u.query
        dec_q = unquote(raw_q)
        # injection verdicts require BOTH the payload sent AND the live response confirming it
        if XSS_MARK in unquote(url) and XSS_MARK in body:
            ev["reflected-xss"] = f"`{u.path}` reflected the script marker unescaped: {XSS_MARK}"
        if ("'" in dec_q or "%27" in raw_q) and (status == 500 or SQL_ERR_RE.search(body)):
            snippet = body.strip().replace("\n", " ")[:120]
            ev["sqli"] = f"`{u.path}` returned a SQL error on a single quote (HTTP {status}): {snippet}"
        if (".." in dec_q or "/etc/passwd" in dec_q) and "root:x:" in body:
            ev["path-traversal"] = f"`{u.path}` returned /etc/passwd contents (`root:x:`)."
        # content findings only when the request carried no injection payload (a plain fetch)
        plain = not (XSS_MARK in unquote(url) or "'" in dec_q or ".." in dec_q
                     or "/etc/passwd" in dec_q)
        if plain and body:
            if SECRET_RE.search(body):
                ev.setdefault("exposed-secrets", f"`{u.path or '/'}` leaks credentials/API keys.")
            elif ADMIN_RE.search(body):
                ev.setdefault("broken-access-control",
                              f"`{u.path or '/'}` serves an admin interface without authentication.")
    return set(ev), ev


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def scanner_matches(messages):
    """Collect nuclei's verified matches from the run — each is a live matcher hit (template
    id + matched-at URL), not prose, so it belongs in the evidence-gated report. De-duplicated
    by (template, matched_at) and ordered by severity."""
    seen, out = set(), []
    for name, _tin, res, _raw in _pairs(messages):
        if name != "nuclei_scan":
            continue
        for f in res.get("findings", []):
            key = (f.get("template"), f.get("matched_at"))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
    out.sort(key=lambda f: _SEV_RANK.get(f.get("severity", "unknown"), 5))
    return out


# SARIF level + GitHub's numeric security-severity, keyed by our human severity label.
_SEV_TO_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                 "low": "note", "info": "note", "unknown": "note"}
_SEV_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5",
              "low": "3.0", "info": "1.0", "unknown": "0.0"}
_BACKTICK_RE = re.compile(r"`([^`]+)`")


def _location_from(evidence: str, target: str) -> str:
    """Best-effort location URI for a finding: the first back-ticked path in its evidence,
    joined onto the target when it's a bare path; else the target itself."""
    m = _BACKTICK_RE.search(evidence or "")
    tok = m.group(1).strip() if m else ""
    if tok.startswith(("http://", "https://")):
        return tok
    if tok.startswith("/") and target:
        return target.rstrip("/") + tok
    return target or tok or "unknown"


def structured(target, messages):
    """Flat, serialisation-ready list of the evidence-gated findings (the same data report()
    renders as markdown) plus nuclei's verified matches. The single source the md / json /
    sarif projections all build on — so every format shows exactly the evidence, nothing more.
    """
    found, ev = analyze(messages)
    out = []
    for fid, label, sev in _SPEC:
        if fid in found:
            out.append({
                "id": fid, "name": label, "severity": sev,
                "evidence": ev[fid], "remediation": _REMEDIATION[fid],
                "location": _location_from(ev[fid], target), "source": "nexus-evidence",
            })
    for f in scanner_matches(messages):
        out.append({
            "id": f.get("template") or "nuclei-match",
            "name": f.get("name") or f.get("template") or "nuclei match",
            "severity": (f.get("severity") or "info").capitalize(),
            "evidence": f"nuclei template `{f.get('template')}` matched at {f.get('matched_at')}.",
            "remediation": "Review the matched template's guidance and remediate.",
            "location": f.get("matched_at") or target, "source": "nuclei",
        })
    return out


def to_json(target, messages, version="0"):
    """The findings as a machine-readable JSON document (structured evidence, no prose)."""
    import datetime
    doc = {
        "tool": "Nexus",
        "version": version,
        "target": target,
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "findings": structured(target, messages),
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def to_sarif(target, messages, version="0"):
    """The findings as SARIF 2.1.0 — the industry-standard static-analysis format that GitHub
    code scanning, VS Code, and CI pipelines ingest directly. Each result is evidence-backed;
    nothing here comes from the model's prose."""
    items = structured(target, messages)
    rules, results = {}, []
    for it in items:
        rid = it["id"]
        sev = it["severity"].lower()
        level = _SEV_TO_LEVEL.get(sev, "note")
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": it["name"],
                "shortDescription": {"text": it["name"]},
                "fullDescription": {"text": it["remediation"]},
                "defaultConfiguration": {"level": level},
                "properties": {"security-severity": _SEV_SCORE.get(sev, "0.0"),
                               "tags": ["security", it["source"]]},
            }
        results.append({
            "ruleId": rid,
            "level": level,
            "message": {"text": f"{it['name']}: {it['evidence']} "
                                f"Remediation: {it['remediation']}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": it["location"]}}}],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Nexus",
                "version": version,
                "informationUri": "https://pypi.org/project/nexus-sec/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def report(target, messages, deep=False):
    """A clean, evidence-only assessment report — no model prose, no fabrication.

    deep=False (default) is the canonical report other code (ood_eval, the flywheel verifier)
    parses — its bytes are STABLE. deep=True appends a senior-level "Understanding the findings"
    section explaining each confirmed class at the code level + how to fix it, grounded in the
    curated knowledge base (deterministic, not model prose). Opt-in so the default stays fixed."""
    found, ev = analyze(messages)
    lines = [f"# Security Assessment — {target}", "", "## Findings"]
    any_found = False
    for fid, label, sev in _SPEC:
        if fid in found:
            any_found = True
            lines.append(f"- **{label}** ({sev}): {ev[fid]} Remediation: {_REMEDIATION[fid]}")
    if not any_found:
        lines.append("- No material findings confirmed by evidence.")
    if deep and any_found:
        seen = set()
        deep_lines = []
        for fid, label, _sev in _SPEC:
            if fid in found and fid not in seen:
                seen.add(fid)
                exp = explain(fid)
                if exp:
                    deep_lines.append(f"### {label}\n{exp[1]}")
        if deep_lines:
            lines += ["", "## Understanding the findings"] + deep_lines
    scans = scanner_matches(messages)
    if scans:
        lines += ["", "## Scanner-verified matches (nuclei)"]
        for f in scans:
            sev = (f.get("severity") or "unknown").capitalize()
            lines.append(f"- **{f.get('name') or f.get('template')}** ({sev}) "
                         f"[`{f.get('template')}`] at {f.get('matched_at')}")
    return "\n".join(lines)
