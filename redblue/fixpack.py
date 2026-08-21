"""fixpack.py — turn confirmed findings into an actionable remediation plan + copy-paste fixes.

A finding list tells a client *what* is wrong; a senior report tells them *what to do Monday
morning*. This module adds the two things that make a report actionable:

  * a **prioritised roadmap** — findings grouped into Immediate / Short-term / Hygiene, ordered by
    real risk (CVSS), each with a rough effort tag;
  * **remediation-as-code** — a concrete, correct, copy-paste fix snippet per finding class
    (a parameterised query, a CSP header, a path-canonicalisation guard, an nginx deny rule).

Both are a deterministic, curated projection over the evidence-gated findings — no model prose, so
the fixes are as trustworthy as the findings. Distinct from `remediate.py` (which proposes host/OS
changes on the blue side); this is the web-finding remediation that rides in the client deliverable.
Pure stdlib, offline.
"""

from __future__ import annotations

# Per finding-class remediation. `effort` is a rough consultant estimate; `now` flags fixes that
# must not wait for a maintenance window (a live leaked credential is already burning). `lang` tags
# the snippet so a renderer can label the code block.
FIXES = {
    "sqli": {
        "effort": "Medium", "now": False, "lang": "python",
        "summary": "Use parameterised queries / prepared statements — never build SQL from input.",
        "code": ("# Vulnerable — the value is concatenated into the SQL string:\n"
                 "#   cur.execute(\"SELECT * FROM users WHERE id = '\" + user_id + \"'\")\n\n"
                 "# Fixed — the driver binds the parameter, so it can never be interpreted as SQL:\n"
                 "cur.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n\n"
                 "# Better still: use your ORM's query API, which parameterises by default."),
    },
    "reflected-xss": {
        "effort": "Low", "now": False, "lang": "nginx / template",
        "summary": "Context-encode output and serve a strict Content-Security-Policy.",
        "code": ("# 1. Encode on output — enable your template engine's auto-escaping\n"
                 "#    (Jinja2: autoescape=True; React escapes by default; else html.escape()).\n\n"
                 "# 2. Add a strict CSP header so injected script cannot execute:\n"
                 "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; "
                 "base-uri 'none'\" always;"),
    },
    "path-traversal": {
        "effort": "Medium", "now": False, "lang": "python",
        "summary": "Canonicalise the resolved path and confirm it stays inside an allowed base dir.",
        "code": ("import os\n\n"
                 "BASE = \"/var/www/files\"\n\n"
                 "def safe_path(user_supplied: str) -> str:\n"
                 "    full = os.path.realpath(os.path.join(BASE, user_supplied))\n"
                 "    # realpath collapses ../ ; reject anything that escaped the base directory:\n"
                 "    if full != BASE and not full.startswith(BASE + os.sep):\n"
                 "        raise PermissionError(\"path outside allowed directory\")\n"
                 "    return full"),
    },
    "exposed-secrets": {
        "effort": "Low", "now": True, "lang": "shell / nginx",
        "summary": "Remove the file, ROTATE every exposed credential now, and block dotfiles.",
        "code": ("# 1. Rotate every credential/key that was exposed — assume it is already compromised.\n"
                 "# 2. Remove the file from the web root (and from git history if committed).\n"
                 "# 3. Load secrets from the environment, not a file under the web root:\n"
                 "#      DB_PASSWORD = os.environ[\"DB_PASSWORD\"]\n"
                 "# 4. Deny access to dotfiles / backups at the edge:\n"
                 "location ~ /\\.(?!well-known) { deny all; }\n"
                 "location ~* \\.(env|bak|old|sql|zip)$ { deny all; }"),
    },
    "broken-access-control": {
        "effort": "Medium", "now": False, "lang": "python",
        "summary": "Enforce authorization server-side on every privileged route; deny by default.",
        "code": ("from functools import wraps\n"
                 "from flask import abort\n\n"
                 "def require_role(role):\n"
                 "    def deco(view):\n"
                 "        @wraps(view)\n"
                 "        def wrapped(*a, **kw):\n"
                 "            if not current_user.is_authenticated:\n"
                 "                abort(401)\n"
                 "            if not current_user.has_role(role):\n"
                 "                abort(403)          # authorize, don't just authenticate\n"
                 "            return view(*a, **kw)\n"
                 "        return wrapped\n"
                 "    return deco\n\n"
                 "@app.route(\"/admin/users\")\n"
                 "@require_role(\"admin\")\n"
                 "def admin_users(): ..."),
    },
    "server-disclosure": {
        "effort": "Low", "now": False, "lang": "nginx",
        "summary": "Suppress the version banner so the stack isn't advertised.",
        "code": ("# nginx — stop emitting the version:\n"
                 "server_tokens off;\n\n"
                 "# behind a proxy, strip upstream banners too:\n"
                 "proxy_hide_header Server;\n"
                 "proxy_hide_header X-Powered-By;"),
    },
    "missing-headers": {
        "effort": "Low", "now": False, "lang": "nginx",
        "summary": "Add the baseline security response headers at the edge.",
        "code": ("add_header Content-Security-Policy \"default-src 'self'\" always;\n"
                 "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
                 "add_header X-Frame-Options DENY always;\n"
                 "add_header X-Content-Type-Options nosniff always;"),
    },
}

# Roadmap phases, most-urgent first. A finding lands in a phase by CVSS band, except `now` fixes
# (e.g. a live leaked secret) which are always Immediate regardless of score.
_PHASES = [
    ("Immediate", "Fix before this system faces untrusted traffic.", {"Critical", "High"}),
    ("Short-term", "Schedule within the current remediation cycle.", {"Medium"}),
    ("Hygiene", "Address as part of routine hardening.", {"Low", "Info"}),
]


def fix_for(fid: str) -> dict | None:
    """The curated remediation (summary/code/effort/lang) for a finding class, or None if unmapped."""
    return FIXES.get(fid)


def _phase_of(item: dict) -> str:
    fx = FIXES.get(item.get("id"))
    if fx and fx.get("now"):
        return "Immediate"
    band = item.get("band") or str(item.get("severity", "Info")).capitalize()
    for name, _desc, bands in _PHASES:
        if band in bands:
            return name
    return "Hygiene"


def roadmap(items: list) -> list:
    """Group findings into remediation phases. Returns [(phase, description, [items])] in urgency
    order, skipping empty phases. `items` should already be CVSS-enriched (deliverable.enrich)."""
    out = []
    for name, desc, _bands in _PHASES:
        members = [it for it in items if _phase_of(it) == name]
        if members:
            out.append((name, desc, members))
    return out


def _fix_line(it: dict) -> str:
    fx = FIXES.get(it.get("id"))
    cv = f" (CVSS {it['cvss']:.1f})" if it.get("cvss") is not None else ""
    eff = f" — effort: {fx['effort']}" if fx else ""
    return f"{it.get('name')}{cv}{eff}"


def to_markdown(target: str, items: list) -> str:
    """A standalone remediation fix-pack: the phased plan, then a copy-paste fix per finding class."""
    lines = [f"# Remediation plan — {target}", ""]
    plan = roadmap(items)
    if not plan:
        lines.append("No findings to remediate.")
        return "\n".join(lines)
    for name, desc, members in plan:
        lines.append(f"## {name} ({len(members)})")
        lines.append(f"_{desc}_")
        for it in members:
            lines.append(f"- {_fix_line(it)}")
        lines.append("")
    # de-duplicated per-class fixes (several findings can share a class)
    lines.append("## Fixes")
    seen = set()
    for it in items:
        fid = it.get("id")
        if fid in seen:
            continue
        seen.add(fid)
        fx = FIXES.get(fid)
        if not fx:
            continue
        lines.append(f"### {it.get('name')}")
        lines.append(fx["summary"])
        lines.append(f"```{fx['lang'].split(' ')[0]}")
        lines.append(fx["code"])
        lines.append("```")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
