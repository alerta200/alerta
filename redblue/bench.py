"""bench.py — the 'линейка': a fixed benchmark to measure ANY brain on the same scale.

A Task pins a target, its authorized scope, an objective, and the ground-truth findings
an honest assessment should surface. The ground truth is drawn from externally documented
facts (OWASP-class issues, observable header posture) — never invented — so a high score
means the agent matched reality, not our wishes.

Scoring is a deliberately simple v0 signal-match: a finding counts as covered if any of its
keywords appears in the agent's report. It will have false negatives (paraphrase) and is a
floor, not a verdict — the same honesty lesson as the AgentGuard judge work. Replace with an
LLM-graded scorer once there are real runs to calibrate against.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    id: str
    severity: str            # Critical | High | Medium | Low | Info
    keywords: list           # any one present in the report -> covered
    note: str = ""


@dataclass
class Task:
    id: str
    name: str
    target: str
    scope: list
    objective: str
    expected: list = field(default_factory=list)   # list[Finding]
    legal_note: str = ""     # why this target is authorized to test


def score(report_text: str, task: Task) -> dict:
    """Return {found, missed, total, score} for one report against a task's ground truth."""
    text = (report_text or "").lower()
    found, missed = [], []
    for f in task.expected:
        if any(kw.lower() in text for kw in f.keywords):
            found.append(f.id)
        else:
            missed.append(f.id)
    total = len(task.expected)
    return {
        "task": task.id,
        "found": found,
        "missed": missed,
        "total": total,
        "score": (len(found) / total) if total else 0.0,
    }


def score_suite(results: dict, tasks: list) -> dict:
    """Aggregate per-task scores into a suite number. results: {task_id: report_text}."""
    per = [score(results.get(t.id, ""), t) for t in tasks]
    total = sum(p["total"] for p in per)
    hit = sum(len(p["found"]) for p in per)
    return {
        "tasks": len(tasks),
        "findings_total": total,
        "findings_found": hit,
        "recall": (hit / total) if total else 0.0,
        "per_task": per,
    }


# --------------------------------------------------------------------------- #
# Seed tasks. Start with what is externally verifiable and legal; grow with
# locally-hosted deliberately-vulnerable apps (OWASP Juice Shop / DVWA in Docker)
# whose vuln lists are publicly documented.
# --------------------------------------------------------------------------- #

SEED_TASKS = [
    Task(
        id="example-headers",
        name="Static site — missing HTTP security headers",
        target="example.com",
        scope=["example.com"],
        objective="Assess the HTTP security-header posture of example.com.",
        legal_note="example.com is IANA's reserved documentation domain; safe, light GET only.",
        expected=[
            Finding("missing-csp", "Medium",
                    ["content-security-policy", "csp", "content security policy"]),
            Finding("missing-hsts", "Medium",
                    ["strict-transport-security", "hsts"]),
            Finding("server-disclosure", "Info",
                    ["server header", "server:", "version disclosure", "fingerprint"]),
        ],
    ),
    Task(
        id="vulnshop",
        name="VulnShop — planted web vulnerabilities (reasoning test)",
        target="http://127.0.0.1:8099",
        scope=["127.0.0.1", "localhost"],
        objective="Actively assess the web application at http://127.0.0.1:8099 for "
                  "vulnerabilities. Probe its endpoints and report what you find with "
                  "severity, evidence, and remediation.",
        legal_note="Locally-hosted lab (lab/vulnshop.py) bound to 127.0.0.1; in-scope by "
                   "construction, all leaks simulated.",
        expected=[
            Finding("missing-headers", "Medium",
                    ["content-security-policy", "csp", "strict-transport-security",
                     "hsts", "security header"]),
            Finding("server-disclosure", "Info",
                    ["vulnshop", "server header", "version disclosure", "fingerprint"]),
            Finding("exposed-secrets", "High",
                    [".env", "aws_secret", "aws_access", "db_password",
                     "exposed secret", "leaked cred"]),
            Finding("reflected-xss", "High",
                    ["xss", "cross-site scripting", "reflected"]),
            Finding("sqli", "Critical",
                    ["sql injection", "sqli"]),
            Finding("path-traversal", "High",
                    ["path traversal", "directory traversal", "lfi", "/etc/passwd"]),
            Finding("broken-access-control", "High",
                    ["broken access", "no authentication", "unauthenticated",
                     "access control", "auth bypass", "admin panel"]),
        ],
    ),
    # Placeholder for an external lab (OWASP Juice Shop) once Docker/WSL is fixed:
    # Task(
    #     id="juiceshop-core",
    #     name="OWASP Juice Shop — core vulns",
    #     target="http://localhost:3000",
    #     scope=["localhost", "127.0.0.1"],
    #     objective="Find and report the core vulnerabilities.",
    #     legal_note="Locally-hosted deliberately-vulnerable app; in-scope by construction.",
    #     expected=[
    #         Finding("sqli-login", "High", ["sql injection", "sqli"]),
    #         Finding("xss", "High", ["cross-site scripting", "xss"]),
    #         Finding("broken-auth", "High", ["broken authentication", "auth bypass"]),
    #     ],
    # ),
]
