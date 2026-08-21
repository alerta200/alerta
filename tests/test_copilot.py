"""Lock the evidence-grounded co-pilot: it answers questions about an assessment DETERMINISTICALLY
from the confirmed findings, and — the load-bearing property — it never fabricates a finding the
target didn't confirm. Ask about a class that isn't in evidence and it says so.

The co-pilot is the interactive face of the same evidence gate the report enforces; a hallucinated
answer about a client's security posture would betray the whole moat, so these tests pin both the
useful answers and the refusal-to-invent.
"""

import json

import pytest

from redblue import copilot, deliverable, findings
from redblue.cli import main


@pytest.fixture(autouse=True)
def _pro_licensed(monkeypatch):
    # `nexus ask` is a Pro-gated feature; license the CLI tests so they exercise the co-pilot itself,
    # not the upsell. A dedicated test below pins the unlicensed-block behaviour.
    monkeypatch.setattr("redblue.license.is_commercial_authorized", lambda *a, **k: True)


def _doc(target, *finds):
    return {"tool": "Nexus", "target": target,
            "findings": [{"id": i, "name": n, "severity": s, "evidence": ev,
                          "remediation": "r", "location": loc, "source": "nexus-evidence"}
                         for (i, n, s, loc, ev) in finds]}


def _enriched(target, *finds):
    return deliverable.enrich(_doc(target, *finds)["findings"])


_SQLI = ("sqli", "SQL injection", "Critical", "http://t/i?id=1", "500 SQL syntax error near ''")
_XSS = ("reflected-xss", "Reflected XSS", "High", "http://t/d?title=x", "reflected <script> unescaped")
_TRAV = ("path-traversal", "Path traversal", "High", "http://t/f?p=x", "/etc/passwd contents returned")
_SECRET = ("exposed-secrets", "Exposed secrets", "High", "http://t/.env", "DB_PASSWORD=hunter2")
_HDR = ("missing-headers", "Missing security headers", "Medium", "http://t/", "no CSP/HSTS")


# ---- deterministic answers ------------------------------------------------

def test_summary_lists_findings():
    e = _enriched("http://t", _SQLI, _HDR)
    ans = copilot.answer("give me a summary", "http://t", e)
    assert "confirmed 2 finding" in ans
    assert "SQL injection" in ans and "Missing security headers" in ans


def test_triage_names_the_worst_first():
    e = _enriched("http://t", _HDR, _SQLI)          # deliberately worst-last in input
    ans = copilot.answer("what do I fix first?", "http://t", e)
    assert ans.startswith("Fix first: SQL injection")   # enrich sorts Critical to the top
    assert "9.8" in ans


def test_explain_by_class_keyword():
    e = _enriched("http://t", _SQLI, _HDR)
    ans = copilot.answer("explain the sql injection", "http://t", e)
    assert "SQL injection" in ans and "9.8" in ans
    assert "500 SQL syntax error" in ans            # the real evidence, verbatim
    assert "parameterised" in ans.lower()           # the curated fix summary


def test_explain_by_index():
    e = _enriched("http://t", _SQLI, _HDR)
    ans = copilot.answer("tell me about finding 1", "http://t", e)
    assert "SQL injection" in ans


def test_attack_paths_when_two_members_present():
    e = _enriched("http://t", _TRAV, _SECRET)
    ans = copilot.answer("how do these chain together?", "http://t", e)
    assert "Impact:" in ans and "chain" in ans.lower()


def test_attack_paths_independent_when_no_chain():
    e = _enriched("http://t", _HDR)
    ans = copilot.answer("what's the attack path?", "http://t", e)
    assert "independent" in ans.lower()


def test_compliance_maps_standards():
    e = _enriched("http://t", _SQLI)
    ans = copilot.answer("what compliance standards does this map to?", "http://t", e)
    assert "CWE-89" in ans and "A03" in ans


def test_fix_one_returns_code():
    e = _enriched("http://t", _SQLI)
    ans = copilot.answer("how do I fix the sqli?", "http://t", e)
    assert "cur.execute" in ans and "```" in ans


def test_fix_all_returns_roadmap():
    e = _enriched("http://t", _SQLI, _HDR)
    ans = copilot.answer("give me the remediation plan", "http://t", e)
    assert "Immediate" in ans and "## Fixes" in ans


def test_email_draft():
    e = _enriched("http://t", _SQLI)
    ans = copilot.answer("draft a client summary email", "http://t", e)
    assert ans.startswith("Subject: Security assessment results")
    assert "SQL injection" in ans


# ---- the load-bearing property: never fabricate ---------------------------

def test_absent_class_is_not_fabricated():
    # Only SQLi was confirmed; asking to explain XSS must NOT invent one.
    e = _enriched("http://t", _SQLI)
    ans = copilot.answer("explain the xss vulnerability", "http://t", e)
    assert ans is not None
    assert "no evidence" in ans.lower() and "confirmed" in ans.lower()
    assert "<script>" not in ans                    # nothing invented


def test_fix_absent_class_is_not_fabricated():
    e = _enriched("http://t", _SQLI)
    ans = copilot.answer("how do I fix the exposed secrets?", "http://t", e)
    assert "no evidence" in ans.lower()


def test_unmapped_question_returns_none():
    e = _enriched("http://t", _SQLI)
    assert copilot.answer("what's the weather like?", "http://t", e) is None


def test_empty_question_returns_none():
    assert copilot.answer("   ", "http://t", _enriched("http://t", _SQLI)) is None


def test_no_findings_summary_is_honest():
    ans = copilot.answer("summary", "http://t", [])
    assert "no material weaknesses" in ans.lower()


# ---- grounding block (LLM seam) -------------------------------------------

def test_grounding_is_evidence_only_with_gate():
    e = _enriched("http://t", _SQLI, _HDR)
    g = copilot.grounding("http://t", e)
    assert "SQL injection" in g and "500 SQL syntax error" in g
    assert "Answer ONLY from the findings above" in g   # the gate instruction is present


def test_grounding_empty_is_explicit():
    g = copilot.grounding("http://t", [])
    assert "none" in g.lower()


# ---- invariant: every shipped finding class is nameable -------------------

def test_every_finding_class_has_keywords():
    spec_ids = {fid for fid, _l, _s in findings._SPEC}
    kw_ids = {fid for fid, _kw in copilot._CLASS_KW}
    assert spec_ids <= kw_ids, spec_ids - kw_ids


# ---- CLI `nexus ask` ------------------------------------------------------

def _write(tmp_path, *finds):
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(_doc("http://t", *finds)), encoding="utf-8")
    return str(rep)


def test_cli_ask_prints(tmp_path, capsys):
    rep = _write(tmp_path, _SQLI)
    assert main(["ask", rep, "what", "do", "I", "fix", "first?"]) == 0
    assert "Fix first: SQL injection" in capsys.readouterr().out


def test_cli_ask_quoted_question(tmp_path, capsys):
    rep = _write(tmp_path, _SQLI)
    assert main(["ask", rep, "explain the sqli"]) == 0
    assert "cur.execute" not in capsys.readouterr().out  # explain, not fix


def test_cli_ask_writes_file(tmp_path):
    rep = _write(tmp_path, _SQLI)
    out = tmp_path / "answer.txt"
    assert main(["ask", rep, "summary", "--report", str(out)]) == 0
    assert "SQL injection" in out.read_text(encoding="utf-8")


def test_cli_ask_no_question_shows_menu(tmp_path, capsys):
    rep = _write(tmp_path, _SQLI)
    assert main(["ask", rep]) == 0
    assert "triage" in capsys.readouterr().out.lower()


def test_cli_ask_absent_class_not_fabricated(tmp_path, capsys):
    rep = _write(tmp_path, _SQLI)
    assert main(["ask", rep, "explain the xss"]) == 0
    assert "no evidence" in capsys.readouterr().out.lower()


def test_cli_ask_bad_file(tmp_path, capsys):
    assert main(["ask", str(tmp_path / "nope.json"), "summary"]) == 1
    assert "could not read" in capsys.readouterr().err


def test_cli_ask_pro_gated_when_unlicensed(tmp_path, capsys, monkeypatch):
    # the co-pilot is Pro-only: an unlicensed run is blocked with a loud upsell, not executed.
    monkeypatch.setattr("redblue.license.is_commercial_authorized", lambda *a, **k: False)
    rep = _write(tmp_path, _SQLI)
    assert main(["ask", rep, "what do I fix first?"]) == 2
    err = capsys.readouterr().err
    assert "Pro feature" in err and "nexus license add" in err
