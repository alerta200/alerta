"""Lock the remediation fix-pack: every finding class has a concrete fix, the roadmap phases
findings by urgency, and the `nexus fixes` command + the HTML deliverable render it.

The remediation plan is what makes the report actionable ("what do we do Monday, and here's the
code"). A missing fix for a shipped finding class would leave a client stranded — so an invariant
test forces every class to carry one.
"""

import json

import pytest

from redblue import deliverable, findings, fixpack
from redblue.cli import main


@pytest.fixture(autouse=True)
def _pro_licensed(monkeypatch):
    # `nexus fixes` is Pro-gated; license the CLI tests so they exercise the plan, not the upsell.
    monkeypatch.setattr("redblue.license.is_commercial_authorized", lambda *a, **k: True)


def _msgs(*calls):
    out = []
    for i, (name, tin, res) in enumerate(calls):
        tid = f"c{i}"
        out.append({"role": "assistant",
                    "content": [{"type": "tool_use", "id": tid, "name": name, "input": tin}]})
        out.append({"role": "user",
                    "content": [{"type": "tool_result", "tool_use_id": tid,
                                 "content": json.dumps(res), "is_error": False}]})
    return out


def _doc(target, *finds):
    return {"tool": "Nexus", "target": target,
            "findings": [{"id": i, "name": n, "severity": s, "evidence": "e",
                          "remediation": "r", "location": loc, "source": "nexus-evidence"}
                         for (i, n, s, loc) in finds]}


def test_every_finding_class_has_a_fix():
    spec_ids = {fid for fid, _l, _s in findings._SPEC}
    assert spec_ids <= set(fixpack.FIXES), spec_ids - set(fixpack.FIXES)


def test_fix_shape_is_complete():
    for fid, fx in fixpack.FIXES.items():
        assert fx["summary"] and fx["code"] and fx["lang"], fid
        assert fx["effort"] in ("Low", "Medium", "High"), fid
        assert isinstance(fx["now"], bool), fid


def test_roadmap_phases_by_band():
    items = [{"id": "sqli", "name": "SQL injection", "band": "Critical", "cvss": 9.8},
             {"id": "missing-headers", "name": "Missing headers", "band": "Medium", "cvss": 5.3},
             {"id": "server-disclosure", "name": "Server disclosure", "band": "Info", "cvss": 0.0}]
    phases = {name: [it["id"] for it in members] for name, _d, members in fixpack.roadmap(items)}
    assert phases["Immediate"] == ["sqli"]
    assert phases["Short-term"] == ["missing-headers"]
    assert phases["Hygiene"] == ["server-disclosure"]


def test_now_flag_forces_immediate_regardless_of_band():
    # exposed-secrets is marked now=True: a live leaked credential can't wait for a window.
    assert fixpack.FIXES["exposed-secrets"]["now"] is True
    items = [{"id": "exposed-secrets", "name": "Exposed secrets", "band": "Medium", "cvss": 5.0}]
    phases = {name for name, _d, _m in fixpack.roadmap(items)}
    assert phases == {"Immediate"}


def test_roadmap_empty():
    assert fixpack.roadmap([]) == []


def test_markdown_has_plan_and_code_fences():
    items = deliverable.enrich(_doc("http://t",
        ("sqli", "SQL injection", "Critical", "http://t/i"),
        ("missing-headers", "Missing headers", "Medium", "http://t/"))["findings"])
    md = fixpack.to_markdown("http://t", items)
    assert "## Immediate (1)" in md and "## Short-term (1)" in md
    assert "```python" in md and "cur.execute" in md   # the real sqli fix code


def test_markdown_dedups_shared_class():
    # two SQLi findings at different paths => the fix block appears once
    items = deliverable.enrich(_doc("http://t",
        ("sqli", "SQL injection", "Critical", "http://t/a"),
        ("sqli", "SQL injection", "Critical", "http://t/b"))["findings"])
    md = fixpack.to_markdown("http://t", items)
    assert md.count("### SQL injection") == 1


# ---- CLI `nexus fixes` --------------------------------------------------

def test_cli_fixes_prints(tmp_path, capsys):
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(_doc("http://t",
        ("sqli", "SQL injection", "Critical", "http://t/i"))), encoding="utf-8")
    assert main(["fixes", str(rep)]) == 0
    out = capsys.readouterr().out
    assert "Remediation plan" in out and "cur.execute" in out


def test_cli_fixes_writes_file(tmp_path):
    rep = tmp_path / "r.json"
    rep.write_text(json.dumps(_doc("http://t",
        ("sqli", "SQL injection", "Critical", "http://t/i"))), encoding="utf-8")
    out = tmp_path / "plan.md"
    assert main(["fixes", str(rep), "--report", str(out)]) == 0
    assert "## Immediate" in out.read_text(encoding="utf-8")


def test_cli_fixes_bad_file(tmp_path, capsys):
    assert main(["fixes", str(tmp_path / "nope.json")]) == 1
    assert "could not read" in capsys.readouterr().err


def test_deliverable_html_has_remediation_section():
    h = deliverable.to_html("http://t", _msgs(
        ("http_probe", {"url": "http://t/i?id=1'", "method": "GET"},
         {"status": 500, "headers": {}, "body_preview": "SQL syntax error"})))
    assert "Remediation plan" in h and "Immediate" in h
    assert "<pre><code>" in h and "cur.execute" in h


def test_cli_fixes_pro_gated_when_unlicensed(tmp_path, capsys, monkeypatch):
    # the remediation plan is Pro-only: unlicensed → blocked with upsell, before any file is read.
    monkeypatch.setattr("redblue.license.is_commercial_authorized", lambda *a, **k: False)
    assert main(["fixes", str(tmp_path / "r.json")]) == 2
    assert "Pro feature" in capsys.readouterr().err
