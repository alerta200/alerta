"""Lock the retest / delta diff: fixed vs still-open vs new, and the CLI `nexus retest` subcommand.

A retest is the paid proof-of-remediation step, so the classification must be exact and honest:
a finding is 'fixed' only when its (class, location) is absent from the new run, 'still open' only
when present in both, 'new' only when absent from the old run. Nothing inferred; pure set logic
over the evidence-gated `--format json` artefacts.
"""

import json

import pytest

from redblue import retest
from redblue.cli import main


@pytest.fixture(autouse=True)
def _pro_licensed(monkeypatch):
    # `nexus retest` is Pro-gated; license the CLI tests so they exercise the diff, not the upsell.
    monkeypatch.setattr("redblue.license.is_commercial_authorized", lambda *a, **k: True)


def _doc(target, *finds):
    return {"tool": "Nexus", "version": "0", "target": target,
            "findings": [{"id": i, "name": n, "severity": s, "evidence": "e",
                          "remediation": "r", "location": loc, "source": "nexus-evidence"}
                         for (i, n, s, loc) in finds]}


_OLD = _doc("http://t",
            ("sqli", "SQL injection", "Critical", "http://t/i"),
            ("path-traversal", "Path traversal", "High", "http://t/d"),
            ("exposed-secrets", "Exposed secrets", "High", "http://t/.env"))
_NEW = _doc("http://t",
            ("exposed-secrets", "Exposed secrets", "High", "http://t/.env"),   # still open
            ("reflected-xss", "Reflected XSS", "High", "http://t/s"))          # new


def test_diff_classifies_by_id_and_location():
    d = retest.diff(_OLD["findings"], _NEW["findings"])
    assert {f["id"] for f in d["fixed"]} == {"sqli", "path-traversal"}
    assert {f["id"] for f in d["still_open"]} == {"exposed-secrets"}
    assert {f["id"] for f in d["new"]} == {"reflected-xss"}


def test_same_class_different_location_is_not_the_same_finding():
    old = _doc("http://t", ("sqli", "SQL injection", "Critical", "http://t/a"))
    new = _doc("http://t", ("sqli", "SQL injection", "Critical", "http://t/b"))
    d = retest.diff(old["findings"], new["findings"])
    assert len(d["fixed"]) == 1 and len(d["new"]) == 1 and d["still_open"] == []


def test_remediation_rate_and_stats():
    s = retest.diff(_OLD["findings"], _NEW["findings"])["stats"]
    assert s["fixed"] == 2 and s["still_open"] == 1 and s["new"] == 1
    assert s["prior"] == 3
    assert abs(s["remediation_rate"] - 2 / 3) < 1e-9


def test_diff_empty_both():
    d = retest.diff([], [])
    assert d["fixed"] == [] and d["still_open"] == [] and d["new"] == []
    assert d["stats"]["remediation_rate"] is None


def test_load_findings_accepts_doc_and_bare_list(tmp_path):
    p1 = tmp_path / "doc.json"
    p1.write_text(json.dumps(_OLD), encoding="utf-8")
    items, target = retest.load_findings(str(p1))
    assert target == "http://t" and len(items) == 3
    p2 = tmp_path / "bare.json"
    p2.write_text(json.dumps(_OLD["findings"]), encoding="utf-8")
    items2, target2 = retest.load_findings(str(p2))
    assert len(items2) == 3 and target2 == ""


def test_markdown_has_all_three_sections():
    md = retest.to_markdown("http://t", retest.diff(_OLD["findings"], _NEW["findings"]))
    assert "## Fixed (2)" in md and "## Still open (1)" in md
    assert "## New since last assessment (1)" in md
    assert "SQL injection" in md and "CVSS 9.8" in md


def test_html_has_summary_and_branding():
    h = retest.to_html("http://t", retest.diff(_OLD["findings"], _NEW["findings"]),
                       meta={"vendor": "Acme Sec", "client": "BluePeak"})
    for needle in ("Retest summary", "Acme Sec", "BluePeak", "CONFIDENTIAL",
                   "remediated", "Still open"):
        assert needle in h, needle


# ---- CLI subcommand -----------------------------------------------------

def test_cli_retest_markdown(tmp_path, capsys):
    old = tmp_path / "old.json"; old.write_text(json.dumps(_OLD), encoding="utf-8")
    new = tmp_path / "new.json"; new.write_text(json.dumps(_NEW), encoding="utf-8")
    rc = main(["retest", str(old), str(new)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "2 of 3 prior findings remediated" in out


def test_cli_retest_html_writes_file(tmp_path):
    old = tmp_path / "old.json"; old.write_text(json.dumps(_OLD), encoding="utf-8")
    new = tmp_path / "new.json"; new.write_text(json.dumps(_NEW), encoding="utf-8")
    out = tmp_path / "r.html"
    rc = main(["retest", str(old), str(new), "--format", "html", "--report", str(out),
               "--client", "BluePeak", "--vendor", "Acme Sec"])
    assert rc == 0
    body = out.read_text(encoding="utf-8")
    assert "<!doctype html>" in body.lower() and "BluePeak" in body and "Retest summary" in body


def test_cli_retest_bad_file_fails_cleanly(tmp_path, capsys):
    rc = main(["retest", str(tmp_path / "nope.json"), str(tmp_path / "nope2.json")])
    assert rc == 1
    assert "could not read" in capsys.readouterr().err


def test_cli_retest_pro_gated_when_unlicensed(tmp_path, capsys, monkeypatch):
    # retest is Pro-only: unlicensed → blocked with upsell, before any file is read.
    monkeypatch.setattr("redblue.license.is_commercial_authorized", lambda *a, **k: False)
    assert main(["retest", str(tmp_path / "a.json"), str(tmp_path / "b.json")]) == 2
    assert "Pro feature" in capsys.readouterr().err
