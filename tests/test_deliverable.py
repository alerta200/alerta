"""Lock the client-ready deliverable: CVSS 3.1 scoring, attack-path chaining, executive summary,
and the branded HTML render.

Guarantees: (1) CVSS scores are the real formula's canonical values, not invented; (2) an attack
chain is asserted ONLY when every member is present in the evidence — never fabricated; (3) the
HTML report is itself safe — evidence containing an XSS marker must be escaped, or the deliverable
would carry the very payload it reports. All network-free (hand-built transcripts).
"""

import json

from redblue import deliverable as D
from redblue import findings


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


def _xss(target="http://t"):
    return _msgs(("http_probe",
                 {"url": f"{target}/s?q=<script>alert(1)</script>", "method": "GET"},
                 {"status": 200, "headers": {},
                  "body_preview": "hi <script>alert(1)</script>"}))


def _sqli(target="http://t"):
    return _msgs(("http_probe", {"url": f"{target}/i?id=1'", "method": "GET"},
                 {"status": 500, "headers": {}, "body_preview": "SQL syntax error near"}))


def _traversal_and_secret(target="http://t"):
    return _msgs(
        ("http_probe", {"url": f"{target}/d?f=../../etc/passwd", "method": "GET"},
         {"status": 200, "headers": {}, "body_preview": "root:x:0:0:root:/root:/bin/sh"}),
        ("http_probe", {"url": f"{target}/.env", "method": "GET"},
         {"status": 200, "headers": {}, "body_preview": "DB_PASSWORD=hunter2"}))


# ---- CVSS 3.1 -----------------------------------------------------------

def test_cvss_scores_are_canonical():
    # Computed by the real CVSS 3.1 formula — these are the published base scores for the vectors.
    expect = {"sqli": 9.8, "path-traversal": 7.5, "exposed-secrets": 7.5,
              "broken-access-control": 7.5, "reflected-xss": 6.1, "missing-headers": 5.3,
              "server-disclosure": 0.0}
    for fid, score in expect.items():
        assert D.cvss_score(D.CVSS_VECTORS[fid]) == score, fid


def test_cvss_band_boundaries():
    assert D.cvss_band(0.0) == "Info"
    assert D.cvss_band(3.9) == "Low"
    assert D.cvss_band(4.0) == "Medium"
    assert D.cvss_band(6.9) == "Medium"
    assert D.cvss_band(7.0) == "High"
    assert D.cvss_band(9.0) == "Critical"


def test_enrich_sorts_and_attaches_cvss():
    items = D.enrich(findings.structured("http://t", _sqli() + _xss()))
    assert [i["band"] for i in items] == ["Critical", "Medium"]  # sqli before xss
    assert items[0]["cvss"] == 9.8
    assert items[0]["cvss_vector"] == D.CVSS_VECTORS["sqli"]


# ---- attack paths (no fabrication) --------------------------------------

def test_single_sqli_yields_db_compromise_path():
    items = D.enrich(findings.structured("http://t", _sqli()))
    paths = D.attack_paths(items)
    assert len(paths) == 1
    assert "database compromise" in paths[0]["title"].lower()


def test_traversal_plus_secret_chains():
    items = D.enrich(findings.structured("http://t", _traversal_and_secret()))
    titles = " ".join(p["title"].lower() for p in D.attack_paths(items))
    assert "credential theft" in titles  # the two combine into a real chain


def test_no_findings_no_paths():
    assert D.attack_paths([]) == []


def test_lone_xss_makes_no_chain():
    # A single reflected XSS with nothing to chain into must not invent a multi-hop path.
    items = D.enrich(findings.structured("http://t", _xss()))
    assert D.attack_paths(items) == []


# ---- executive summary --------------------------------------------------

def test_exec_summary_counts_and_worst():
    items = D.enrich(findings.structured("http://t", _sqli() + _xss()))
    s = D.executive_summary("http://t", items, D.attack_paths(items))
    assert "2 finding" in s and "1 Critical" in s and "sql injection" in s.lower()


def test_exec_summary_clean_when_empty():
    s = D.executive_summary("http://t", [], [])
    assert "no material weaknesses" in s.lower()


# ---- HTML render --------------------------------------------------------

def test_html_has_all_sections_and_branding():
    h = D.to_html("http://t", _sqli() + _traversal_and_secret(),
                  meta={"vendor": "Acme Sec", "client": "BluePeak Ltd"}, version="0.1.0")
    for needle in ("Executive summary", "Findings", "Attack paths", "Acme Sec",
                   "BluePeak Ltd", "CONFIDENTIAL", "CVSS", "AV:N/AC:L"):
        assert needle in h, needle


def test_html_escapes_xss_marker_in_evidence():
    # The deliverable reports an XSS finding; it must NOT itself execute the payload.
    h = D.to_html("http://t", _xss())
    assert "<script>alert(1)</script>" not in h
    assert "&lt;script&gt;" in h


def test_html_eval_watermark_toggle():
    assert "EVALUATION REPORT" in D.to_html("http://t", _sqli(), eval_mode=True)
    assert "EVALUATION REPORT" not in D.to_html("http://t", _sqli(), eval_mode=False)


def test_html_clean_when_no_findings():
    h = D.to_html("http://t", _msgs(("http_probe", {"url": "http://t/", "method": "GET"},
                                     {"status": 200, "headers": {}, "body_preview": "all good"})))
    assert "No material findings" in h
    assert "no material weaknesses" in h.lower()  # summary agrees


# ---- CLI wiring: `nexus --format html` writes a branded .html deliverable ------------------

def test_cli_format_html_writes_deliverable(monkeypatch, tmp_path):
    from redblue import cli
    from redblue import license as _license
    monkeypatch.setattr(_license, "is_commercial_authorized", lambda *a, **k: True)
    monkeypatch.setattr(cli, "_target_reachable", lambda *a, **k: True)
    monkeypatch.setattr(cli, "_build_brain", lambda *a, **k: (object(), None))

    class _Agent:
        # a transcript that yields one confirmed SQLi finding
        messages = _sqli("http://127.0.0.1:8173")

        def __init__(self, *a, **k):
            pass

        def run(self, *a, **k):
            return "narrative"

    monkeypatch.setattr(cli, "SecurityAgent", _Agent)
    out = tmp_path / "client.html"
    rc = cli._assess("http://127.0.0.1:8173", [], brain="claude", model=None, ollama_url=None,
                     base=None, adapter=None, effort="high", rules_accepted=True,
                     report=str(out), report_format="html",
                     client="BluePeak Ltd", vendor="Acme Sec", present=cli.PlainPresenter())
    assert rc != 2
    body = out.read_text(encoding="utf-8")
    assert "<!doctype html>" in body.lower()
    assert "BluePeak Ltd" in body and "Acme Sec" in body
    assert "Attack paths" in body and "CVSS" in body
