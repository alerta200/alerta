"""Lock the evaluation-mode licence gate in the assessment path.

Business rule (see cli._assess): assessing an EXTERNAL / public-internet target is a commercial
use and needs a valid licence; LOCAL / private / lab targets run free in evaluation mode, but the
report they produce is watermarked so it can't be passed off as a licensed deliverable. A red test
here means either paying customers are blocked from local evaluation, or an unlicensed build can
silently produce a clean client report (revenue leak) — both are product-breaking.
"""

from redblue import cli
from redblue import license as _license


def _unlicensed(monkeypatch):
    monkeypatch.setattr(_license, "is_commercial_authorized", lambda *a, **k: False)


def _licensed(monkeypatch):
    monkeypatch.setattr(_license, "is_commercial_authorized", lambda *a, **k: True)


# ---- the external gate ---------------------------------------------------

def test_unlicensed_external_target_is_blocked(monkeypatch):
    # Even WITH the program-rules gate cleared, an unlicensed build must not assess a public
    # target — that's the commercial line. rc 2 = refused before any brain is loaded.
    _unlicensed(monkeypatch)
    rc = cli._assess("http://example.com", [], brain="claude", model=None, ollama_url=None,
                     base=None, adapter=None, effort="high", rules_accepted=True,
                     present=cli.PlainPresenter())
    assert rc == 2


def test_licensed_external_target_passes_licence_gate(monkeypatch, tmp_path):
    # A valid licence must clear the licence gate. We stub the heavy tail so the test stays fast;
    # the point is only that the licence gate did not return 2.
    _licensed(monkeypatch)
    monkeypatch.setattr(cli, "_target_reachable", lambda *a, **k: True)
    monkeypatch.setattr(cli, "_build_brain", lambda *a, **k: (object(), None))

    class _Agent:
        messages: list = []

        def __init__(self, *a, **k):
            pass

        def run(self, *a, **k):
            return "narrative"

    monkeypatch.setattr(cli, "SecurityAgent", _Agent)
    monkeypatch.setattr(cli.findings, "report", lambda *a, **k: "## Findings\n\nnone")
    rc = cli._assess("http://example.com", [], brain="claude", model=None, ollama_url=None,
                     base=None, adapter=None, effort="high", rules_accepted=True,
                     report=str(tmp_path / "report.md"), present=cli.PlainPresenter())
    assert rc != 2


# ---- local evaluation + watermark ---------------------------------------

def _run_local(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_target_reachable", lambda *a, **k: True)
    monkeypatch.setattr(cli, "_build_brain", lambda *a, **k: (object(), None))

    class _Agent:
        messages: list = []

        def __init__(self, *a, **k):
            pass

        def run(self, *a, **k):
            return "narrative"

    monkeypatch.setattr(cli, "SecurityAgent", _Agent)
    monkeypatch.setattr(cli.findings, "report", lambda *a, **k: "## Findings\n\nnone")
    out = tmp_path / "report.md"
    rc = cli._assess("http://127.0.0.1:8173", [], brain="claude", model=None, ollama_url=None,
                     base=None, adapter=None, effort="high", rules_accepted=True,
                     report=str(out), present=cli.PlainPresenter())
    return rc, out.read_text(encoding="utf-8")


def test_unlicensed_local_runs_but_watermarks_report(monkeypatch, tmp_path):
    _unlicensed(monkeypatch)
    rc, body = _run_local(monkeypatch, tmp_path)
    assert rc != 2                                   # local eval is allowed
    assert "EVALUATION REPORT" in body               # watermark present
    assert "NOT A LICENSED DELIVERABLE" in body


def test_licensed_local_report_has_no_watermark(monkeypatch, tmp_path):
    _licensed(monkeypatch)
    rc, body = _run_local(monkeypatch, tmp_path)
    assert rc != 2
    assert "EVALUATION REPORT" not in body
