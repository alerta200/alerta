"""Lock the compliance mapping: every evidence-gated finding class maps to CWE / OWASP 2021 / PCI,
and the deliverable renders that mapping. This is what makes the report a compliance artefact for a
SOC 2 / ISO / PCI client — so the coverage must be complete and stable.
"""

import json

from redblue import compliance, deliverable, findings


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


def test_every_finding_class_is_mapped():
    # Invariant: if someone adds a finding class to findings._SPEC, it MUST get a compliance row —
    # a client report can't have an unmapped finding. This test forces that.
    spec_ids = {fid for fid, _label, _sev in findings._SPEC}
    assert spec_ids <= set(compliance.COMPLIANCE), spec_ids - set(compliance.COMPLIANCE)


def test_mapping_shape_is_complete():
    for fid, m in compliance.COMPLIANCE.items():
        assert m["cwe"][0].startswith("CWE-"), fid
        assert m["owasp"][0].startswith("A") and ":2021" in m["owasp"][0], fid
        assert m["pci"][0] and m["pci"][1], fid


def test_for_finding_none_when_unmapped():
    assert compliance.for_finding("nuclei-template-xyz") is None


def test_short_line_format():
    line = compliance.short_line("sqli")
    assert "CWE-89" in line and "OWASP A03:2021" in line and "PCI DSS 6.2.4" in line
    assert compliance.short_line("unknown") == ""


def test_owasp_coverage_groups_and_sorts():
    items = [{"id": "sqli", "name": "SQL injection"},
             {"id": "reflected-xss", "name": "Reflected XSS"},
             {"id": "broken-access-control", "name": "Broken access control"}]
    cov = compliance.owasp_coverage(items)
    ids = [c[0] for c in cov]
    assert ids == ["A01:2021", "A03:2021"]          # sorted, deduped (sqli+xss share A03)
    a03 = next(c for c in cov if c[0] == "A03:2021")
    assert set(a03[2]) == {"SQL injection", "Reflected XSS"}


def test_enrich_attaches_compliance():
    items = deliverable.enrich(findings.structured(
        "http://t", _msgs(("http_probe", {"url": "http://t/i?id=1'", "method": "GET"},
                           {"status": 500, "headers": {}, "body_preview": "SQL syntax error"}))))
    assert items[0]["compliance"]["cwe"][0] == "CWE-89"
    assert "OWASP A03:2021" in items[0]["standards"]


def test_deliverable_html_has_compliance_section():
    h = deliverable.to_html("http://t", _msgs(
        ("http_probe", {"url": "http://t/i?id=1'", "method": "GET"},
         {"status": 500, "headers": {}, "body_preview": "SQL syntax error"})))
    assert "Compliance mapping" in h
    assert "CWE-89" in h and "A03:2021" in h and "PCI DSS" in h
    assert "OWASP categories implicated" in h
