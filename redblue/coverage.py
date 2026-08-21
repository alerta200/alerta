"""coverage.py — harness-enforced methodology completeness.

The weak local brain tends to stop after surface recon. This tracker watches what the
agent has actually done (what it discovered, probed, and injection-tested) and computes
what's still missing. The agent loop uses it to refuse an early finish: while coverage is
incomplete, the harness injects a concrete "you still have to do X" nudge and forces
another step. This is the 'strong harness + weak brain' lever — the methodology lives in
the harness, so the model can't skip it.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

HREF = re.compile(r"href=['\"]([^'\"]+)['\"]")
TECHNIQUES = ("xss", "sqli", "trav")


class Coverage:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.base_path = urlparse(self.base).path or "/"
        self.discovered: set[str] = set()      # paths found by content_discovery
        self.probed: set[str] = set()          # paths fetched by http_probe
        self.endpoints: dict[str, str] = {}     # path -> a parameter name to test
        self.tested: dict = defaultdict(set)    # (path,param) -> {techniques done}

    # ---- observe each tool call + result ---------------------------------

    def observe(self, tool_name: str, tool_input: dict, content: str):
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError):
            data = {}

        if tool_name == "content_discovery":
            for d in data.get("discovered", []):
                p = d.get("path")
                if p and p != "/":
                    self.discovered.add(p)

        elif tool_name == "http_probe":
            url = tool_input.get("url", "")
            u = urlparse(url)
            path = u.path or "/"
            self.probed.add(path)
            # learn parameterised endpoints from the homepage links
            if path in ("/", self.base_path):
                body = data.get("body_preview", "")
                for href in HREF.findall(body):
                    hu = urlparse(href)
                    params = list(parse_qs(hu.query).keys())
                    if hu.path and params:
                        self.endpoints.setdefault(hu.path, params[0])
            # record any injection test performed on this call
            qs = parse_qs(u.query)
            for param, vals in qs.items():
                val = vals[0] if vals else ""
                tech = self._technique(val)
                if tech:
                    self.tested[(path, param)].add(tech)
                    self.endpoints.setdefault(path, param)

    @staticmethod
    def _technique(val: str):
        if "<script" in val.lower():
            return "xss"
        if "../" in val or val.strip() in ("'", '"'):
            return "sqli" if val.strip() in ("'", '"') else "trav"
        if "'" in val:
            return "sqli"
        return None

    # ---- what's still missing -------------------------------------------

    def missing(self):
        unprobed = sorted(p for p in self.discovered if p not in self.probed)
        untested = []
        for path, param in self.endpoints.items():
            done = self.tested.get((path, param), set())
            for tech in TECHNIQUES:
                if tech not in done:
                    untested.append((path, param, tech))
        return unprobed, untested

    def is_complete(self):
        unprobed, untested = self.missing()
        # only "complete" once we've actually discovered/looked at something
        seen_anything = bool(self.discovered or self.endpoints)
        return seen_anything and not unprobed and not untested

    def nudge(self) -> str:
        unprobed, untested = self.missing()
        parts = ["You are NOT finished. Keep using the tools — do not write the final "
                 "report yet."]
        if unprobed:
            parts.append("Fetch each of these discovered paths with http_probe and inspect "
                         "the response: " + ", ".join(self.base + p for p in unprobed[:8]))
        if untested:
            sample = untested[:6]
            human = {"xss": "reflected-XSS marker <script>alert(1)</script>",
                     "sqli": "a single quote ' for SQL injection",
                     "trav": "../../etc/passwd for path traversal"}
            lines = [f"{self.base}{path} (param '{param}') with {human[tech]}"
                     for path, param, tech in sample]
            parts.append("Test these endpoint/parameter cases via http_probe: "
                         + "; ".join(lines))
        return " ".join(parts)
