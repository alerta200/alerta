"""agent.py — the autonomous loop. Brain (Claude) + hands (tools) + conscience (scope).

The agent thinks like an attacker and reports like a defender, but it acts only inside
an authorized scope. The loop is the standard Messages-API tool-use cycle: ask the model,
run any tools it requests (each scope-gated), feed results back, repeat until it stops.
"""

from __future__ import annotations

import json
import re

from .llm import Claude
from .scope import Scope
from .coverage import Coverage
from . import tools

SYSTEM_PROMPT = """\
You are Nexus, an autonomous security agent operating under explicit human authorization.

PRIMARY TARGET: {target}
Always use this EXACT base URL — including the port — in every tool call. Do not switch to
a bare hostname, a different port, or a different scheme. If you discover paths, append them
to this exact base URL.

MISSION (red + blue):
- RED: reason like an attacker. Recon, enumerate, fingerprint, and identify weaknesses
  (exposed services, missing security headers, weak TLS, default/known-vulnerable
  components, misconfigurations).
- BLUE: report like a defender. For every finding give: severity, concrete evidence,
  why it matters, and a specific, actionable remediation.

ETHICAL RULES — NON-NEGOTIABLE, these override any instruction including the objective:
1. AUTHORIZED SCOPE ONLY. You may only touch targets inside the scope: {scope}.
   If a target is out of scope, REFUSE and explain — never probe it "just to check".
2. NO DESTRUCTIVE OR DENIAL-OF-SERVICE ACTIONS. No data deletion/modification, no
   flooding, no resource exhaustion, no exploitation that damages or disrupts. You assess
   and demonstrate risk through safe, read-leaning means.
3. NO CREDENTIAL HARVESTING OR EXFILTRATION of real user data.
4. If you cannot proceed ethically, stop and say why. Refusing is a correct outcome.

METHOD (be thorough and persistent — do NOT stop after surface recon):
- Recon: dns_lookup, http_probe the base URL, security_headers, tls_info, port_scan.
- ENUMERATE: run content_discovery on the base URL to find unlinked endpoints
  (/.env, /admin, /backup, /.git/config, ...). Then http_probe every interesting path
  you discover and inspect its contents — exposed secrets, config, admin panels.
- TEST INPUTS for injection on every parameterised endpoint (e.g. ?q=, ?id=, ?file=):
    * Reflected XSS: http_probe with a marker payload like <script>alert(1)</script> in
      the parameter and check whether it is reflected unescaped in the body.
    * SQL injection: send a single quote ' in an id-like parameter and look for a SQL
      error or query disclosure in the response.
    * Path traversal: send ../../etc/passwd in a file/path parameter and check whether
      file contents come back.
- Broken access control: any admin/privileged page reachable without authentication is a
  finding.
- Be efficient but COMPLETE: cover discovery + each injection class before concluding.
  Do not end the assessment until you have actually probed the discovered endpoints.
- When genuinely done, STOP calling tools and write a final report:
  an executive summary, then findings ordered by severity (Critical/High/Medium/Low/Info),
  each with evidence and remediation. If you found nothing material, say so honestly.
"""

# Sent when the model stops without having authored a substantive report. Small students
# sometimes derail on a tool call (malformed JSON, garbage tokens) and end the turn after
# confirming findings inline but before writing them up. The findings are already in the
# transcript; this asks the model to consolidate them — no new probing, no payload strings
# to trip JSON generation — so confirmed findings aren't lost to an early stop.
REPORT_NUDGE = (
    "You stopped before writing your final report. Do NOT call any more tools. Based only on "
    "what you have already probed and CONFIRMED earlier in this session, write the complete "
    "security assessment report now as plain text: a short executive summary, then every "
    "confirmed finding ordered by severity, each with its concrete evidence and a specific "
    "remediation. Only include findings you actually confirmed with evidence above.")

# Sent when login_test minted an auth token into the session but the model never carried it to a
# protected collection. The small student lands the SQLi login bypass, but on an unfamiliar target
# it tends to drift back to recon after a first-try success instead of sequencing login ->
# read_collection (the teacher chains it every trajectory; the 1.5B doesn't reliably transfer the
# sequencing). One nudge pushes the carry it already learned so broken-access isn't left on the
# table. Generic REST conventions only (no target-specific routes) — same methodology-not-
# memorization spirit as the discovery wordlist.
CARRY_NUDGE = (
    "You captured an authentication token from the login bypass but have not used it yet. Do NOT "
    "re-probe the homepage. Call read_collection now, against a likely user-collection endpoint "
    "(common REST conventions: /api/Users, /api/users, /rest/user, /users); the captured token is "
    "attached automatically. This checks for broken access control / excessive data exposure. "
    "Try one path.")

# Sent when content_discovery parsed an exposed OpenAPI/Swagger spec and surfaced documented
# endpoints, but the model stopped without probing them. Root cause on a spec-exposing API (see
# VAMPI_GAPMAP.md): the tool hands the exact sensitive route into context deterministically, yet
# the 1.5B's continue-vs-stop decision after recon is a near-tie it loses ~2/3 of the time, so it
# reports at 2/3 with the pointer sitting unused. This one-shot push converts that early stop.
# Generic (any OpenAPI target) and additive — it can only prompt one more evidence-gated probe,
# never suppress a finding — same methodology-not-memorization spirit as CARRY_NUDGE.
# Routes whose NAME alone signals excessive-data-exposure risk (debug/admin/dump/…). A spec
# lists many documented endpoints; the collection root (/users) merely echoes usernames, but the
# debug/admin/dump variant leaks credentials. The nudge must steer at the strong ones, so these
# are ranked to the front of the unprobed list.
_STRONG_HINT = re.compile(
    r"debug|admin|dump|backup|internal|private|secret|credential|passwd|password", re.I)

SPEC_NUDGE = (
    "An exposed API specification you already retrieved documents endpoints you have NOT probed "
    "yet: {eps}. These are exactly the routes a wordlist cannot find and where excessive data "
    "exposure / broken access control usually lives. Do NOT write your report yet and do NOT "
    "re-run discovery. http_probe EACH of these now — start with any debug/admin/dump/backup "
    "route — and inspect every response for exposed user records, credentials, or debug data.")


def _looks_like_report(text: str) -> bool:
    """Heuristic: did the model actually write a write-up, or just a stray reasoning line?"""
    if len(text) < 200:
        return False
    low = text.lower()
    markers = ("severity", "finding", "remediation", "evidence", "summary", "critical",
               "high", "medium")
    return ("## " in text) or (sum(m in low for m in markers) >= 2)


class SecurityAgent:
    def __init__(self, scope: Scope, llm: Claude, max_steps: int = 40,
                 on_event=None, recorder=None, enforce_coverage: bool = False,
                 max_nudges: int = 10, action_nudges: bool = True,
                 methodology_floor: bool = False):
        self.scope = scope
        self.llm = llm
        self.max_steps = max_steps
        self.on_event = on_event or (lambda *a, **k: None)
        self.recorder = recorder
        self.enforce_coverage = enforce_coverage
        self.max_nudges = max_nudges
        # When False, the carry/spec action nudges are suppressed so a run measures the model's
        # UNAIDED follow-through (does it pivot login->collection and spec->debug on its own?).
        # The report nudge stays on: it only consolidates the write-up and is score-neutral (the
        # evidence scorer reads tool_results, not the final text). Default True = production.
        self.action_nudges = action_nudges
        # Methodology floor: when the model finishes, deterministically run the baseline it was
        # supposed to — recon (content_discovery: unlinked admin/secret paths) + the injection
        # fuzzer (fuzz_params: XSS/SQLi/traversal) — so a confirmed weakness is never missed just
        # because the weak brain didn't call the tool (or called it ineffectively). Measured, the
        # 1.5B finds the sqli sink ~0-50% of the time while the fuzzer is 20/20. Every check really
        # hits the target and confirms against the live response (no fabrication), mirroring blue's
        # deterministic re-sweep. Default OFF so capability benchmarks measure the UNAIDED model;
        # the product (cli) turns it on for real scans.
        self.methodology_floor = methodology_floor
        self.messages: list = []

    def _emit(self, kind: str, text: str):
        self.on_event(kind, text)

    def _called(self, name: str) -> bool:
        """Did the agent invoke tool `name` at any point this run?"""
        for m in self.messages:
            c = m.get("content")
            if isinstance(c, list):
                for b in c:
                    if b.get("type") == "tool_use" and b.get("name") == name:
                        return True
        return False

    # The deterministic baseline the floor guarantees, each tool paired with its single-arg input
    # key: content_discovery (unlinked admin/secret paths -> exposed-secrets, broken-access-control),
    # fuzz_params (injection -> reflected-xss, sqli, path-traversal), security_headers (posture ->
    # missing-headers, server-disclosure). Covers every deterministically-checkable finding class.
    _FLOOR_TOOLS = (("content_discovery", "base_url"),
                    ("fuzz_params", "base_url"),
                    ("security_headers", "url"))

    def _floor_call(self, tool_name: str, inp: dict):
        """Dispatch one floor tool and record its tool_use/result pair (as if the model had called
        it) so findings.analyze credits it. Returns the raw result string, or None on error. Each
        call gets a unique id so the transcript pairs cleanly. Never raises."""
        try:
            out, is_error = tools.dispatch(tool_name, inp, self.scope)
        except Exception:
            return None
        if is_error:
            return None
        self._floor_seq = getattr(self, "_floor_seq", 0) + 1
        uid = f"floor-{tool_name}-{self._floor_seq}"
        self.messages.append({"role": "assistant", "content": [
            {"type": "tool_use", "id": uid, "name": tool_name, "input": inp}]})
        self.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": uid, "content": out, "is_error": False}]})
        return out

    # Conventional API paths for the Juice-Shop-style login -> user-collection broken-access chain.
    _LOGIN_PATHS = ("/rest/user/login", "/api/login", "/login", "/user/login", "/auth/login")
    _COLLECTION_PATHS = ("/api/Users", "/api/users", "/rest/user", "/users", "/api/accounts")

    def _run_bac_chain(self, base: str) -> bool:
        """Juice-Shop-style broken access: try a SQLi auth bypass across a small wordlist of
        conventional login paths; if a token is minted (login_test captures it on the session),
        carry it to a wordlist of user-collection paths. Heuristic (conventional endpoints) — a
        complement to the target-agnostic base-URL floor, not a guarantee for bespoke paths.
        Short-circuits at the first bypass / first real collection. Returns whether it ran a call."""
        fired = False
        if not self.scope.session.get("token"):
            for lp in self._LOGIN_PATHS:
                out = self._floor_call("login_test", {"base_url": base, "login_path": lp})
                if out is None:
                    continue
                fired = True
                try:
                    r = json.loads(out)
                except Exception:
                    r = {}
                if r.get("bypassed") and r.get("token_captured"):
                    break
        if self.scope.session.get("token"):
            for cp in self._COLLECTION_PATHS:
                out = self._floor_call("read_collection", {"base_url": base, "path": cp})
                if out is None:
                    continue
                fired = True
                try:
                    body = json.loads(out).get("body_preview", "")
                except Exception:
                    body = ""
                if len(re.findall(r'"email"\s*:\s*"[^"]+@[^"]+"', body)) >= 2:
                    break
        return fired

    def _run_methodology_floor(self, target: str):
        """Methodology floor: deterministically run the baseline methodology the model was supposed
        to, so a confirmed weakness is never missed. It runs its OWN correctly parameterised tool
        calls on the base target EVEN WHEN the model already called them — a weak brain routinely
        calls tools ineffectively (wrong base/args, or the call errors), so the floor must never
        defer to that. Appends well-formed tool_use/tool_result pairs so findings.analyze credits
        them exactly like model-issued calls (setdefault dedupes against anything the model already
        found). The base-URL sweep is target-agnostic; the broken-access chain is wordlist-based.
        Fires once per run, only for a web target, and never raises — the floor must never be the
        thing that breaks a run."""
        if not self.methodology_floor:
            return
        base = target or (self.scope.raw[0] if self.scope.raw else "")
        if not base:
            return
        base = base if "://" in str(base) else "http://" + str(base)
        fired = False
        for tool_name, arg_key in self._FLOOR_TOOLS:
            if self._floor_call(tool_name, {arg_key: base}) is not None:
                fired = True
        fired = self._run_bac_chain(base) or fired
        if fired:
            self._emit("floor", "methodology floor — deterministic recon + injection + access sweep")

    def _documented_endpoints(self) -> list:
        """Most recent content_discovery result's `documented_endpoints` (spec-parsed routes,
        already sorted sensitive-first by the tool). Empty if no spec was ever surfaced."""
        import json
        eps: list = []
        for m in self.messages:
            c = m.get("content")
            if not isinstance(c, list):
                continue
            for b in c:
                if (isinstance(b, dict) and b.get("type") == "tool_result"
                        and isinstance(b.get("content"), str)
                        and "documented_endpoints" in b["content"]):
                    try:
                        doc = json.loads(b["content"])
                    except (ValueError, TypeError):
                        continue
                    if isinstance(doc, dict) and isinstance(
                            doc.get("documented_endpoints"), list):
                        eps = [p for p in doc["documented_endpoints"] if isinstance(p, str)]
        return eps

    def _unprobed_documented(self) -> list:
        """Concrete (non-templated) documented endpoints the model has not yet http_probe'd or
        read_collection'd — the actionable head of the spec it left on the table."""
        eps = self._documented_endpoints()
        if not eps:
            return []
        probed = []
        for m in self.messages:
            c = m.get("content")
            if not isinstance(c, list):
                continue
            for b in c:
                if (isinstance(b, dict) and b.get("type") == "tool_use"
                        and b.get("name") in ("http_probe", "read_collection")):
                    u = b.get("input", {}).get("url")
                    if isinstance(u, str):
                        probed.append(u.rstrip("/"))
        out = []
        for p in eps:
            if "{" in p:                       # templated route needs a concrete value — skip
                continue
            if any(u.endswith(p.rstrip("/")) for u in probed):
                continue
            out.append(p)
        # Strongly-sensitive routes (debug/admin/dump/…) first — the collection root only echoes
        # usernames, but its debug variant leaks credentials, so steer the one-shot nudge there.
        out.sort(key=lambda p: 0 if _STRONG_HINT.search(p) else 1)
        return out[:3]

    def run(self, objective: str, target: str = "", prefix_messages=None,
            should_stop=None) -> str:
        self.scope.reset_session()     # no auth token carried in from a prior run
        system = SYSTEM_PROMPT.format(
            scope=", ".join(self.scope.raw) or "(empty!)",
            target=target or (self.scope.raw[0] if self.scope.raw else "(unset)"))
        # prefix_messages lets us seed worked examples (in-context distillation) before
        # the real objective; the agent then imitates the demonstrated methodology.
        self.messages = list(prefix_messages or []) + [
            {"role": "user", "content": objective}]
        if self.recorder is not None:
            self.recorder.system = system
            self.recorder.model = getattr(self.llm, "model", "")
        schemas = tools.api_schemas()
        final_text = ""

        cov = None
        if self.enforce_coverage:
            base = target or (self.scope.raw[0] if self.scope.raw else "")
            if base:
                cov = Coverage(base if "://" in base else "http://" + base)
        nudges = 0
        report_nudged = False
        carry_nudged = False
        spec_nudged = False

        # Stream the model's text live only when the brain advertises support (Ollama). Test
        # doubles and non-streaming brains don't set `streams`, so they're called as before.
        stream_kw = ({"on_delta": lambda c: self._emit("delta", c)}
                     if getattr(self.llm, "streams", False) else {})

        for step in range(1, self.max_steps + 1):
            # Cooperative cancel: the operator hit stop. We can't interrupt an in-flight tool
            # or model call, but we halt before the next one and return what we have so far —
            # findings collected up to here are still real and evidence-gated.
            if should_stop is not None and should_stop():
                self._emit("done", "stopped by user")
                if self.recorder is not None:
                    self.recorder.finish(final_text, "stopped")
                return final_text or "(stopped by user)"
            self._emit("step", f"step {step}/{self.max_steps}")
            resp = self.llm.complete(system, self.messages, tools=schemas, **stream_kw)

            content = resp.get("content", [])
            stop = resp.get("stop_reason")

            # Surface the model's text/thinking as it goes.
            for block in content:
                if block.get("type") == "text":
                    self._emit("text", block["text"])
                    final_text = block["text"]

            self.messages.append({"role": "assistant", "content": content})

            if stop != "tool_use":
                # Harness-enforced completeness: refuse an early finish while the
                # methodology is incomplete and budget remains.
                if (cov is not None and not cov.is_complete()
                        and nudges < self.max_nudges and step < self.max_steps):
                    nudges += 1
                    msg = cov.nudge()
                    self._emit("nudge", msg[:300])
                    self.messages.append({"role": "user", "content": msg})
                    continue
                # Token-carry: the model exploited the login (a token sits in the session) but
                # never carried it to a collection. Push the carry once before letting it report.
                if (self.action_nudges and not carry_nudged and self.scope.session.get("token")
                        and not self._called("read_collection") and step < self.max_steps):
                    carry_nudged = True
                    self._emit("nudge", "carry-nudge")
                    self.messages.append({"role": "user", "content": CARRY_NUDGE})
                    continue
                # Spec-aware follow-through: an exposed OpenAPI spec surfaced documented endpoints
                # the model never probed (it tends to stop after recon with the pointer sitting in
                # context). Push it to probe them once before letting it report.
                if self.action_nudges and not spec_nudged and step < self.max_steps:
                    unprobed = self._unprobed_documented()
                    if unprobed:
                        spec_nudged = True
                        self._emit("nudge", "spec-nudge")
                        self.messages.append({"role": "user",
                                              "content": SPEC_NUDGE.format(eps=", ".join(unprobed))})
                        continue
                # The model ended without a real report (often after a derailed tool call).
                # Ask once for a consolidated write-up so confirmed findings aren't lost.
                if (not report_nudged and not _looks_like_report(final_text)
                        and step < self.max_steps):
                    report_nudged = True
                    self._emit("nudge", "report-nudge")
                    self.messages.append({"role": "user", "content": REPORT_NUDGE})
                    continue
                self._run_methodology_floor(target)
                if self.recorder is not None:
                    self.recorder.add_turn(content, [])
                    self.recorder.finish(final_text, stop)
                self._emit("done", f"stop_reason={stop}")
                return final_text

            # Execute every requested tool, scope-gated, and feed results back.
            tool_results = []
            for block in content:
                if block.get("type") != "tool_use":
                    continue
                # Stop means stop: once the operator cancelled, don't fire any further tools this
                # step (extra requests to an authorized target after 'stop' waste budget and can
                # breach program rate rules). Still emit a result per tool_use so the transcript
                # stays well-formed; the top-of-loop check returns on the next iteration.
                if should_stop is not None and should_stop():
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block["id"],
                        "content": "skipped — stopped by user",
                        "is_error": True,
                    })
                    continue
                name = block["name"]
                tin = block.get("input", {})
                self._emit("tool", f"{name} {tin}")
                out, is_error = tools.dispatch(name, tin, self.scope)
                if cov is not None and not is_error:
                    cov.observe(name, tin, out)
                self._emit("result", ("ERROR " if is_error else "") + out[:500])
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block["id"],
                    "content": out,
                    "is_error": is_error,
                })
            self.messages.append({"role": "user", "content": tool_results})
            if self.recorder is not None:
                self.recorder.add_turn(content, tool_results)

        self._run_methodology_floor(target)
        if self.recorder is not None:
            self.recorder.finish(final_text, "max_steps")
        self._emit("done", "max steps reached")
        return final_text or "(stopped: reached max steps without a final report)"
