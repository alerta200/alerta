"""tools.py — the agent's hands. Every tool is scope-gated and read-leaning.

Two families:
  * built-in stdlib probes (DNS, HTTP, port scan, TLS) — no external deps, safe defaults;
  * a guarded wrapper over allowlisted security binaries (nmap, nuclei, ffuf, ...) for
    when they're installed and the operator wants real depth.

Hard rules enforced here, not left to the model:
  * a tool refuses any target outside ``scope`` (raises ScopeError -> tool_result is_error);
  * only an allowlist of external binaries may run, and their target argument is scope-checked;
  * nothing here performs a destructive or denial-of-service action.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import urllib.error
import urllib.request
from urllib.parse import urlparse, parse_qs, quote

from .scope import Scope, ScopeError

# A SQL error surfaced in a response body (mirrors findings.py) — used to confirm SQLi live.
SQL_ERR_RE = re.compile(r"SQL|psycopg|MySQL|SQLite|ORA-\d|syntax error|unterminated", re.I)

# External binaries the agent is permitted to invoke. Recon / assessment tools only —
# nothing whose default mode is destructive. Flags are still the model's responsibility,
# but the system prompt forbids DoS/destructive switches and the scope gate bounds targets.
ALLOWED_BINARIES = {
    "nmap": "network/service discovery and version detection",
    "nuclei": "template-based vulnerability scanner",
    "ffuf": "content/endpoint fuzzing",
    "gobuster": "directory and DNS brute forcing",
    "whatweb": "web technology fingerprinting",
    "nikto": "web server misconfiguration scanner",
    "sslscan": "TLS configuration assessment",
    "dig": "DNS lookups",
    "host": "DNS lookups",
    "curl": "raw HTTP requests",
}

# Per-run cap so a single tool call can't turn into a port sweep of everything.
MAX_PORTS = 64
HTTP_TIMEOUT = 15
EXTERNAL_TIMEOUT = 300
# A conventional browser User-Agent. Real servers/WAFs routinely drop an obvious scanner
# banner ("redblue/0.1") before we can even read the response headers — which silently hides
# the very surface we're authorized to assess. This is not evasion (the run is authorized and
# throttled): mature scanners (nuclei, ZAP, Burp) default to a browser-like UA for the same
# reason — to observe the app as a real client sees it.
_DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")


# --------------------------------------------------------------------------- #
# scoped HTTP egress — the scope gate must hold on the ACTUAL network path,
# not just the initial URL. urllib follows 3xx redirects by default, so an
# in-scope target that replies `302 -> http://169.254.169.254/` (cloud metadata),
# `-> http://127.0.0.1/`, or any internal host would otherwise make us fetch an
# UNAUTHORIZED target (classic SSRF-via-redirect). Every built-in HTTP probe goes
# through _scoped_open, which re-checks each redirect hop against scope.
# --------------------------------------------------------------------------- #

class _ScopedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-check every redirect hop against scope; refuse one that leaves it.

    An in-scope redirect (e.g. ``/`` -> ``/login``, or http -> https on the same
    host) is still followed, so legitimate behaviour is preserved. A redirect to an
    out-of-scope host is a hard refuse (:class:`ScopeError`) — identical treatment to
    an out-of-scope *initial* target.
    """

    def __init__(self, scope: Scope):
        super().__init__()
        self._scope = scope

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # `newurl` is already absolutised by urllib before this call.
        if not self._scope.allows(newurl):
            raise ScopeError(
                f"redirect to {newurl!r} is OUT OF SCOPE (SSRF guard); "
                "authorized scope is: " + ", ".join(self._scope.raw)
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# A scanner must reach https targets that a browser would REFUSE — self-signed, expired, or
# hostname-mismatched certs are the norm on internal servers, dev/staging boxes, and appliances,
# and are themselves things we assess (tls_info reports the cert as a finding). We connect anyway;
# certificate *validity* is graded separately, not used to block the whole assessment.
_UNVERIFIED_SSL = ssl.create_default_context()
_UNVERIFIED_SSL.check_hostname = False
_UNVERIFIED_SSL.verify_mode = ssl.CERT_NONE


def _scoped_open(req, scope: Scope, timeout):
    """``urlopen`` replacement that enforces ``scope`` on every redirect hop.

    Non-2xx responses still raise :class:`urllib.error.HTTPError` and network faults
    still raise :class:`urllib.error.URLError`, exactly like ``urlopen`` — only the
    redirect-following behaviour changes, and invalid TLS certs don't block the probe.
    """
    scope.throttle()   # politeness: honour the operator's request-rate cap before egress
    opener = urllib.request.build_opener(
        _ScopedRedirectHandler(scope),
        urllib.request.HTTPSHandler(context=_UNVERIFIED_SSL))
    return opener.open(req, timeout=timeout)


# --------------------------------------------------------------------------- #
# built-in probes
# --------------------------------------------------------------------------- #

def dns_lookup(host: str, scope: Scope) -> dict:
    scope.require(host)
    h = Scope._host(host)
    result = {"host": h, "addresses": []}
    try:
        infos = socket.getaddrinfo(h, None)
        result["addresses"] = sorted({i[4][0] for i in infos})
    except socket.gaierror as e:
        result["error"] = str(e)
    return result


def _read_body(resp, resp_headers: dict, max_bytes: int) -> str:
    """Read up to max_bytes and decode as text — decompressing gzip/deflate if a server sent
    it anyway (some ignore Accept-Encoding: identity), so the evidence checks never read a
    compressed body as garbage. Best-effort: on any decode/inflate failure, fall back to raw."""
    raw = resp.read(max_bytes)
    enc = ""
    for k, v in (resp_headers or {}).items():
        if k.lower() == "content-encoding":
            enc = (v or "").lower()
            break
    if raw and ("gzip" in enc or "deflate" in enc):
        import zlib
        # Cap the DECOMPRESSED output at max_bytes. Without a limit a small gzip payload
        # (~4 KB here) can inflate ~1000x — a hostile target could balloon body_preview and
        # the run transcript. We only ever preview max_bytes of text, so bound it there.
        limit = max(1, max_bytes)
        for wbits in ((16 + zlib.MAX_WBITS) if "gzip" in enc else -zlib.MAX_WBITS, zlib.MAX_WBITS):
            try:
                raw = zlib.decompressobj(wbits).decompress(raw, limit)
                break
            except (zlib.error, OSError):
                continue
    return raw.decode("utf-8", "replace")


def http_probe(url: str, scope: Scope, method: str = "GET",
               headers: dict | None = None, body=None, max_bytes: int = 4096) -> dict:
    """GET/POST/etc a URL. ``headers`` adds/overrides request headers (e.g. an
    Authorization bearer token carried from a prior login). ``body`` is the request
    payload: a dict is JSON-encoded (Content-Type application/json) so the agent can
    exercise JSON APIs and authentication endpoints; a string is sent as-is. ``max_bytes``
    caps how much response body is read into ``body_preview`` (default 4 KB keeps the
    trajectory compact; injection confirmation raises it so a marker reflected LATE in a
    large real-world page — past the nav/boilerplate — is not silently missed). Still
    read-leaning — no destructive methods are special-cased, the scope gate bounds the
    host, and the system prompt forbids DoS/destructive use."""
    scope.require(url)
    if "://" not in url:
        url = "http://" + url
    # Ask for an UNCOMPRESSED body: with a browser User-Agent many hosts/CDNs would gzip the
    # response, and a compressed body reads as binary garbage — so a reflected XSS marker / SQL
    # error / /etc/passwd would be silently MISSED (a false negative on a real site).
    hdrs = {"User-Agent": _DEFAULT_UA, "Accept-Encoding": "identity"}
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        else:
            data = str(body).encode("utf-8")
    for k, v in (headers or {}).items():           # caller headers win (e.g. auth, ctype)
        hdrs[str(k)] = str(v)
    method = (method or "GET").upper()
    out: dict = {"url": url, "method": method}
    # Enforce "read-leaning, no destructive actions" IN CODE, not just the prompt: DELETE/PUT/
    # PATCH modify or destroy server state. The request is never sent — a manipulated model (or a
    # prompt-injecting target) cannot make Nexus damage the system it's assessing.
    if method in ("DELETE", "PUT", "PATCH", "TRACE", "CONNECT"):
        out["error"] = (f"REFUSED: {method} can modify/destroy server state; Nexus assesses by "
                        "read-leaning means only. Use GET/POST to probe.")
        return out
    # Real hosts (WAFs, load balancers, flaky demo boxes) intermittently drop a connection
    # mid-scan. A single reset must NOT abort a whole fuzz/crawl sweep, so a connection-level
    # failure (RemoteDisconnected / ConnectionReset / BadStatusLine) is retried once — after
    # the politeness throttle — before being reported as a soft error like any network fault.
    for attempt in range(2):
        req = urllib.request.Request(url, method=method, data=data, headers=hdrs)
        try:
            with _scoped_open(req, scope, HTTP_TIMEOUT) as resp:
                out["status"] = resp.status
                out["headers"] = dict(resp.headers.items())
                out["body_preview"] = _read_body(resp, out["headers"], max_bytes)
            out.pop("error", None)
            return out
        except urllib.error.HTTPError as e:
            out.pop("error", None)
            out["status"] = e.code
            out["headers"] = dict(e.headers.items()) if e.headers else {}
            try:                                    # API errors carry the useful evidence in the body
                out["body_preview"] = _read_body(e, out["headers"], max_bytes)
            except Exception:                       # noqa: BLE001
                pass
            return out
        except (ConnectionError, http.client.HTTPException) as e:
            out["error"] = f"{type(e).__name__}: {e}"   # retry once, then fall through
            continue
        except (urllib.error.URLError, socket.timeout, ssl.SSLError) as e:
            out["error"] = str(e)
            return out
    return out


# Blue-team baseline: response headers every public web app should set, with the
# severity of their absence and the one-line remediation. Pure data so the analysis
# below is deterministic and testable without a network.
_SECURITY_HEADERS = {
    "content-security-policy": (
        "Medium",
        "No Content-Security-Policy: the page has no defence-in-depth against XSS / "
        "content injection.",
        "Add a Content-Security-Policy restricting script/style/connect sources.",
    ),
    "strict-transport-security": (
        "Medium",
        "No HTTP Strict-Transport-Security: clients can be downgraded to plaintext HTTP "
        "(SSL-strip).",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' over HTTPS.",
    ),
    "x-content-type-options": (
        "Low",
        "No X-Content-Type-Options: browsers may MIME-sniff responses into a dangerous type.",
        "Add 'X-Content-Type-Options: nosniff'.",
    ),
    "x-frame-options": (
        "Low",
        "No X-Frame-Options (and no CSP frame-ancestors): the page can be framed for "
        "clickjacking.",
        "Add 'X-Frame-Options: DENY' or a CSP 'frame-ancestors' directive.",
    ),
    "referrer-policy": (
        "Info",
        "No Referrer-Policy: full URLs may leak to third parties via the Referer header.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ),
}

# Headers that advertise stack/version and help an attacker fingerprint you.
_DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version")


def analyze_security_headers(headers: dict) -> list:
    """Pure analysis: given a response-header dict, return a list of findings.

    Deterministic and network-free so it can be unit-tested directly.
    """
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    findings = []
    for name, (severity, why, fix) in _SECURITY_HEADERS.items():
        present = name in lower
        # X-Frame-Options is also satisfied by a CSP frame-ancestors directive.
        if not present and name == "x-frame-options":
            csp = lower.get("content-security-policy", "")
            if "frame-ancestors" in csp.lower():
                present = True
        if not present:
            findings.append({"severity": severity, "header": name,
                             "issue": why, "remediation": fix})
    for name in _DISCLOSURE_HEADERS:
        if name in lower:
            findings.append({
                "severity": "Info", "header": name,
                "issue": f"Header '{name}: {lower[name]}' discloses stack/version, "
                         "aiding fingerprinting.",
                "remediation": f"Remove or genericise the '{name}' response header.",
            })
    return findings


def security_headers(url: str, scope: Scope) -> dict:
    """Fetch a URL and grade its HTTP security headers (blue-team posture check)."""
    scope.require(url)
    probe = http_probe(url, scope)
    if "error" in probe and "headers" not in probe:
        return {"url": probe.get("url", url), "error": probe["error"]}
    findings = analyze_security_headers(probe.get("headers", {}))
    return {
        "url": probe.get("url", url),
        "status": probe.get("status"),
        "findings": findings,
        "summary": f"{len(findings)} header issue(s)",
    }


# A small built-in content-discovery wordlist of commonly-sensitive paths. This is the
# same idea as gobuster/ffuf wordlists — standard methodology, not target-specific
# knowledge — so the agent can find unlinked endpoints without an external binary.
_DISCOVERY_PATHS = [
    # classic server-app surface
    "/.env", "/.env.bak", "/.git/config", "/admin", "/admin/", "/login",
    "/dashboard", "/console", "/backup", "/backup.sql", "/database.sql",
    "/config.php", "/config.json", "/robots.txt", "/.htaccess", "/server-status",
    "/phpinfo.php", "/debug", "/test", "/users", "/download", "/search",
    "/wp-admin", "/.well-known/", "/.well-known/security.txt",
    # API / SPA / modern surface — standard methodology, not target-specific
    "/api", "/rest", "/graphql", "/ftp", "/ftp/", "/swagger.json", "/swagger-ui",
    "/openapi.json", "/v1", "/v2", "/actuator", "/metrics", "/sitemap.xml",
    # machine-readable API contracts — an exposed spec lists every documented endpoint
    "/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json",
    # nested API collection routes — where excessive-data-exposure / broken-access lives. A
    # SPA serves its shell for "/users", so the real data sits under /api|/rest, not the root.
    "/api/users", "/api/user", "/api/accounts", "/api/members", "/api/customers",
    "/api/orders", "/api/products", "/rest/users", "/rest/user", "/v1/users", "/api/v1/users",
    # search endpoints (a classic injection surface) live under /api|/rest too, not just /search
    "/api/search", "/search/query", "/rest/products/search", "/api/products/search",
    # admin / debug / dump variants — the same collection, but leaking credentials & no auth.
    "/admin/users", "/admin/users/all", "/api/admin/users", "/debug/users", "/internal/users",
    "/api/users/_debug", "/api/v1/_dump", "/users/v1/_debug",
    # login endpoints — surfacing them points the agent at login_test (SQLi auth-bypass). The
    # real route is often /auth/login or /rest/user/login, not the bare /login.
    "/auth/login", "/api/login", "/rest/user/login", "/user/authenticate", "/signin", "/session",
]

# When content_discovery hits one of these (in the path) with a JSON body, try to parse it as
# an OpenAPI/Swagger contract: an exposed spec enumerates documented routes (debug/admin/
# collection endpoints) that a blind wordlist never guesses. Standard API-recon, target-agnostic.
_SPEC_HINTS = ("openapi", "swagger", "api-docs")
# Endpoints whose name hints at sensitive/collection data — surfaced first so the agent's
# limited context spends its next probe on the routes most likely to expose data.
_SENSITIVE_HINT = re.compile(
    r"debug|admin|user|account|internal|token|secret|key|password|passwd|config|private|"
    r"credential|dump|backup|export|\ball\b", re.I)


def _extract_openapi(body: str):
    """If `body` is an OpenAPI/Swagger JSON document, return its documented path templates,
    ranked sensitive-looking + concrete (no ``{param}``) first; otherwise None."""
    try:
        doc = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc):
        return None
    spec_paths = doc.get("paths")
    if not isinstance(spec_paths, dict):
        return None
    paths = [p for p in spec_paths if isinstance(p, str)]

    def _rank(p):
        return (0 if _SENSITIVE_HINT.search(p) else 1, 0 if "{" not in p else 1, len(p))

    return sorted(paths, key=_rank)


def _ctype_kind(ct: str) -> str:
    ct = (ct or "").lower()
    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    if "xml" in ct:
        return "xml"
    return ct.split(";")[0] or "other"


def content_discovery(base_url: str, scope: Scope) -> dict:
    """Probe a built-in wordlist of common sensitive paths; report which exist AND which
    differ from the app's catch-all baseline.

    Single-page apps (Angular/React) return ``200 + index.html`` for *every* unknown path,
    so a plain "non-404" check reports junk. We first fetch a random nonexistent path to
    learn the catch-all signature (status, content-type, length), then flag each hit as
    ``interesting`` only when it deviates from that baseline (different status, a non-HTML
    content type like JSON, or a materially different body size). This is generic
    methodology — it makes API/listing endpoints stand out from the SPA shell without any
    target-specific knowledge.
    """
    scope.require(base_url)
    if "://" not in base_url:
        base_url = "http://" + base_url
    base = base_url.rstrip("/")

    def _get(path, cap=8192):
        url = base + path
        req = urllib.request.Request(
            url, method="GET", headers={"User-Agent": "nexus/0.1 (authorized-scan)",
                                        "Accept-Encoding": "identity"})
        try:
            with _scoped_open(req, scope, 5) as resp:
                # Inflate a gzipped body (identity is a request, not a guarantee) so directory
                # listings / leaked secrets in the body are matched on real text, not garbage.
                text = _read_body(resp, dict(resp.headers), cap)
                return {"status": resp.status, "len": len(text),
                        "ctype": resp.headers.get("Content-Type", ""),
                        "body": text}
        except urllib.error.HTTPError as e:
            return {"status": e.code, "len": 0, "ctype": "", "body": ""}
        except ScopeError:
            # A path that redirects off-scope is SKIPPED, not fetched — keep discovering
            # the rest rather than aborting the whole run on one stray redirect.
            return None
        except (urllib.error.URLError, socket.timeout, ssl.SSLError):
            return None

    base_probe = _get("/redblue-nonexistent-" + "".join("0123456789abcdef"[i % 16]
                                                         for i in range(16)))
    bstat = base_probe["status"] if base_probe else None
    bkind = _ctype_kind(base_probe["ctype"]) if base_probe else None
    blen = base_probe["len"] if base_probe else 0
    bhead = (base_probe["body"][:512] if base_probe else "")  # catch-all body signature

    found = []
    for p in _DISCOVERY_PATHS:
        r = _get(p)
        if r is None or r["status"] == 404:
            continue
        kind = _ctype_kind(r["ctype"])
        # interesting = deviates from the SPA/catch-all baseline. Compare the BODY itself,
        # not just length: the SPA shell is byte-identical every time, so a different body
        # head means a real endpoint even when the truncated lengths happen to match.
        interesting = (r["status"] != bstat or kind != bkind
                       or r["body"][:512] != bhead)
        entry = {"path": p, "status": r["status"], "len": r["len"],
                 "ctype": r["ctype"], "interesting": bool(interesting)}
        # Surface a short body signature of real endpoints so the scorer can catch an
        # admin/no-auth interface (broken access control) or leaked secrets right at
        # discovery — coverage that doesn't depend on the model re-probing the path.
        if interesting:
            entry["body_preview"] = r["body"][:512]
        # surface a directory-listing body so the model/scorer can spot exposed files —
        # only on a real (non-baseline) endpoint, else the SPA shell's own <a> tags
        # would false-positive every path as a "listing".
        blow = r["body"].lower()
        if interesting and ("index of" in blow or "listing directory" in blow
                            or r["body"].count('href="') >= 3):
            entry["listing"] = True
        found.append(entry)

    # Only the endpoints that DIFFER from the catch-all baseline are worth the model's
    # attention (and its limited context). Paths that merely echo the SPA shell are
    # collapsed to a count instead of dumped — this both focuses the agent on real
    # endpoints and keeps the tool result compact (a 30-path SPA dump otherwise dominates
    # the trajectory and pushes later steps past the context/training window).
    interesting = [f for f in found if f.get("interesting")]
    baseline_matched = len(found) - len(interesting)

    # Spec-aware discovery: if any discovered endpoint is an exposed OpenAPI/Swagger contract,
    # parse it and surface the DOCUMENTED endpoints — routes like /users/v1/_debug that no
    # blind wordlist contains. This is the API analog of a wordlist (generic methodology, not
    # target-specific), and it hands the agent the exact sensitive paths to probe next.
    documented = []
    for f in interesting:
        if "json" not in _ctype_kind(f["ctype"]) or not any(
                h in f["path"].lower() for h in _SPEC_HINTS):
            continue
        full = _get(f["path"], cap=524288)     # untruncated: a big spec must parse as JSON
        eps = _extract_openapi(full["body"]) if full else None
        if eps:
            f["is_api_spec"] = True
            documented = eps
            break

    result = {"base": base, "tested": len(_DISCOVERY_PATHS),
              "baseline": {"status": bstat, "ctype_kind": bkind, "len": blen,
                           "note": "catch-all signature; paths matching it are the SPA shell"},
              "baseline_matched_count": baseline_matched,
              "discovered": interesting,
              "interesting": [f["path"] for f in interesting],
              "summary": f"{len(interesting)} real endpoint(s) differ from the catch-all "
                         f"baseline; {baseline_matched} other path(s) just echoed the SPA shell"}
    if documented:
        result["documented_endpoints"] = documented[:20]
        result["summary"] += (
            f". An exposed API spec documents {len(documented)} endpoint(s) — http_probe the "
            f"sensitive ones next (they expose data no wordlist would find): "
            f"{', '.join(documented[:6])}")
    return result


# Credential field names a pentester sprays at a JSON login when the app doesn't advertise
# them — these generalize (Juice Shop uses `email`), so the tool tries them all in one call.
_CRED_FIELDS = ["email", "username", "user", "login", "mail", "userid", "account"]
# A standard SQL-injection auth-bypass tautology.
_SQLI_LOGIN = "' OR 1=1--"


# Canonical, live-confirmable injection payloads. Each is chosen so the VERDICT comes from
# the target's own response — a marker reflected verbatim, /etc/passwd contents, or a SQL
# error — never from the model's prose. Mirrors findings.py's detection exactly.
# Conventional parameter names sprayed at bare API endpoints that expose none in their HTML
# (search/query/id/file… cover the common injection surfaces). Generic, not target-specific.
_COMMON_PARAMS = ["q", "query", "search", "term", "keyword", "id", "name", "file", "path",
                  "page", "user", "account", "title", "body", "input", "data"]
_FUZZ_XSS = "<script>alert(1)</script>"
_FUZZ_TRAVERSAL = "../../../../../../etc/passwd"
_FUZZ_SQLI = "'"
# Injection confirmation reads more of the body than the default 4 KB preview: a real page's
# reflection/error can sit far past the nav boilerplate, and missing it is a false negative.
_FUZZ_READ = 65536
# Pull every parameterised link out of an HTML page: href/src/action with a ?a=b query.
_PARAM_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"]*\?[^'"#]+)['"]""", re.I)
# Broader net: ANY `/path?a=b` sequence in the body — catches URLs built in inline <script>
# or embedded in JSON that never appear in an href attribute (a real-app blind spot for a
# link-only scan). Bounded charset so it stops at quotes/space/markup.
_URL_PARAM_RE = re.compile(r"""(?<![\w/])(/[\w\-./]*\?[\w.\-]+=[^\s"'<>)]*)""")
# Form parsing: a <form> block, its action/method, and the field names inside it.
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r"""\baction\s*=\s*['"]([^'"]*)['"]""", re.I)
_METHOD_RE = re.compile(r"""\bmethod\s*=\s*['"]?\s*(get|post)""", re.I)
_FIELD_RE = re.compile(r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*['"]([^'"]+)['"]""", re.I)


def _param_targets(html: str):
    """Yield (path, param) pairs for every distinct query parameter that appears in an HTML
    page — whether in an href/src/action attribute OR built into inline script/JSON."""
    seen = set()
    for rx, grp in ((_PARAM_LINK_RE, 1), (_URL_PARAM_RE, 1)):
        for m in rx.finditer(html or ""):
            u = urlparse(m.group(grp))
            path = u.path or "/"
            # Real sites use root-relative links WITHOUT a leading slash (`index.jsp?a=b`).
            # urlparse keeps them bare, so a naive `base + path` join fuses host+path
            # (`http://host` + `index.jsp` -> `http://hostindex.jsp`). Normalise to an
            # absolute path so every downstream join is correct.
            if not path.startswith("/"):
                path = "/" + path
            for param in parse_qs(u.query):
                key = (path, param)
                if key not in seen:
                    seen.add(key)
                    yield path, param


# Any link a page points at (with or without a query): href/src/action attributes AND
# quoted "/path" URLs built in inline script. Used by the crawler to expand attack surface.
_ANY_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*['"]([^'"#\s]+)['"]""", re.I)
_JS_PATH_RE = re.compile(r"""['"](/[\w\-./]+(?:\?[^\s"'<>]*)?)['"]""")


def _page_links(html: str):
    """Yield the path portion of every internal link on a page (attributes + JS-built)."""
    seen = set()
    for rx in (_ANY_LINK_RE, _JS_PATH_RE):
        for m in rx.finditer(html or ""):
            raw = m.group(1)
            u = urlparse(raw)
            # same-origin only: skip absolute URLs to other hosts and non-http schemes.
            if u.scheme and u.scheme not in ("http", "https"):
                continue
            if u.netloc:
                continue
            path = u.path
            if path.startswith("/") and path not in seen:
                seen.add(path)
                yield path


try:                       # optional: JS rendering for single-page apps. redblue works without it.
    from playwright.sync_api import sync_playwright as _sync_playwright
    _HAS_PLAYWRIGHT = True
except ImportError:
    _HAS_PLAYWRIGHT = False

# An SPA landing page is a near-empty shell whose UI is built by JS: a root mount point and
# script tags, but no real navigation links. Detect that so we only pay the browser cost when
# static extraction would otherwise come up empty.
_SPA_SHELL_RE = re.compile(r"""id\s*=\s*['"]?(root|app|__next|___gatsby)['"]?""", re.I)
# Static assets — links to these are not navigation, so they don't disqualify an SPA shell.
_ASSET_RE = re.compile(r"\.(js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|json)(\?|$)", re.I)


def _looks_like_spa(body: str, links_found: int) -> bool:
    if links_found:
        return False
    b = body or ""
    return "<script" in b.lower() and (bool(_SPA_SHELL_RE.search(b)) or len(b) < 1500)


def render_page(url: str, scope: Scope, timeout_ms: int = 8000) -> dict:
    """Render ``url`` in a headless browser and return ``{rendered_html, api_urls}``.

    For single-page apps the real links, forms, and API calls only exist after JavaScript
    runs. This executes the page and returns both the rendered DOM and the same-scope URLs the
    page actually requested (its API surface) — endpoints no static/regex scan would find.
    Requires the optional ``playwright`` extra; raises if it is unavailable.
    """
    if not _HAS_PLAYWRIGHT:
        raise LocalRenderUnavailable("playwright is not installed (pip install playwright)")
    scope.require(url)
    scope.throttle()
    reqs: list[str] = []
    with _sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            page.on("request", lambda r: reqs.append(r.url))
            page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            html = page.content()
        finally:
            browser.close()
    # Keep only the app's OWN (in-scope) requests — its API surface, not third-party assets.
    api = []
    for u in reqs:
        if u not in api and scope.allows(u):
            api.append(u)
    return {"rendered_html": html, "api_urls": api}


class LocalRenderUnavailable(RuntimeError):
    """Raised when JS rendering is requested but playwright isn't installed."""


def crawl(base_url: str, scope: Scope, max_pages: int = 15, max_depth: int = 2) -> dict:
    """Breadth-first fetch of same-scope pages, returning ``{path: body_preview}``.

    Real applications spread their attack surface across many linked pages; a scan that only
    reads the landing page under-reports. This walks in-scope links (from href/src/action and
    JS-built URLs) to a small page/depth cap, so the fuzzer sees the whole reachable surface.
    Every fetch goes through the scope gate and the politeness throttle. Bounded on purpose —
    it is a coverage aid, not a full spider.
    """
    scope.require(base_url)
    if "://" not in base_url:
        base_url = "http://" + base_url
    base = base_url.rstrip("/")
    pages: dict = {}
    queue = [("/", 0)]
    seen = {"/"}
    while queue and len(pages) < max_pages:
        path, depth = queue.pop(0)
        full = base + path
        if not scope.allows(full):
            continue
        r = http_probe(full, scope)
        body = r.get("body_preview", "") or ""
        links = list(_page_links(body))
        # SPA fallback: if the page is an empty JS shell, render it so the real DOM links,
        # forms, and API calls become visible. The captured API URLs are appended to the body
        # so the existing param/link extractors pick them up unchanged. Asset links
        # (.js/.css/…) don't count as navigation — an app-shell with only a bundle is still an SPA.
        nav_links = [l for l in links if not _ASSET_RE.search(l)]
        if _HAS_PLAYWRIGHT and _looks_like_spa(body, len(nav_links)):
            try:
                rendered = render_page(full, scope)
                # Reduce captured API calls to path?query so the param extractors (which
                # anchor on a leading '/') pick them up as targets.
                api_rel = []
                for u in rendered["api_urls"]:
                    pu = urlparse(u)
                    api_rel.append(pu.path + ("?" + pu.query if pu.query else ""))
                body = rendered["rendered_html"] + "\n" + "\n".join(api_rel)
                links = list(_page_links(body))
            except Exception:   # noqa: BLE001 — rendering is best-effort, never fatal
                pass
        pages[path] = body
        if depth >= max_depth:
            continue
        for link in _page_links(body):
            lp = urlparse(link).path
            if lp not in seen:
                seen.add(lp)
                queue.append((lp, depth + 1))
    return pages


def _form_targets(html: str, page_path: str):
    """Yield (method, action_path, [field_names]) for every <form> on the page. A GET form's
    fields are query params; a POST form's fields are body params — both are attack surface a
    link-only scan misses entirely."""
    for fm in _FORM_RE.finditer(html or ""):
        head = fm.group(0)[:fm.group(0).find(">") + 1]
        am = _ACTION_RE.search(head)
        action = am.group(1) if am and am.group(1) else page_path or "/"
        action = urlparse(action).path or (page_path or "/")
        if not action.startswith("/"):      # root-relative form action (`search.jsp`) -> absolute
            action = "/" + action
        method = (_METHOD_RE.search(head).group(1).upper() if _METHOD_RE.search(head) else "GET")
        fields = []
        for fm2 in _FIELD_RE.finditer(fm.group(1)):
            if fm2.group(1) not in fields:
                fields.append(fm2.group(1))
        if fields:
            yield method, action, fields


def fuzz_params(base_url: str, scope: Scope, pages=None) -> dict:
    """Crawl a page (and any given extra pages), extract EVERY query parameter it links to,
    and actively test each one for reflected-XSS, path-traversal, and SQL injection.

    The point is coverage that does not depend on the model remembering to probe each link:
    one call enumerates ``?title=``, ``?account=``, ``?id=`` … and fires all three payloads at
    every one. A weakness is put in ``confirmed`` ONLY when the live response proves it (the
    XSS marker reflected unescaped, ``/etc/passwd`` contents returned, or a SQL error / 500 on
    a quote) — so the result is evidence, not a guess. In-scope targets only.
    """
    scope.require(base_url)
    if "://" not in base_url:
        base_url = "http://" + base_url
    base = base_url.rstrip("/")

    _PAYLOADS = (("reflected-xss", _FUZZ_XSS), ("path-traversal", _FUZZ_TRAVERSAL),
                 ("sqli", _FUZZ_SQLI))

    def _confirm(kind, body, status, path, param, where):
        if kind == "reflected-xss" and _FUZZ_XSS in body:
            return f"`{path}` reflected the script marker unescaped via {where} `{param}`: {_FUZZ_XSS}"
        if kind == "path-traversal" and "root:x:" in body:
            return f"`{path}` returned /etc/passwd contents (`root:x:`) via {where} `{param}`."
        if kind == "sqli" and (status == 500 or SQL_ERR_RE.search(body or "")):
            snip = (body or "").strip().replace("\n", " ")[:120]
            return f"`{path}` returned a SQL error on a quote via {where} `{param}` (HTTP {status}): {snip}"
        return None

    # Enumerate the surface across pages. When the caller names ``pages`` we fetch exactly
    # those; otherwise we crawl the in-scope site so the fuzzer sees the whole reachable
    # surface, not just the landing page. Page bodies are reused (no double-fetch).
    if pages is None:
        pagemap = crawl(base, scope)
    else:
        pagemap = {"/": http_probe(base + "/", scope).get("body_preview", "")}
        for pg in pages:
            pg_path = pg if pg.startswith("/") else "/" + pg
            pagemap[pg_path] = http_probe(base + pg_path, scope).get("body_preview", "")

    get_targets = {}
    form_targets = []   # (method, path, [fields])
    for pg_path, body in pagemap.items():
        for path, param in _param_targets(body):
            get_targets[(path, param)] = True
        for method, action, fields in _form_targets(body, pg_path or "/"):
            form_targets.append((method, action, fields))

    # A bare JSON API endpoint (e.g. /search/query, /api/products) exposes NO HTML links or
    # forms, so nothing above finds its parameters — yet that is exactly where injection lives.
    # Spray a small set of conventional parameter names at endpoints that yielded none: the
    # explicitly-named pages the caller pointed us at, and any API-looking discovered path.
    # Generic pentest methodology (parameter fuzzing), bounded so it never floods a crawl.
    _paths_with_params = {p for (p, _) in get_targets}
    for pg_path in list(pagemap):
        p = pg_path if pg_path.startswith("/") else "/" + pg_path
        if p == "/" or p in _paths_with_params:
            continue
        if pages is not None or any(s in p for s in ("/api", "/rest", "/search", "/graphql")):
            for cp in _COMMON_PARAMS:
                get_targets[(p, cp)] = True
    form_targets = list({(m, a, tuple(f)) for m, a, f in form_targets})
    form_targets = [(m, a, list(f)) for m, a, f in form_targets]

    tested, confirmed = [], []
    seen_hit = set()   # (type, path, param) — don't double-report the same confirmed weakness

    def _record(kind, path, param, ev):
        key = (kind, path, param)
        if key not in seen_hit:
            seen_hit.add(key)
            confirmed.append({"type": kind, "path": path, "param": param, "evidence": ev})

    # GET query parameters.
    for (path, param) in get_targets:
        tested.append({"surface": "GET", "path": path, "param": param})
        for kind, payload in _PAYLOADS:
            r = http_probe(f"{base}{path}?{param}={quote(payload)}", scope, max_bytes=_FUZZ_READ)
            ev = _confirm(kind, r.get("body_preview", ""), r.get("status"), path, param, "query param")
            if ev:
                _record(kind, path, param, ev)

    # Form fields — GET forms as query params, POST forms as an urlencoded body.
    for (method, path, fields) in form_targets:
        for field in fields:
            tested.append({"surface": f"{method} form", "path": path, "param": field})
            for kind, payload in _PAYLOADS:
                if method == "POST":
                    data = "&".join(f"{f}={quote(payload if f == field else 'x')}" for f in fields)
                    r = http_probe(f"{base}{path}", scope, method="POST", body=data,
                                   headers={"Content-Type": "application/x-www-form-urlencoded"},
                                   max_bytes=_FUZZ_READ)
                else:
                    r = http_probe(f"{base}{path}?{field}={quote(payload)}", scope, max_bytes=_FUZZ_READ)
                ev = _confirm(kind, r.get("body_preview", ""), r.get("status"), path, field,
                              f"{method} form field")
                if ev:
                    _record(kind, path, field, ev)

    summary = (f"tested {len(tested)} parameter(s) across "
               f"{len({t['path'] for t in tested})} endpoint(s) "
               f"(GET params + form fields); {len(confirmed)} confirmed injection(s): "
               + (", ".join(sorted({c['type'] for c in confirmed})) or "none"))
    return {"base": base, "tested": tested, "confirmed": confirmed, "summary": summary}


def _join(base_url: str, path: str) -> str:
    if "://" not in base_url:
        base_url = "http://" + base_url
    return base_url.rstrip("/") + "/" + (path or "").lstrip("/")


def login_test(base_url: str, login_path: str, scope: Scope) -> dict:
    """Test a candidate login endpoint for a SQL-injection AUTHENTICATION BYPASS.

    POSTs a SQLi tautology (``' OR 1=1--``) across common credential field names to
    ``base_url + login_path`` and reports whether the server issues an auth token. This is a
    single, simple-signature action the way a pentester thinks ("try SQLi on this login") —
    the tool handles the POST method, the JSON body, the field spraying, and CAPTURES any
    issued token on the run session so a later ``read_collection`` can carry it automatically
    (no need to copy the JWT). Only a live 200 + token counts as a bypass — nothing is faked.
    """
    scope.require(base_url)
    url = _join(base_url, login_path)
    last_status = None
    for field in _CRED_FIELDS:
        body = json.dumps({field: _SQLI_LOGIN, "password": "x"}).encode("utf-8")
        req = urllib.request.Request(
            url, method="POST", data=body,
            headers={"User-Agent": "nexus/0.1 (authorized-scan)",
                     "Content-Type": "application/json",
                     "Accept-Encoding": "identity"})
        try:
            with _scoped_open(req, scope, HTTP_TIMEOUT) as resp:
                # Decode via _read_body so a gzipped 200 (some servers/CDNs compress anyway) is
                # inflated — otherwise the token regex below reads compressed garbage and the
                # auth-bypass evidence is silently lost.
                status = resp.status
                preview = _read_body(resp, dict(resp.headers), 2048)
        except urllib.error.HTTPError as e:
            status = e.code
            try:
                preview = _read_body(e, dict(e.headers), 2048)
            except Exception:                          # noqa: BLE001
                preview = ""
        except (urllib.error.URLError, socket.timeout, ssl.SSLError) as e:
            return {"login_path": login_path, "url": url, "bypassed": False,
                    "error": str(e)}
        last_status = status
        m = re.search(r'"(?:token|access_token|jwt)"\s*:\s*"([^"]+)"', preview)
        if status == 200 and m:
            tok = m.group(1)
            scope.session["token"] = tok               # carried by read_collection
            # Mask the raw token in the transcript: the model never needs the JWT string (the
            # tool carries it automatically), and a real JWT is ~700 volatile chars that change
            # every login — echoing it makes the model's context differ run-to-run and breaks
            # greedy determinism (the trajectory diverges downstream). The evidence scorer keys
            # on bypassed/token_captured, not this preview, so masking is score-neutral.
            masked = preview.replace(tok, "<captured-token>")
            return {"login_path": login_path, "url": url, "bypassed": True,
                    "field": field, "status": status, "token_captured": True,
                    "body_preview": masked}
    return {"login_path": login_path, "url": url, "bypassed": False,
            "status": last_status, "token_captured": False}


def read_collection(base_url: str, path: str, scope: Scope) -> dict:
    """Fetch an API collection/resource, AUTOMATICALLY carrying any token captured by a prior
    ``login_test`` (``Authorization: Bearer …``). Use to test broken access control / excessive
    data exposure (e.g. a user list): try it after a login bypass and the tool reuses the token
    for you — you only supply the path, never the JWT. Returns the live response body as evidence.
    """
    scope.require(base_url)
    url = _join(base_url, path)
    token = scope.session.get("token")
    hdrs = {"User-Agent": "nexus/0.1 (authorized-scan)", "Accept-Encoding": "identity"}
    if token:
        hdrs["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, method="GET", headers=hdrs)
    out = {"path": path, "url": url, "carried_token": bool(token)}
    try:
        with _scoped_open(req, scope, HTTP_TIMEOUT) as resp:
            out["status"] = resp.status
            # _read_body inflates a gzipped body — else the emails/role evidence for broken
            # access control is read as garbage and the finding is lost.
            out["body_preview"] = _read_body(resp, dict(resp.headers), 4096)
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        try:
            out["body_preview"] = _read_body(e, dict(e.headers), 4096)
        except Exception:                              # noqa: BLE001
            out["body_preview"] = ""
    except (urllib.error.URLError, socket.timeout, ssl.SSLError) as e:
        out["error"] = str(e)
    return out


def port_scan(host: str, scope: Scope, ports=None) -> dict:
    scope.require(host)
    h = Scope._host(host)
    if not ports:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                 3306, 3389, 5432, 6379, 8080, 8443]
    ports = [int(p) for p in ports][:MAX_PORTS]
    open_ports = []
    for p in ports:
        scope.throttle()   # politeness: pace the connect-scan to the operator's rate cap
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            if s.connect_ex((h, p)) == 0:
                open_ports.append(p)
        except OSError:
            pass
        finally:
            s.close()
    return {"host": h, "scanned": len(ports), "open_ports": open_ports}


def tls_info(host: str, scope: Scope, port: int = 443) -> dict:
    scope.require(host)
    h = Scope._host(host)
    out: dict = {"host": h, "port": port}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((h, port), timeout=HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=h) as ss:
                out["tls_version"] = ss.version()
                out["cipher"] = ss.cipher()
                cert = ss.getpeercert(binary_form=False)
                # CERT_NONE yields no parsed dict; fetch fields via a verifying probe.
        vctx = ssl.create_default_context()
        with socket.create_connection((h, port), timeout=HTTP_TIMEOUT) as sock:
            with vctx.wrap_socket(sock, server_hostname=h) as ss:
                cert = ss.getpeercert()
                out["subject"] = cert.get("subject")
                out["issuer"] = cert.get("issuer")
                out["notAfter"] = cert.get("notAfter")
                out["subjectAltName"] = cert.get("subjectAltName")
    except ssl.SSLCertVerificationError as e:
        out["cert_verify_error"] = str(e)
    except (OSError, ssl.SSLError, socket.timeout) as e:
        out["error"] = str(e)
    return out


# The scope gate on run_tool must cover the binary's ACTUAL targets, not just the declared
# `target` param: nmap/curl/ffuf act on whatever host/URL sits in `args`, so an in-scope
# `target` with an out-of-scope host smuggled into `args` would escape scope. We scan every
# arg for host/URL/IP candidates and scope-check each. Flags (-sV), ports (80, 1-1000) and
# output files (report.html — they don't resolve) are left alone so real scans still run.
_ARG_URL_RE = re.compile(r'(?:https?|ftp)://[^\s\'"]+', re.I)
_HOSTISH_RE = re.compile(r'^[A-Za-z0-9_.-]+$')


def _looks_like_ip(tok: str) -> bool:
    try:
        ipaddress.ip_address(tok.strip("[]"))
        return True
    except ValueError:
        return False


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except (socket.gaierror, OSError):
        return False


def _arg_hosts(token: str) -> list:
    """Host/URL candidates inside one external-tool arg that must be scope-checked.

    Fail-safe by construction: a genuine network target (an embedded URL, an IP literal, or
    a hostname that resolves) is returned; flags, ports, and output filenames are not. A
    token that can't be reached (doesn't resolve) is harmless to skip — it can't cause egress.
    """
    token = str(token).strip()
    urls = _ARG_URL_RE.findall(token)
    if urls:
        return urls
    if token.startswith("-"):
        if "=" not in token:              # a bare flag (-sV, -oN) carries no standalone host
            return []
        token = token.split("=", 1)[1].strip()
        urls = _ARG_URL_RE.findall(token)
        if urls:
            return urls
    cand = token.lstrip("/").split("/")[0].strip("[]")    # host[:port] from a scheme-less token
    m = re.match(r'^(.*):(\d{1,5})$', cand)
    if m and not _looks_like_ip(cand):                    # strip a trailing :port (keep ::1)
        cand = m.group(1)
    if not cand:
        return []
    if _looks_like_ip(cand):
        return [cand]
    if _HOSTISH_RE.match(cand) and re.search(r'[A-Za-z]', cand) and _resolves(cand):
        return [cand]
    return []


def nuclei_scan(base_url: str, scope: Scope, severity: str = "medium,high,critical",
                tags: str | None = None, timeout_s: int = 90) -> dict:
    """Run the nuclei template scanner against an in-scope URL and return its VERIFIED matches.

    This is redblue's step-change in coverage: nuclei ships thousands of community templates
    (known CVEs, exposed configs/secrets, misconfigurations) that our hand-rolled probes don't
    cover. Every nuclei finding is a live matcher hit — not prose — so it fits the evidence-gate:
    the report credits it as a scanner-verified match with its template id and matched-at URL.

    Runs with structured JSONL output, the operator's rate limit, and a severity floor (info/low
    noise filtered by default). In-scope target only; the URL is scope-checked before launch.
    """
    scope.require(base_url)
    if "://" not in base_url:
        base_url = "http://" + base_url
    path = shutil.which("nuclei")
    if not path:
        return {"target": base_url, "error": "nuclei is not installed on this host",
                "findings": [], "count": 0}
    # Translate the politeness throttle into nuclei's requests-per-second cap.
    rl = max(1, int(round(1.0 / scope.rate_limit))) if scope.rate_limit > 0 else 150
    # -etags dos,fuzzing: NEVER run denial-of-service or fuzzing templates — that would violate
    # Nexus's own no-destructive/no-DoS rule (and they're the slowest). -c/-timeout speed the rest.
    argv = [path, "-u", base_url, "-jsonl", "-silent", "-no-color", "-disable-update-check",
            "-etags", "dos,fuzzing", "-c", "50", "-timeout", "5", "-rl", str(rl),
            "-severity", severity]
    if tags:
        argv += ["-tags", tags]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return {"target": base_url, "error": f"nuclei timed out after {timeout_s}s",
                "findings": [], "count": 0}
    except OSError as e:
        return {"target": base_url, "error": str(e), "findings": [], "count": 0}
    findings = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = j.get("info", {}) or {}
        findings.append({
            "template": j.get("template-id") or j.get("templateID") or "",
            "name": info.get("name", ""),
            "severity": (info.get("severity", "") or "").lower(),
            "matched_at": j.get("matched-at") or j.get("host") or base_url,
            "type": j.get("type", ""),
        })
    return {"target": base_url, "findings": findings, "count": len(findings)}


# Args an allowlisted binary must never receive — even against an in-scope target — because
# they read/write LOCAL files or reach non-web protocols (LFI / SSRF / exfiltration vectors a
# manipulated model or a prompt-injecting target could try). We capture stdout, so no scan ever
# needs the model to write a file itself.
# Require `scheme://` so a header value ("User-Agent: x") or IP:port ("1.2.3.4:80") isn't
# mistaken for a scheme; the no-slash local schemes (file:/etc, data:…) are caught below.
_URL_SCHEME_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]+)://")
# (?=\S): a real local scheme is followed by a path, not a space — so "Data: 5" (a header)
# doesn't match while "data:text/html" and "file:/etc/passwd" do.
_BARE_SCHEME_RE = re.compile(r"^(file|jar|netdoc|data|php|expect|glob):(?=\S)", re.I)
# Write/local-file flags, PER binary (case-sensitive, as the tools parse them): curl -O writes a
# file, but nmap -O is OS detection — same string, opposite risk, so they can't share one set.
_CURL_WRITE = {"-o", "-O", "--output", "--output-dir", "--create-dirs", "-T", "--upload-file",
               "--dump-header", "-D", "--trace", "--trace-ascii", "--cookie-jar", "-c", "-K",
               "--config", "--netrc-file"}
_NMAP_WRITE = {"-oN", "-oX", "-oG", "-oA", "-oS", "--stylesheet", "--resume"}


def _dangerous_arg(binary: str, arg) -> str | None:
    """Return a reason to refuse this external-tool arg, or None if it's safe. Blocks non-web
    schemes, @file local reads, and file-write flags — LFI / SSRF / exfiltration vectors."""
    a = str(arg)
    m = _URL_SCHEME_RE.match(a)
    if m and m.group(1).lower() not in ("http", "https"):
        return f"scheme {m.group(1)}:// is not allowed (only http/https)"
    if _BARE_SCHEME_RE.match(a):
        return "local/exotic URL scheme is not allowed"
    if a.startswith("@") or "=@" in a:
        return "reading a local file into the request (@file) is not allowed"
    write = _CURL_WRITE if binary in ("curl", "wget") else (_NMAP_WRITE if binary == "nmap" else set())
    if a in write or a.startswith(("--output=", "-o=")):
        return f"file-write flag {a!r} is not allowed"
    return None


# nmap script categories/names that attack rather than assess — denial-of-service, exploitation,
# brute force, malware. Running these would break Nexus's no-destructive / no-DoS promise.
_NMAP_BAD_SCRIPT_RE = re.compile(r"(dos|exploit|brute|malware|slowloris|flood)", re.I)


# Rate-limit flag per binary — injected on a throttled (external) target so a run_tool binary
# can't flood a live service faster than the program's rules permit. Our built-in probes already
# obey scope.throttle(); external binaries would otherwise ignore it.
_RATE_FLAG = {"nuclei": "-rl", "ffuf": "-rate", "nmap": "--max-rate"}


def _throttle_args(binary: str, args, scope: Scope):
    if scope.rate_limit <= 0:
        return list(args or [])
    rps = max(1, int(round(1.0 / scope.rate_limit)))
    args = list(args or [])
    flag = _RATE_FLAG.get(binary)
    if flag:
        if not any(str(a) == flag or str(a).startswith(flag + "=") for a in args):
            args += [flag, str(rps)]
    elif binary == "gobuster" and not any("--delay" in str(a) for a in args):
        args += ["--delay", f"{max(1, 1000 // rps)}ms"]
    return args


def _reject_nmap_scripts(args) -> None:
    """Refuse nmap --script specs that reference destructive/DoS/brute/exploit scripts."""
    seq = list(args or [])
    for i, raw in enumerate(seq):
        a = str(raw)
        val = None
        if a == "--script" and i + 1 < len(seq):
            val = str(seq[i + 1])
        elif a.startswith("--script="):
            val = a.split("=", 1)[1]
        elif a.startswith("--script"):
            val = a[len("--script"):].lstrip("=")
        if val and _NMAP_BAD_SCRIPT_RE.search(val):
            raise ScopeError(
                f"refused nmap script {val!r}: dos/exploit/brute/malware scripts are "
                "destructive and violate Nexus's no-DoS rule")


def run_tool(binary: str, args, scope: Scope, target: str) -> dict:
    """Run an allowlisted external security binary against an in-scope target.

    Both the declared ``target`` AND every host/URL/IP found in ``args`` are scope-checked,
    so a host smuggled into ``args`` (e.g. ``curl http://169.254.169.254/``) cannot escape
    scope even when ``target`` itself is authorized.
    """
    if binary not in ALLOWED_BINARIES:
        raise ScopeError(
            f"binary {binary!r} is not allowlisted; allowed: "
            + ", ".join(sorted(ALLOWED_BINARIES))
        )
    scope.require(target)
    for a in (args or []):                # no host/URL/IP in args may leave scope
        reason = _dangerous_arg(binary, a)  # …and no local-file / non-web / write args at all
        if reason:
            raise ScopeError(f"refused arg {a!r}: {reason}")
        for host in _arg_hosts(a):
            scope.require(host)
    if binary == "nmap":
        _reject_nmap_scripts(args)     # no dos/exploit/brute/malware NSE scripts
    args = _throttle_args(binary, args, scope)   # never flood a rate-limited (external) target
    path = shutil.which(binary)
    if not path:
        return {"binary": binary, "error": f"{binary} is not installed on this host"}
    argv = [path] + [str(a) for a in args]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=EXTERNAL_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"binary": binary, "error": f"timed out after {EXTERNAL_TIMEOUT}s",
                "argv": argv}
    except OSError as e:
        return {"binary": binary, "error": str(e), "argv": argv}
    out = proc.stdout
    err = proc.stderr
    return {
        "binary": binary,
        "argv": argv,
        "returncode": proc.returncode,
        "stdout": out[-12000:],
        "stderr": err[-4000:],
    }


# --------------------------------------------------------------------------- #
# registry: schemas the model sees + dispatch
# --------------------------------------------------------------------------- #

def api_schemas() -> list:
    return [
        {
            "name": "dns_lookup",
            "description": "Resolve a hostname to its IP addresses. In-scope targets only.",
            "input_schema": {
                "type": "object",
                "properties": {"host": {"type": "string"}},
                "required": ["host"],
            },
        },
        {
            "name": "http_probe",
            "description": "Send an HTTP request to a URL and return status, response "
                           "headers, and a body preview. Defaults to GET. Set 'method' "
                           "(GET/POST/PUT/...), 'headers' (e.g. an Authorization bearer "
                           "token captured from a prior login), and 'body' (a JSON object "
                           "is sent as application/json; a string is sent verbatim) to "
                           "exercise JSON APIs, login/auth endpoints, and authenticated "
                           "requests. In-scope targets only; no destructive/DoS use.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string"},
                    "headers": {"type": "object"},
                    "body": {"type": ["object", "string"]},
                },
                "required": ["url"],
            },
        },
        {
            "name": "login_test",
            "description": "Test a login/authentication endpoint for a SQL-injection "
                           "AUTHENTICATION BYPASS. Give the base URL and a candidate login "
                           "path (e.g. /rest/user/login, /api/login); the tool POSTs an "
                           "injection tautology across common credential fields and reports "
                           "whether the server issues an auth token — and captures that token "
                           "for later authenticated requests. Spray several candidate login "
                           "paths this way. In-scope targets only.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string"},
                    "login_path": {"type": "string"},
                },
                "required": ["base_url", "login_path"],
            },
        },
        {
            "name": "read_collection",
            "description": "Fetch an API collection/resource path, automatically carrying any "
                           "auth token captured by a prior login_test (Authorization: Bearer). "
                           "Give the base URL and a candidate collection path (e.g. /api/Users, "
                           "/rest/users). Use after a login bypass to test for broken access "
                           "control / excessive data exposure — you supply only the path, the "
                           "tool reuses the token. In-scope targets only.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string"},
                    "path": {"type": "string"},
                },
                "required": ["base_url", "path"],
            },
        },
        {
            "name": "security_headers",
            "description": "Fetch a URL and grade its HTTP security headers "
                           "(CSP, HSTS, X-Frame-Options, X-Content-Type-Options, "
                           "Referrer-Policy) plus version-disclosure headers. Returns "
                           "findings with severity and remediation. In-scope targets only.",
            "input_schema": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
        {
            "name": "content_discovery",
            "description": "Probe a built-in wordlist of commonly-sensitive paths "
                           "(/.env, /admin, /backup, /.git/config, ...) against a base "
                           "URL and report which respond (non-404). Also parses any exposed "
                           "OpenAPI/Swagger spec it finds and returns `documented_endpoints` "
                           "(the API's own list of routes, e.g. debug/user-collection paths) "
                           "— http_probe those next. Use this to find unlinked endpoints. "
                           "In-scope targets only.",
            "input_schema": {
                "type": "object",
                "properties": {"base_url": {"type": "string"}},
                "required": ["base_url"],
            },
        },
        {
            "name": "fuzz_params",
            "description": "The go-to tool for testing web parameters. Crawls the in-scope "
                           "site (following links in href/src/action AND URLs built in inline "
                           "JavaScript), extracts EVERY query parameter and <form> field it "
                           "finds (GET params and POST-body fields), and actively injects "
                           "reflected-XSS, path-traversal, and SQL-injection payloads into "
                           "each one — confirming a hit only when the live response proves it "
                           "(marker reflected, /etc/passwd returned, or a SQL error). Call "
                           "this once after discovery instead of probing each link by hand — "
                           "it covers the whole reachable surface in a single step. Pass "
                           "explicit 'pages' (paths) to fuzz exactly those instead of "
                           "crawling. In-scope targets only.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string"},
                    "pages": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["base_url"],
            },
        },
        {
            "name": "nuclei_scan",
            "description": "Run the nuclei template scanner against a URL and return its "
                           "verified matches (known CVEs, exposed configs/secrets, "
                           "misconfigurations) — thousands of community templates beyond the "
                           "built-in probes. Each hit is a live matcher result reported with "
                           "its template id, name, severity, and matched-at URL. Optionally "
                           "narrow with 'severity' (default medium,high,critical) or 'tags' "
                           "(e.g. 'exposure,misconfig,cve'). In-scope targets only.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string"},
                    "severity": {"type": "string"},
                    "tags": {"type": "string"},
                },
                "required": ["base_url"],
            },
        },
        {
            "name": "port_scan",
            "description": "TCP connect-scan a small set of ports (capped). Returns open "
                           "ports. In-scope targets only; not a DoS tool.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "ports": {"type": "array", "items": {"type": "integer"}},
                },
                "required": ["host"],
            },
        },
        {
            "name": "tls_info",
            "description": "Inspect a TLS endpoint: protocol version, cipher, certificate "
                           "subject/issuer/expiry/SANs. In-scope targets only.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "port": {"type": "integer"},
                },
                "required": ["host"],
            },
        },
        {
            "name": "run_tool",
            "description": "Run an allowlisted external security binary against an in-scope "
                           "target. Allowed: " + ", ".join(sorted(ALLOWED_BINARIES)) +
                           ". Do NOT use destructive or denial-of-service flags. The "
                           "'target' must be the host/URL you are touching so it can be "
                           "scope-checked.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "binary": {"type": "string"},
                    "args": {"type": "array", "items": {"type": "string"}},
                    "target": {"type": "string"},
                },
                "required": ["binary", "target"],
            },
        },
    ]


def dispatch(name: str, tool_input: dict, scope: Scope):
    """Run a tool by name. Returns (content_str, is_error)."""
    try:
        if name == "dns_lookup":
            result = dns_lookup(tool_input["host"], scope)
        elif name == "http_probe":
            result = http_probe(tool_input["url"], scope,
                                method=tool_input.get("method", "GET"),
                                headers=tool_input.get("headers"),
                                body=tool_input.get("body"))
        elif name == "security_headers":
            result = security_headers(tool_input["url"], scope)
        elif name == "content_discovery":
            result = content_discovery(tool_input["base_url"], scope)
        elif name == "fuzz_params":
            result = fuzz_params(tool_input["base_url"], scope, tool_input.get("pages"))
        elif name == "nuclei_scan":
            result = nuclei_scan(tool_input["base_url"], scope,
                                 severity=tool_input.get("severity", "medium,high,critical"),
                                 tags=tool_input.get("tags"))
        elif name == "login_test":
            result = login_test(tool_input["base_url"], tool_input.get("login_path", ""), scope)
        elif name == "read_collection":
            result = read_collection(tool_input["base_url"], tool_input.get("path", ""), scope)
        elif name == "port_scan":
            result = port_scan(tool_input["host"], scope, tool_input.get("ports"))
        elif name == "tls_info":
            result = tls_info(tool_input["host"], scope,
                              int(tool_input.get("port", 443)))
        elif name == "run_tool":
            result = run_tool(tool_input["binary"], tool_input.get("args"),
                              scope, tool_input["target"])
        else:
            return f"unknown tool: {name}", True
    except ScopeError as e:
        return f"REFUSED (out of scope): {e}", True
    except KeyError as e:
        return f"missing required argument: {e}", True
    except Exception as e:  # noqa: BLE001 - surface any tool failure to the model
        return f"tool error: {type(e).__name__}: {e}", True
    return json.dumps(result, default=str), False
