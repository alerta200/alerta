"""knowledge.py — a curated, offline security-and-programming knowledge base that GROUNDS the
chat assistant.

The chat model (a small local model, or Claude) can be shallow or drift on technical questions.
Rather than hope it "knows", we ground it: when a question matches a known topic, the relevant
authoritative reference is injected into the model's context for that turn — cause at the
source-code level, how to fix it, and a short example. This is the evidence-gate idea applied to
chat: don't trust the model's parametric memory, hand it real knowledge.

Everything here is accurate, defensive-oriented security engineering (root cause + remediation).
Pure stdlib, deterministic keyword matching, no embeddings, no network.
"""

from __future__ import annotations

import re

# Each entry: keywords that select it + a compact, authoritative reference the model can answer
# from. Written for a security engineer: the code-level cause, the fix, and a minimal example.
_TOPICS: list[dict] = [
    {
        "id": "sql-injection",
        "keywords": ["sql injection", "sqli", "sql инъекц", "sql-инъекц", "sql инекц",
                     "or 1=1", "union select", "инъекция sql"],
        "title": "SQL injection",
        "text": (
            "Cause: user input is concatenated into a SQL string, so input becomes SQL syntax. "
            "`\"SELECT * FROM users WHERE name='\" + name + \"'\"` with name=`' OR '1'='1` returns "
            "every row; `'; DROP TABLE users;--` can destroy data. Auth bypass via `' OR 1=1--`. "
            "Fix: NEVER build SQL by string concatenation — use parameterised queries / prepared "
            "statements so input is data, never code: (Python) "
            "`cur.execute(\"SELECT * FROM users WHERE name=%s\", (name,))`. Use an ORM or query "
            "builder, validate/allowlist where structure (table/column names) must be dynamic, "
            "and grant the DB account least privilege. Escaping by hand is error-prone — "
            "parameterisation is the real fix."
        ),
    },
    {
        "id": "xss",
        "keywords": ["xss", "cross-site scripting", "cross site scripting",
                     "межсайтов", "script>alert", "reflected xss", "stored xss", "dom xss"],
        "title": "Cross-site scripting (XSS)",
        "text": (
            "Cause: attacker-controlled data is written into an HTML page without context-correct "
            "encoding, so the browser executes it as script. Types: reflected (payload echoed from "
            "the request), stored (persisted then served to others), DOM-based (client JS writes "
            "input into the DOM, e.g. `innerHTML`). Impact: session theft, actions as the victim. "
            "Fix: context-aware OUTPUT ENCODING at the sink — HTML-escape for HTML body, attribute "
            "encoding in attributes, JS-string encoding in scripts, URL-encoding in URLs. Prefer "
            "framework auto-escaping (React/Vue/Angular escape by default; avoid "
            "`dangerouslySetInnerHTML`/`v-html`/`innerHTML` with untrusted data). Add a strict "
            "Content-Security-Policy as defence in depth, and set cookies HttpOnly."
        ),
    },
    {
        "id": "broken-access-control",
        "keywords": ["broken access control", "access control", "idor",
                     "контроль доступа", "нарушен доступ", "authorization bypass",
                     "insecure direct object", "privilege escalation", "эскалац"],
        "title": "Broken access control / IDOR",
        "text": (
            "Cause: the server trusts the client for authorisation — it authenticates *who* you "
            "are but doesn't check *what* you may do. IDOR: `/api/orders/123` returns any order "
            "because the id isn't checked against the current user. Also: missing role checks on "
            "privileged endpoints, client-side-only enforcement, forced browsing to admin pages. "
            "Fix: enforce authorisation SERVER-SIDE on every request, deny by default, and scope "
            "every object lookup to the authenticated principal "
            "(`WHERE id=%s AND owner_id=%s`). Centralise checks (middleware/policy) rather than "
            "sprinkling them; never rely on hidden fields or unguessable ids as access control."
        ),
    },
    {
        "id": "ssrf",
        "keywords": ["ssrf", "server-side request forgery", "server side request",
                     "подделка запрос", "169.254.169.254", "metadata endpoint", "метадан"],
        "title": "Server-side request forgery (SSRF)",
        "text": (
            "Cause: the server fetches a URL supplied (or influenced) by the user, so the attacker "
            "makes the server request internal targets it can reach but the attacker can't — cloud "
            "metadata (`169.254.169.254`), loopback, internal admin panels. Impact: credential "
            "theft (IAM tokens), internal recon, pivoting. Fix: allowlist destinations "
            "(scheme+host), resolve the hostname and validate the RESOLVED IP against a denylist "
            "of internal/loopback/link-local ranges (re-validate to avoid DNS-rebinding TOCTOU), "
            "block redirects to non-allowlisted hosts, disable unused URL schemes, and put egress "
            "behind a proxy that enforces the policy."
        ),
    },
    {
        "id": "path-traversal",
        "keywords": ["path traversal", "directory traversal", "../", "..%2f",
                     "обход каталог", "обход директор", "lfi", "local file inclusion",
                     "/etc/passwd"],
        "title": "Path traversal",
        "text": (
            "Cause: user input is used to build a filesystem path without canonicalisation, so "
            "`../../../../etc/passwd` escapes the intended directory. Fix: don't pass user input "
            "to file APIs directly — resolve to a canonical absolute path and verify it stays "
            "within an allowed base (Python: `full = (base / name).resolve(); "
            "full.is_relative_to(base)`), reject `..`, absolute paths, and encoded traversal "
            "(`%2e%2e%2f`). Prefer an allowlist / indirection (map an id to a known file) over "
            "accepting raw filenames."
        ),
    },
    {
        "id": "command-injection",
        "keywords": ["command injection", "os command", "rce", "remote code execution",
                     "инъекция команд", "shell inject", "shell=true", "system(",
                     "выполнение команд"],
        "title": "OS command injection",
        "text": (
            "Cause: user input is passed to a shell, so shell metacharacters (`; | & $() ` `) run "
            "extra commands — `ping ' + host` with host=`8.8.8.8; rm -rf /`. Fix: avoid the shell "
            "entirely — call the program with an ARGUMENT LIST, not a shell string "
            "(Python: `subprocess.run([\"ping\", \"-c\", \"1\", host])`, never "
            "`shell=True` with interpolation). If a shell is unavoidable, allowlist the input and "
            "use the language's safe-quoting (`shlex.quote`), but arg-list execution is the real "
            "fix. Run with least privilege."
        ),
    },
    {
        "id": "insecure-deserialization",
        "keywords": ["deserialization", "deserialisation", "pickle", "десериализац",
                     "unserialize", "yaml.load", "objectinputstream", "gadget chain"],
        "title": "Insecure deserialization",
        "text": (
            "Cause: untrusted bytes are deserialised into live objects with formats that can "
            "instantiate arbitrary types or run code — Python `pickle.loads`, PyYAML "
            "`yaml.load` (unsafe loader), Java `ObjectInputStream`, PHP `unserialize`. Gadget "
            "chains turn this into remote code execution. Fix: never deserialise untrusted data "
            "with code-capable formats. Use data-only formats (JSON) with a schema; if you must "
            "use YAML, use `yaml.safe_load`; sign/validate serialized blobs you control; and "
            "constrain allowed types where the library supports it."
        ),
    },
    {
        "id": "auth-and-passwords",
        "keywords": ["password", "парол", "hashing password", "bcrypt", "argon2",
                     "хеширован", "хэшир", "credential storage", "хранить парол",
                     "jwt", "session", "аутентификац", "authentication"],
        "title": "Authentication & password storage",
        "text": (
            "Store passwords with a SLOW, salted password hash — Argon2id (preferred), scrypt, or "
            "bcrypt — never MD5/SHA-1/SHA-256 (too fast → brute-forceable) and never plaintext or "
            "reversible encryption. Per-user salt is built into these; add a pepper if you can "
            "keep it secret. Compare with constant-time checks. For sessions/JWT: sign tokens "
            "(strong secret / asymmetric), verify signature AND expiry AND audience, reject "
            "`alg:none`, keep lifetimes short, and store session cookies HttpOnly+Secure+SameSite. "
            "Rate-limit and lock out on repeated failures; support MFA."
        ),
    },
    {
        "id": "security-headers",
        "keywords": ["security header", "csp", "content-security-policy", "hsts",
                     "strict-transport", "заголовк безопасн", "x-frame-options",
                     "clickjacking", "кликджек"],
        "title": "HTTP security headers",
        "text": (
            "Key headers: Content-Security-Policy (restrict script/style/connect sources — the "
            "strongest XSS mitigation; avoid `unsafe-inline`), Strict-Transport-Security (force "
            "HTTPS: `max-age=31536000; includeSubDomains`), X-Content-Type-Options: nosniff "
            "(stop MIME sniffing), X-Frame-Options / CSP frame-ancestors (anti-clickjacking), "
            "Referrer-Policy, and a sane Permissions-Policy. Set Secure+HttpOnly+SameSite on "
            "cookies. Headers are defence in depth, not a substitute for fixing the underlying "
            "code (encode output, parameterise queries, etc.)."
        ),
    },
    {
        "id": "secrets-management",
        "keywords": ["secret", "секрет", "api key", "api-ключ", "hardcoded", "захардкож",
                     "credentials in code", "ключ в код", ".env leak", "exposed secret"],
        "title": "Secrets management",
        "text": (
            "Never hardcode secrets (API keys, DB passwords, tokens) in source or commit them — "
            "they leak via repos, client bundles, and error pages. Fix: load secrets from the "
            "environment or a secrets manager (Vault, cloud KMS/Secrets Manager) at runtime, keep "
            "them out of version control (`.gitignore`, pre-commit secret scanning), rotate on "
            "exposure, and scope each credential to least privilege. If a secret was ever "
            "committed, rotate it — deleting the commit is NOT enough (it stays in history and "
            "clones)."
        ),
    },
    {
        "id": "input-validation",
        "keywords": ["input validation", "валидац", "sanitize", "санитиз", "allowlist",
                     "whitelist", "белый список", "untrusted input", "недоверенн"],
        "title": "Input validation & the trust boundary",
        "text": (
            "Validate at the TRUST BOUNDARY (where untrusted input enters) with an ALLOWLIST of "
            "what's acceptable (type, length, format, range) — allowlists beat denylists because "
            "you can't enumerate all bad input. But validation is not the primary defence against "
            "injection: the real fix is safe handling at the SINK (parameterised queries for SQL, "
            "context encoding for HTML, arg-list exec for shells). Validate for correctness, "
            "encode/parameterise for safety — do both, and never trust client-side validation "
            "alone (re-check server-side)."
        ),
    },
    {
        "id": "csrf",
        "keywords": ["csrf", "cross-site request forgery", "xsrf", "csrf token",
                     "межсайтовая подделка", "поддельн запрос"],
        "title": "Cross-site request forgery (CSRF)",
        "text": (
            "Cause: the browser auto-sends cookies, so a malicious site can make the victim's "
            "browser submit a state-changing request to a site they're logged into. Fix: require "
            "an anti-CSRF token (unpredictable, per-session, verified server-side) on state-"
            "changing requests, and/or set SameSite=Lax|Strict on session cookies. Check the "
            "Origin/Referer for sensitive actions. GETs must be side-effect-free. Note: CSRF "
            "tokens don't protect an endpoint that's also vulnerable to XSS — fix both."
        ),
    },
    {
        "id": "jwt-attacks",
        "keywords": ["jwt attack", "jwt", "json web token", "alg none", "alg:none",
                     "none algorithm", "kid injection", "jwt secret", "jwt подпись",
                     "jwt уязвим", "jwt secret brute", "hs256 rs256"],
        "title": "JWT attacks & correct verification",
        "text": (
            "Common JWT flaws: (1) `alg:none` — server accepts an unsigned token; (2) weak HS256 "
            "secret — brute-forced offline, then forge any token; (3) alg confusion — server "
            "verifies an RS256 token as HS256 using the PUBLIC key as the HMAC secret, so the "
            "attacker forges tokens; (4) `kid`/`jku`/`x5u` header injection pointing verification "
            "at an attacker-controlled key; (5) not checking `exp`/`aud`/`iss`. Fix: pin the "
            "expected algorithm(s) server-side (never trust the token's `alg`), reject `none`, use "
            "a strong random secret (or asymmetric keys) and verify signature AND `exp` AND "
            "audience/issuer; don't resolve keys from token-supplied URLs. Keep lifetimes short "
            "and support revocation for sensitive apps."
        ),
    },
    {
        "id": "cors-misconfig",
        "keywords": ["cors", "cross-origin", "access-control-allow-origin",
                     "allow-credentials", "cors misconfig", "cors уязвим", "origin reflect"],
        "title": "CORS misconfiguration",
        "text": (
            "Cause: an over-permissive CORS policy lets a malicious site read authenticated "
            "responses. The dangerous combo is reflecting the request `Origin` into "
            "`Access-Control-Allow-Origin` together with `Access-Control-Allow-Credentials: true` "
            "— any origin can then make credentialed requests and read the response. "
            "`Allow-Origin: *` with credentials is blocked by browsers, but origin-reflection "
            "bypasses that. Fix: allowlist specific trusted origins (exact match, not "
            "`endsWith`/regex that a subdomain can spoof), only send "
            "`Allow-Credentials: true` for those, and never reflect arbitrary origins. CORS "
            "controls who can READ cross-origin responses — it is not CSRF protection."
        ),
    },
    {
        "id": "xxe",
        "keywords": ["xxe", "xml external entity", "external entity", "xml инъекц",
                     "doctype entity", "billion laughs", "xml parser"],
        "title": "XML external entity (XXE)",
        "text": (
            "Cause: an XML parser resolves external entities defined in a `<!DOCTYPE>`, so "
            "`<!ENTITY x SYSTEM \"file:///etc/passwd\">` leaks local files, and `http://` entities "
            "enable SSRF; nested entities cause a billion-laughs DoS. Fix: disable DTDs / external "
            "entity resolution in the parser (Python: use `defusedxml`; Java: "
            "`setFeature(\"disallow-doctype-decl\", true)` and disable external general/parameter "
            "entities). Prefer JSON if you don't need XML. Never feed untrusted XML to a parser "
            "with default (entity-resolving) settings."
        ),
    },
    {
        "id": "ssti",
        "keywords": ["ssti", "server-side template injection", "template injection",
                     "jinja2 inject", "{{7*7}}", "инъекция шаблон", "шаблонизатор уязвим",
                     "freemarker", "velocity template"],
        "title": "Server-side template injection (SSTI)",
        "text": (
            "Cause: user input is embedded into a server-side template that is then evaluated, so "
            "input becomes template code — `render_template_string(\"Hi \" + name)` with "
            "name=`{{7*7}}` renders `49`, and Jinja2/Twig/Freemarker payloads escalate to reading "
            "files or RCE via the object graph. Fix: never build templates from user input — pass "
            "user data as template VARIABLES/context, not into the template SOURCE. Use a "
            "logic-less/sandboxed template engine for user-authored templates, and keep autoescape "
            "on (it stops XSS, not SSTI — the real fix is not compiling user input as a template)."
        ),
    },
    {
        "id": "race-conditions",
        "keywords": ["race condition", "toctou", "time-of-check", "состояние гонки",
                     "гонк", "double spend", "atomic operation", "concurrency bug",
                     "check-then-act"],
        "title": "Race conditions / TOCTOU",
        "text": (
            "Cause: a check and the action it guards aren't atomic, so concurrent requests slip "
            "between them (time-of-check to time-of-use). Classic: check balance ≥ amount, then "
            "debit — fire N parallel requests and overspend; or check-then-create a file/user. "
            "Fix: make the check-and-act ATOMIC — DB transactions with proper isolation and "
            "row locking (`SELECT ... FOR UPDATE`), conditional/atomic updates "
            "(`UPDATE ... SET bal=bal-? WHERE bal>=?` and check affected rows), unique "
            "constraints, or idempotency keys. Don't rely on read-then-write in application code "
            "under concurrency."
        ),
    },
    {
        "id": "crypto-mistakes",
        "keywords": ["encryption mistake", "aes ecb", "ecb mode", "static iv", "nonce reuse",
                     "weak random", "insecure random", "шифрован ошибк", "md5", "sha1",
                     "roll your own crypto", "hardcoded key", "predictable token"],
        "title": "Common cryptography mistakes",
        "text": (
            "Frequent errors: AES-ECB (identical plaintext blocks → identical ciphertext, leaks "
            "structure) — use AES-GCM (authenticated); reused/static IV or nonce — must be unique "
            "per message; MD5/SHA-1 for signatures/integrity — broken, use SHA-256+; "
            "non-cryptographic RNG (`random`, `Math.random`) for tokens/keys — use a CSPRNG "
            "(`secrets`, `crypto.randomBytes`); encryption without authentication — use an AEAD or "
            "encrypt-then-MAC; hardcoded/predictable keys. Rule: don't roll your own crypto — use "
            "vetted libraries (libsodium/NaCl, the platform crypto) with authenticated modes and "
            "proper key management."
        ),
    },
    {
        "id": "rate-limiting",
        "keywords": ["rate limit", "brute force", "брутфорс", "ограничение запрос",
                     "throttling", "credential stuffing", "перебор пароле", "account lockout",
                     "enumeration", "перечисление"],
        "title": "Rate limiting & brute-force defence",
        "text": (
            "Without rate limiting, attackers brute-force passwords/OTPs, do credential stuffing, "
            "enumerate users, and scrape. Fix: throttle sensitive endpoints (login, password "
            "reset, OTP, token) per-account AND per-IP; use exponential backoff / temporary "
            "lockout after repeated failures; require CAPTCHA or MFA on suspicious volume; and "
            "avoid user-enumeration oracles (return the same message and similar timing for "
            "unknown vs wrong-password, don't reveal which emails exist). Add monitoring/alerting "
            "on spikes. Enforce limits server-side; client throttling is bypassable."
        ),
    },
    {
        "id": "open-redirect",
        "keywords": ["open redirect", "открытый редирект", "unvalidated redirect",
                     "redirect_uri", "returnurl", "next parameter redirect"],
        "title": "Open redirect",
        "text": (
            "Cause: the app redirects to a URL taken from user input without validation "
            "(`/login?next=...`, `redirect_uri=...`), so `?next=https://evil.com` sends users to "
            "an attacker site — used for phishing and, in OAuth, to steal tokens/codes. Fix: "
            "don't redirect to arbitrary user-supplied URLs — allowlist target paths, or accept "
            "only relative paths (reject `//`, `http:`, `https:`, backslashes and encoded "
            "variants). For OAuth `redirect_uri`, exact-match against pre-registered URIs."
        ),
    },
    {
        "id": "file-upload",
        "keywords": ["file upload", "загрузка файл", "upload vulnerab", "unrestricted upload",
                     "webshell", "веб-шелл", "content-type spoof", "double extension"],
        "title": "Insecure file upload",
        "text": (
            "Risks: uploading a server-executable file (`.php`, `.jsp`) into a web-served "
            "directory → RCE (web shell); path traversal in the filename; content-type spoofing; "
            "huge files (DoS); malicious SVG/HTML (stored XSS). Fix: validate the file server-side "
            "by CONTENT (magic bytes), not just extension or client `Content-Type`; store uploads "
            "OUTSIDE the web root (or on object storage) and serve via a handler, never execute "
            "the directory; generate your own random filename (don't trust the user's); cap size; "
            "and set `Content-Disposition: attachment` / a restrictive CSP for served files."
        ),
    },
    {
        "id": "supply-chain",
        "keywords": ["supply chain", "цепочка поставок", "dependency", "зависимост",
                     "npm package", "typosquat", "malicious package", "lockfile",
                     "dependency confusion", "vulnerable dependency", "sbom"],
        "title": "Dependency / supply-chain risk",
        "text": (
            "Most code you ship is third-party. Risks: known-vulnerable versions, typosquatted or "
            "hijacked packages, dependency confusion (a public package shadowing your internal "
            "name), and post-install scripts. Fix: pin versions and commit a lockfile; scan "
            "dependencies for known CVEs (e.g. `pip-audit`, `npm audit`, Dependabot); verify "
            "integrity (hashes / signatures); scope internal registries to prevent confusion; "
            "review new/updated deps and minimise them; and keep an SBOM. Update deliberately, "
            "not blindly — but don't sit on known-vulnerable versions."
        ),
    },
    {
        "id": "python-pitfalls",
        "keywords": ["python security", "python pitfall", "eval python", "pickle python",
                     "yaml.load", "subprocess shell", "python уязвим", "assert auth",
                     "python инъекц", "flask debug"],
        "title": "Python security pitfalls",
        "text": (
            "Watch for: `eval`/`exec` on untrusted input (arbitrary code) — parse instead "
            "(`ast.literal_eval` for literals); `pickle.loads` / `yaml.load` on untrusted data "
            "(RCE) — use JSON / `yaml.safe_load`; `subprocess(..., shell=True)` with interpolation "
            "(command injection) — pass an arg list; using `assert` for security checks (stripped "
            "under `python -O`); f-strings/`%`-format building SQL (use params); `Flask(debug=True)` "
            "/ Werkzeug console in production (RCE); and non-crypto `random` for tokens (use "
            "`secrets`). Also validate archive extraction paths (zip-slip)."
        ),
    },
    {
        "id": "javascript-pitfalls",
        "keywords": ["javascript security", "node security", "prototype pollution",
                     "innerhtml", "eval javascript", "js уязвим", "nodejs уязвим",
                     "__proto__", "child_process exec", "dangerouslysetinnerhtml"],
        "title": "JavaScript / Node.js security pitfalls",
        "text": (
            "Watch for: writing untrusted data via `innerHTML` / `dangerouslySetInnerHTML` / "
            "`document.write` (DOM XSS) — set text or sanitise (DOMPurify); `eval` / `new "
            "Function` / `setTimeout(string)` on input (code injection); prototype pollution via "
            "unsafe deep-merge of user JSON writing `__proto__`/`constructor` (gadget to RCE/auth "
            "bypass) — reject those keys, use `Object.create(null)` / `Map`; `child_process.exec` "
            "with interpolation (command injection) — use `execFile`/`spawn` with an arg array; and "
            "server-side secrets leaking into client bundles. Keep dependencies patched (`npm "
            "audit`)."
        ),
    },
    {
        "id": "secure-defaults",
        "keywords": ["secure by default", "defense in depth", "принцип наименьш",
                     "least privilege", "fail closed", "fail secure", "hardening",
                     "безопасн по умолчан", "эшелонированн", "secure default"],
        "title": "Secure-by-default & defence in depth",
        "text": (
            "Design principles: fail CLOSED (on error/uncertainty, deny — don't fall open); least "
            "privilege (every user/service/token gets the minimum access it needs); defence in "
            "depth (multiple independent layers, so one bypass isn't game over); secure defaults "
            "(the out-of-the-box config is the safe one — opt IN to risk, never rely on users to "
            "harden); minimise attack surface (disable unused features/endpoints/ports); and "
            "complete mediation (check authorisation on every access, not once). Validate at trust "
            "boundaries, encode at sinks, and make the safe path the easy path."
        ),
    },
    {
        "id": "logging-monitoring",
        "keywords": ["logging", "логирован", "log injection", "sensitive data log",
                     "secrets in logs", "monitoring", "мониторинг", "audit log",
                     "insufficient logging"],
        "title": "Logging & monitoring (safely)",
        "text": (
            "Two failure modes: too little (no way to detect or investigate an incident) and "
            "unsafe logging. Do log security events (auth success/failure, access-control denials, "
            "input-validation failures) with enough context to trace. Don't log secrets, full "
            "credentials, tokens, card/PII data. Prevent log injection/forging by neutralising "
            "newlines/control chars in logged user input (an attacker can otherwise fake log "
            "lines). Protect and retain logs, and ALERT on anomalies (spikes in failures, new "
            "admin actions) — logs no one watches don't stop attacks."
        ),
    },
    {
        "id": "api-security",
        "keywords": ["api security", "безопасность api", "bola", "bfla", "mass assignment",
                     "массовое присвоение", "broken object level", "broken function level",
                     "idor api", "rest api уязвим", "api уязвим", "excessive data exposure"],
        "title": "API security (BOLA / BFLA / mass assignment)",
        "text": (
            "APIs concentrate the OWASP API Top 10. BOLA (Broken Object Level Auth, the #1): "
            "`GET /api/orders/123` returns any order because the id isn't scoped to the caller — "
            "authorize EVERY object access against the authenticated principal server-side. BFLA "
            "(Broken Function Level Auth): a regular user calls an admin-only endpoint/method that "
            "isn't role-checked — enforce role per function, deny by default. MASS ASSIGNMENT: the "
            "handler binds the whole JSON body to the model, so `{\"isAdmin\":true}` or "
            "`{\"balance\":9999}` sets fields the client should never control — bind an explicit "
            "allowlist of writable fields (DTO), never the raw object. Also: excessive data "
            "exposure (return only needed fields, don't rely on the client to filter), and always "
            "rate-limit. Auth on every request; there is no trusted client."
        ),
    },
    {
        "id": "graphql-security",
        "keywords": ["graphql", "граф ql", "graphql уязвим", "introspection", "query depth",
                     "query batching", "resolver", "n+1 graphql", "graphql injection"],
        "title": "GraphQL security",
        "text": (
            "GraphQL shifts query power to the client, adding its own risks: (1) INTROSPECTION and "
            "verbose suggestions leak the whole schema — disable introspection and field "
            "suggestions in production. (2) DEEP/RECURSIVE queries and aliased/batched queries "
            "cause DoS or brute-force (many logins in one request) — enforce query depth/complexity "
            "limits, cost analysis, timeouts, and rate-limit by operation. (3) AUTHORIZATION must "
            "be enforced in every RESOLVER, not at a gateway — object/field access is as prone to "
            "BOLA/BFLA as REST (a nested field can bypass a top-level check). (4) Injection still "
            "applies: resolvers hitting SQL/OS must parameterise. Validate inputs, disable batching "
            "if unused, and don't expose internal errors."
        ),
    },
    {
        "id": "cloud-misconfig",
        "keywords": ["cloud security", "облач", "s3 bucket", "public bucket", "iam", "iam policy",
                     "misconfiguration cloud", "aws misconfig", "gcp", "azure", "metadata service",
                     "over-permissive", "publicly accessible"],
        "title": "Cloud misconfiguration (S3 / IAM)",
        "text": (
            "Most cloud breaches are misconfigurations, not exploits. Common: PUBLIC object storage "
            "(S3/GCS buckets world-readable/writable) leaking data — default to private, use Block "
            "Public Access, and audit ACLs/bucket policies. OVER-PERMISSIVE IAM (`Action:*`, "
            "`Resource:*`, wildcard trust) — grant least privilege, scope by resource/condition, "
            "prefer short-lived roles over long-lived keys, and never embed keys in code/AMIs. "
            "Exposed metadata service (SSRF → `169.254.169.254` → creds) — enforce IMDSv2. Also: "
            "public admin ports/security groups (`0.0.0.0/0`), unencrypted storage, disabled "
            "logging (CloudTrail). Enable logging, encrypt at rest, and scan with a CSPM. The shared-"
            "responsibility model: the provider secures the cloud, YOU secure what's in it."
        ),
    },
    {
        "id": "container-security",
        "keywords": ["container security", "docker security", "kubernetes", "k8s", "контейнер",
                     "docker уязвим", "privileged container", "container escape", "pod security",
                     "root container", "image scanning"],
        "title": "Container & Kubernetes security",
        "text": (
            "Containers are isolation, not a security boundary by default. Harden: don't run as "
            "ROOT (set a non-root USER, drop Linux capabilities, read-only rootfs, no `--privileged` "
            "/ no host mounts / no hostPID/Network) — a privileged container ≈ host root (escape). "
            "Use minimal/distroless images, PIN digests, and SCAN images for CVEs (Trivy/Grabber). "
            "Never bake secrets into images (they persist in layers) — mount them. Kubernetes: apply "
            "restrictive Pod Security Standards, NetworkPolicies (default-deny egress/ingress), RBAC "
            "least privilege (no cluster-admin for apps), don't mount the default ServiceAccount "
            "token unless needed, and protect the API server/etcd/kubelet. Keep the runtime patched."
        ),
    },
    {
        "id": "business-logic",
        "keywords": ["business logic", "бизнес-логик", "logic flaw", "логическая уязвим",
                     "workflow bypass", "price manipulation", "negative quantity", "coupon abuse",
                     "abuse of functionality"],
        "title": "Business-logic vulnerabilities",
        "text": (
            "Logic flaws break the RULES of the application even when every input is technically "
            "valid — so scanners miss them; they need understanding of intent. Examples: negative "
            "or fractional quantities yielding a credit; applying a coupon N times; skipping a "
            "checkout/payment step by requesting the confirmation endpoint directly; changing a "
            "price/currency the client shouldn't control; race conditions on limited resources "
            "(see TOCTOU); replaying one-time tokens. Fix: enforce invariants SERVER-SIDE at each "
            "step (validate state transitions, ranges, ownership, and totals recomputed on the "
            "server), make multi-step flows non-skippable and idempotent, and threat-model the "
            "abuse cases per feature. Never trust client-computed values (price, discount, role)."
        ),
    },
    {
        "id": "denial-of-service",
        "keywords": ["denial of service", "dos", "отказ в обслуживании", "resource exhaustion",
                     "redos", "regex dos", "zip bomb", "billion laughs", "unbounded", "amplification"],
        "title": "Denial of service & resource exhaustion",
        "text": (
            "App-layer DoS needs no botnet — one request can exhaust resources. Watch: ReDoS "
            "(catastrophic-backtracking regex on user input — use linear-time regex/RE2, bound "
            "length); unbounded work (huge page sizes, no pagination, N+1, expensive sorts on "
            "user-controlled fields); decompression bombs (zip/XML billion-laughs — cap output "
            "size, disable entity expansion); unbounded uploads/allocations; and amplification "
            "(one request triggering many/expensive downstream calls). Fix: validate and CAP sizes/"
            "counts/time everywhere, paginate, add per-user rate limits and timeouts, use bounded "
            "buffers and streaming, and apply circuit breakers on downstream calls. Fail fast, not "
            "unboundedly."
        ),
    },
    {
        "id": "threat-modeling",
        "keywords": ["threat model", "моделирование угроз", "stride", "attack surface",
                     "trust boundary", "dread", "attack tree", "security design review",
                     "data flow diagram"],
        "title": "Threat modeling",
        "text": (
            "Threat modeling finds design flaws BEFORE code — cheaper than pen-testing them later. "
            "Answer four questions (Shostack): (1) What are we building? — draw a data-flow diagram "
            "with trust boundaries. (2) What can go wrong? — enumerate threats, e.g. STRIDE "
            "(Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation "
            "of privilege), one lens per element/flow crossing a boundary. (3) What are we going to "
            "do about it? — mitigate, accept, transfer, or eliminate each, prioritised by risk. "
            "(4) Did we do a good job? — review and iterate. Focus on where data crosses trust "
            "boundaries (untrusted → trusted). Do it early, keep it living, and drive concrete "
            "requirements/tests from the threats found."
        ),
    },
    {
        "id": "ethical-hacking-method",
        "keywords": ["methodology", "методолог", "pentest process", "этап пентест",
                     "recon", "разведк", "kill chain", "how to pentest", "как проводить пентест",
                     "scope of engagement", "rules of engagement"],
        "title": "Ethical-hacking methodology (authorized only)",
        "text": (
            "An authorized assessment runs in phases: (1) SCOPE & authorization — written "
            "permission, defined targets, rules of engagement, rate limits; nothing outside scope. "
            "(2) Recon/enumeration — map hosts, services, endpoints, tech stack. (3) Vulnerability "
            "analysis — identify likely weaknesses per surface. (4) Exploitation — confirm a flaw "
            "with a safe, minimal proof (evidence), no destruction or DoS. (5) Post-exploitation "
            "(only if in scope) — assess impact without harm. (6) Reporting — severity, evidence, "
            "concrete remediation. Golden rules: stay in scope, do no damage, respect program "
            "rate rules, and evidence every finding. Testing systems you don't own or lack written "
            "permission for is illegal."
        ),
    },
]

_WORD = re.compile(r"\w+", re.UNICODE)


def _norm(s: str) -> str:
    return (s or "").lower()


def match(query: str, limit: int = 2) -> list[dict]:
    """Return the topics most relevant to `query`, best first (empty if none clearly match).

    Scoring rewards a multi-word keyword phrase actually appearing in the query (strong signal)
    over incidental single-word overlaps, so a casual message doesn't pull in a topic."""
    q = _norm(query)
    if not q:
        return []
    scored = []
    for topic in _TOPICS:
        score = 0
        for kw in topic["keywords"]:
            if kw in q:
                # a matched phrase is worth more the more words it has
                score += 2 + kw.count(" ")
        if score:
            scored.append((score, topic))
    scored.sort(key=lambda t: t[0], reverse=True)
    return [t for _s, t in scored[:limit]]


def topics() -> list[dict]:
    """All curated topics as {id, title} — for browsing the knowledge base (e.g. `nexus learn`).
    Ordered as authored (grouped by theme)."""
    return [{"id": t["id"], "title": t["title"]} for t in _TOPICS]


def by_id(topic_id: str) -> dict | None:
    """Fetch a curated topic by its stable id (e.g. "sql-injection"). Lets other modules —
    like the findings report — ground their own text in the same authoritative base, keyed
    directly rather than by fuzzy query."""
    for topic in _TOPICS:
        if topic["id"] == topic_id:
            return topic
    return None


def grounding(query: str, limit: int = 2) -> str:
    """A context block to prepend to the chat system prompt for this turn — authoritative
    reference on the topics the question touches, or "" when nothing matches."""
    hits = match(query, limit)
    if not hits:
        return ""
    body = "\n\n".join(f"### {t['title']}\n{t['text']}" for t in hits)
    return ("\n\nReference knowledge for this answer (accurate; ground your reply in it, adapt to "
            "the user's exact question, and answer in the user's language):\n" + body)
