"""license.py — offline, air-gap-friendly commercial-license verification.

Nexus is free to evaluate and (per BUSL-1.1) requires a commercial licence for production /
commercial use. A licence is a short signed token — ``{customer, tier, issued, expires}`` plus
an RSA signature. Nexus ships ONLY the public key and verifies the signature with pure-stdlib
modular exponentiation (``pow``); the private signing key lives with the vendor
(``tools/gen_license.py``). No licence server, no network — verification works fully offline.

HONEST SCOPE: this is honour-based commercial licensing for paying customers, not anti-piracy
DRM. The source is open, so a determined user can bypass any client-side check — the licence's
force is legal (BUSL) + trust, and the real moat is the trained model, updates, and support.

Nexus runs a SOFT evaluation gate (see cli._assess), not a hard lock: without a licence it still
verifies, records, and shows a clear status stamp (``Licensed to … / evaluation only``), and it
still assesses LOCAL / private / lab targets so the tool can be evaluated — but assessing an
EXTERNAL / public-internet target is a commercial use and is refused, and any report an unlicensed
build produces is watermarked ``EVALUATION — NOT A LICENSED DELIVERABLE``. This shapes the honest
buyer toward a licence without pretending to be uncrackable.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import sys
from pathlib import Path


def _ascii_only() -> bool:
    """True when stdout can't encode the glyphs the status stamp uses ('·' and '—') — e.g. Windows
    cp1251/cp866/cp1252 consoles, which turn them into '?'/mojibake. Probes BOTH glyphs: '·' alone
    is a poor test (it exists in cp1251) while '—' does not, so we test the full set."""
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "·—".encode(enc)
        return False
    except (LookupError, UnicodeEncodeError):
        return True


def _sep() -> str:
    """Status-line separator: '·' where encodable, else ASCII ' - '. Keeps the stamp clean everywhere."""
    return " - " if _ascii_only() else " · "

# Vendor public verification key (n, e). Generated with ``python tools/gen_license.py --keygen``;
# the private half lives only at ~/.nexus/nexus-signing-key.json (0600, git-ignored, never shipped).
# To rotate: re-run --keygen --force in a clean environment and replace the n below.
PUBLIC_KEY: dict = {"n": 10567203063890798061576801209922969309856103452050604492889104657657420712538006703371795099974932423565267021452029714717705509397094678309821287877102325870875604976954884195143425144137194421539615234964731606721607580759374866441963131352845331605168590281437208396381257451412551976866776927275803901440590547044078962788703382677557139291733327506091622353488077247465461976493321540454356475967700127115080647622224796324709060821177878669729497394989808637201727567970214506280055269843736936455252606247228652630261554086912633119849591931215140482841892272524603435307645981841605532096467324062644554580821, "e": 65537}

_TIERS = {"1m": "1 month", "6m": "6 months", "1y": "1 year",
          "monthly": "1 month", "pro": "Pro", "eval": "evaluation"}

# Business model: three editions, each unlocking a feature set. Editions map to how Nexus is sold
# (see the licensing plan): Community = evaluation/non-production; Pro = commercial + the tuned
# local defender model + continuous guardian; Enterprise = + whole-estate + the air-gapped bundle
# + support. A licence may also carry explicit per-feature grants (payload "features": [...]) that
# add to its edition's set. Honour-based: these describe entitlement; they are not anti-piracy DRM.
FEATURES_BY_EDITION = {
    "community": frozenset(),
    "pro": frozenset({"commercial", "defender-model", "guard"}),
    "enterprise": frozenset({"commercial", "defender-model", "guard", "estate", "airgap",
                             "support"}),
}
_EDITION_LABEL = {"community": "Community", "pro": "Pro", "enterprise": "Enterprise"}

# The one feature worth a soft notice at point of use: the tuned Nexus defender model (the moat).
FEATURE_DEFENDER_MODEL = "defender-model"


def _derive_edition(payload: dict) -> str:
    """Edition is explicit ("edition": pro|enterprise|community) or inferred from the legacy tier
    so older tokens (customer/tier/expires only) still map to a sensible edition."""
    ed = str(payload.get("edition", "")).lower()
    if ed in FEATURES_BY_EDITION:
        return ed
    tier = str(payload.get("tier", "")).lower()
    if tier in ("enterprise", "ent"):
        return "enterprise"
    if tier in ("eval", "evaluation", ""):
        return "community"
    return "pro"   # 1m / 6m / 1y / monthly / pro → a paid commercial edition


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _canonical(payload: dict) -> bytes:
    # Deterministic bytes so signer and verifier hash the exact same thing.
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash_int(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big")


def verify_token(token: str, pubkey: dict | None = None) -> dict | None:
    """Return the payload dict if the token's signature checks out against ``pubkey`` (or the
    built-in PUBLIC_KEY), else None. Pure stdlib — the check is ``pow(sig, e, n) == hash``."""
    pk = pubkey or PUBLIC_KEY
    n, e = pk.get("n") or 0, pk.get("e") or 0
    if not n or not e:
        return None  # no key configured → nothing can be trusted
    try:
        payload_b64, sig_b64 = token.strip().split(".", 1)
        payload = json.loads(_b64d(payload_b64))
        sig = int.from_bytes(_b64d(sig_b64), "big")
    except (ValueError, json.JSONDecodeError, base64.binascii.Error):
        return None
    if not isinstance(payload, dict):
        return None
    h = _hash_int(_canonical(payload)) % n
    return payload if pow(sig, e, n) == h else None


class License:
    """A verified licence. Signature is already checked; this adds date/tier semantics."""

    def __init__(self, payload: dict):
        self.customer: str = str(payload.get("customer", ""))
        self.tier: str = str(payload.get("tier", ""))
        self.issued: str = str(payload.get("issued", ""))
        self.expires: str = str(payload.get("expires", ""))
        # Business-model fields (backward-compatible: absent → derived / sensible defaults).
        self.edition: str = _derive_edition(payload)
        self.hosts: int = int(payload.get("hosts", 0) or 0)      # 0 = unspecified / site-wide
        self.seats: int = int(payload.get("seats", 0) or 0)
        self.features: list = [str(f) for f in payload.get("features", []) if f]
        # base64 content key that opens the sealed defender-model pack (nxpack). Present only on
        # tokens issued to a defender-model licensee; the key travels WITH the licence (honour-based
        # distribution gate — see nxpack.py / model_store.py).
        self.model_key: str = str(payload.get("model_key", "") or "")

    @property
    def tier_label(self) -> str:
        return _TIERS.get(self.tier, self.tier or "licence")

    @property
    def edition_label(self) -> str:
        return _EDITION_LABEL.get(self.edition, self.edition or "licence")

    @property
    def scope_label(self) -> str:
        """Human-readable seat/host scope for the status stamp."""
        if self.hosts:
            return f"{self.hosts} host" + ("s" if self.hosts != 1 else "")
        if self.seats:
            return f"{self.seats} seat" + ("s" if self.seats != 1 else "")
        return "site-wide" if self.edition == "enterprise" else "unmetered"

    def grants(self, feature: str) -> bool:
        """Does this (valid-or-not) licence's edition + explicit grants include `feature`?"""
        return feature in self.features or feature in FEATURES_BY_EDITION.get(self.edition, frozenset())

    @property
    def expired(self) -> bool:
        try:
            return datetime.date.fromisoformat(self.expires) < datetime.date.today()
        except ValueError:
            return True  # unparseable expiry → treat as expired (fail safe)

    @property
    def valid(self) -> bool:
        return not self.expired

    @property
    def days_left(self) -> int:
        try:
            return (datetime.date.fromisoformat(self.expires) - datetime.date.today()).days
        except ValueError:
            return 0


def license_path() -> Path:
    return Path.home() / ".nexus" / "license.key"


def load_license(pubkey: dict | None = None) -> License | None:
    """Load a licence from $NEXUS_LICENSE or ~/.nexus/license.key and verify it. Returns a
    License on a good signature (even if expired — the caller decides), else None."""
    token = os.environ.get("NEXUS_LICENSE")
    if not token:
        try:
            token = license_path().read_text(encoding="utf-8").strip()
        except OSError:
            return None
    payload = verify_token(token, pubkey)
    return License(payload) if payload else None


def save_license(token: str, pubkey: dict | None = None) -> tuple[bool, str]:
    """Verify then persist a licence token to ~/.nexus/license.key (0600). Returns (ok, msg)."""
    lic = verify_token(token, pubkey)
    if lic is None:
        return False, "invalid or unsigned licence token — check you pasted it in full."
    p = license_path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(p.parent, 0o700)
        except OSError:
            pass
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token.strip() + "\n")
    except OSError as e:
        return False, f"could not write {p}: {e}"
    lo = License(lic)
    when = "expired" if lo.expired else f"valid, expires {lo.expires}"
    return True, f"licence saved for {lo.customer} [{lo.tier_label}] ({when})."


def status_line(pubkey: dict | None = None) -> str:
    """One-line human status for the startup stamp."""
    lic = load_license(pubkey)
    sep = _sep()
    if lic and lic.valid:
        tail = f"{sep}{lic.days_left}d left" if lic.days_left <= 14 else ""
        return (f"Licensed to {lic.customer}{sep}{lic.edition_label}{sep}{lic.scope_label} "
                f"(expires {lic.expires}){tail}{sep}commercial use authorized")
    dash = "—" if sep == " · " else "-"
    if lic and lic.expired:
        return (f"Licence EXPIRED ({lic.expires}) {dash} evaluation / non-production use only. "
                "Renew to keep commercial rights.")
    return f"Unlicensed {dash} evaluation / non-production use only (see LICENSE / --license)"


def is_commercial_authorized(pubkey: dict | None = None) -> bool:
    lic = load_license(pubkey)
    return bool(lic and lic.valid)


# ---- entitlements (honour-based: describe what a licence grants; never anti-piracy DRM) ------

def edition(pubkey: dict | None = None) -> str:
    """Current effective edition: the licence's edition if valid, else 'community'."""
    lic = load_license(pubkey)
    return lic.edition if (lic and lic.valid) else "community"


def allows(feature: str, pubkey: dict | None = None) -> bool:
    """Is `feature` entitled under the current valid licence (by edition or explicit grant)?"""
    lic = load_license(pubkey)
    return bool(lic and lic.valid and lic.grants(feature))


def hosts_allowed(pubkey: dict | None = None) -> int:
    """Contractual host count the current licence covers (0 = unspecified / site-wide)."""
    lic = load_license(pubkey)
    return lic.hosts if (lic and lic.valid) else 0


def defender_notice(pubkey: dict | None = None) -> str | None:
    """A one-line, honour-based notice shown when the tuned local defender model is used without an
    entitlement to it. Returns None when entitled (so callers stay quiet). The module's ethos holds:
    Nexus does not DISABLE the model, it states the licence position — the real gate is that the
    tuned weights are only distributed to licensees, plus the legal BUSL terms."""
    if allows(FEATURE_DEFENDER_MODEL, pubkey):
        return None
    return ("notice: the tuned Nexus defender model is a Pro/Enterprise feature — unlicensed use is "
            "evaluation / non-production only. Activate with `nexus license add <token>`.")
