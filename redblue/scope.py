"""scope.py — the authorization core. Nothing happens outside an allowed scope.

This is the line that makes the agent *ethical* rather than just capable. Every tool
that touches a target must call ``Scope.allows(target)`` first; an out-of-scope target
is a hard refuse, not a warning. The scope is an explicit allowlist provided by the
human operator at launch — never inferred, never widened by the model.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from urllib.parse import urlparse


# Defence-in-depth denylist (F4). These ranges are the high-value SSRF/pivot targets — cloud
# metadata, loopback, private/internal networks — that a scope mistake (a too-broad --scope
# CIDR, a redirect, a smuggled arg) must never reach by accident. An address in one of these
# blocks is allowed ONLY when the operator authorized it *deliberately*: a scope entry confined
# to a dangerous block (e.g. --scope 10.0.0.0/24 or an exact IP), or the --allow-dangerous
# override. A broad net that merely spans the address (e.g. 0.0.0.0/0) does NOT count.
_DANGEROUS_NETS = [ipaddress.ip_network(c) for c in (
    "0.0.0.0/8",             # "this host" / unspecified
    "10.0.0.0/8",            # RFC1918 private
    "172.16.0.0/12",         # RFC1918 private
    "192.168.0.0/16",        # RFC1918 private
    "127.0.0.0/8",           # loopback
    "169.254.0.0/16",        # link-local — includes 169.254.169.254 cloud metadata
    "100.64.0.0/10",         # CGNAT (also Alibaba 100.100.100.200 metadata)
    "::1/128",               # IPv6 loopback
    "fc00::/7",              # IPv6 unique-local (private)
    "fe80::/10",             # IPv6 link-local
)]


def _dangerous_block(ip):
    """Return the denylisted network containing ``ip``, or ``None`` if it is not dangerous."""
    for net in _DANGEROUS_NETS:
        if ip.version == net.version and ip in net:
            return net
    return None


def _within_any_dangerous(net) -> bool:
    """True if ``net`` sits ENTIRELY inside a single dangerous block — i.e. the operator
    deliberately scoped an internal range, not a broad net that merely overlaps one."""
    for d in _DANGEROUS_NETS:
        if net.version == d.version and net.subnet_of(d):
            return True
    return False


class ScopeError(Exception):
    """Raised when a target is outside the authorized scope."""


class Scope:
    """An explicit allowlist of what the agent may touch.

    Entries may be:
      * a hostname            -> matches that host and any subdomain of it
      * an IP address         -> matches exactly that address
      * a CIDR block          -> matches any address inside it

    Matching for a target resolves hostnames to IPs and checks both the name
    suffix rules and the resolved address against CIDR/IP entries, so a host
    cannot sneak out of scope by being referenced via its IP (or vice-versa).
    """

    def __init__(self, entries, allow_dangerous: bool = False, rate_limit: float = 0.0):
        self.hostnames: set[str] = set()
        self.networks: list[ipaddress._BaseNetwork] = []
        self.raw: list[str] = []
        # When True, the F4 danger denylist (metadata/loopback/RFC1918) is disabled. Off by
        # default: reaching an internal range requires the operator to opt in explicitly.
        self.allow_dangerous: bool = bool(allow_dangerous)
        # Politeness throttle: minimum seconds between outbound requests. Bug-bounty and
        # authorized-prod testing must not hammer a live target — many programs mandate a
        # rate limit, and exceeding it violates the rules (so the test is no longer
        # authorized). 0 = no throttle (the lab/loopback default). Enforced at the single
        # HTTP egress choke point so every probe, discovery hit, and fuzz request obeys it.
        self.rate_limit: float = max(0.0, float(rate_limit))
        self._last_request: float = 0.0
        # Per-run scratch: a bearer token captured by login_test so a follow-up
        # read_collection can carry it WITHOUT the (small) model having to reproduce a
        # long JWT verbatim. Cleared between assessments via reset_session().
        self.session: dict = {}
        for entry in entries:
            self.add(entry)

    def reset_session(self) -> None:
        """Drop any per-run state (e.g. a captured auth token) before a new assessment."""
        self.session = {}

    def throttle(self) -> None:
        """Block until at least ``rate_limit`` seconds have passed since the last request.

        Called at the HTTP egress choke point so the whole agent — probes, discovery, and
        the parameter fuzzer — respects one global request cadence. A no-op when
        ``rate_limit`` is 0.
        """
        if self.rate_limit <= 0:
            return
        now = time.monotonic()
        wait = self._last_request + self.rate_limit - now
        if wait > 0:
            time.sleep(wait)
            now = time.monotonic()
        self._last_request = now

    def add(self, entry: str) -> None:
        entry = (entry or "").strip()
        if not entry:
            return
        self.raw.append(entry)
        # 1) A bare IP or CIDR block (e.g. 127.0.0.1 or 10.0.0.0/24) — store as a network.
        try:
            self.networks.append(ipaddress.ip_network(entry, strict=False))
            return
        except ValueError:
            pass
        # 2) Otherwise strip any scheme / port / path down to a bare host.
        host = self._host(entry).lower()
        if not host:
            return
        # 3) That host may itself be a literal IP (e.g. the "127.0.0.1" in "127.0.0.1:8195").
        #    Store it as a /32 (or /128) network so IP-literal targets actually match — an IP
        #    target is checked against networks, never against the hostname set.
        ip = self._as_ip(host)
        if ip is not None:
            suffix = "/32" if ip.version == 4 else "/128"
            self.networks.append(ipaddress.ip_network(host + suffix, strict=False))
            return
        # 4) A real hostname — matches that host and any subdomain.
        self.hostnames.add(host)

    # ---- query -----------------------------------------------------------

    def allows(self, target: str) -> bool:
        """True if ``target`` (host, IP, or URL) falls within scope."""
        host = self._host(target)
        if not host:
            return False
        host = host.lower()

        # Direct literal-IP target: must match a network AND survive the danger denylist.
        ip = self._as_ip(host)
        if ip is not None:
            return self._ip_allowed(ip)

        # Hostname target: name-suffix match against allowed hostnames. A name the operator
        # typed is honoured as intent — the denylist does not second-guess it (so scoping an
        # internal hostname you own still works).
        if self._host_in_names(host):
            return True

        # …or resolve the name and check every address against the networks + denylist.
        if self.networks:
            for addr in self._resolve(host):
                if self._ip_allowed(addr):
                    return True
        return False

    def _ip_allowed(self, ip) -> bool:
        """True if ``ip`` matches an allowed network and is not blocked by the F4 denylist.

        A dangerous address (metadata/loopback/private) passes only when the operator
        authorized it deliberately — a matching scope entry confined to a dangerous block,
        or ``allow_dangerous`` — never merely because a broad net (0.0.0.0/0) spans it.
        """
        matched = [net for net in self.networks if ip.version == net.version and ip in net]
        if not matched:
            return False
        if self.allow_dangerous or _dangerous_block(ip) is None:
            return True
        return any(_within_any_dangerous(net) for net in matched)

    def require(self, target: str) -> None:
        """Raise :class:`ScopeError` unless ``target`` is in scope."""
        if not self.allows(target):
            raise ScopeError(
                f"target {target!r} is OUT OF SCOPE; authorized scope is: "
                + ", ".join(self.raw)
            )

    # ---- helpers ---------------------------------------------------------

    def _host_in_names(self, host: str) -> bool:
        for name in self.hostnames:
            if host == name or host.endswith("." + name):
                return True
        return False

    @staticmethod
    def _host(target: str) -> str:
        """Extract the bare host from a hostname, ``host:port`` or a URL."""
        if not target:
            return ""
        target = target.strip()
        if "://" not in target:
            # Give urlparse a scheme so it parses host:port/path consistently.
            parsed = urlparse("//" + target, scheme="")
        else:
            parsed = urlparse(target)
        host = parsed.hostname or ""
        # A fully-qualified name may carry a trailing dot (`example.com.` == `example.com`).
        # Normalise it away so a trailing-dot target matches a plain scope entry (and vice
        # versa) instead of being wrongly refused as out-of-scope. rstrip is safe: a bare
        # dot / all-dots string isn't a real host and collapses to "".
        return host.rstrip(".")

    @staticmethod
    def _as_ip(host: str):
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return None

    @staticmethod
    def _resolve(host: str):
        addrs = set()
        try:
            for family, _t, _p, _c, sockaddr in socket.getaddrinfo(host, None):
                ip = sockaddr[0]
                try:
                    addrs.add(ipaddress.ip_address(ip))
                except ValueError:
                    continue
        except (socket.gaierror, OSError):
            pass
        return addrs

    def __repr__(self) -> str:
        return f"Scope({self.raw!r})"
