"""redblue — an autonomous red+blue ethical-hacking agent.

It reasons like an attacker (recon, enumerate, find weaknesses) and reports like a
defender (severity, evidence, concrete remediation), acting ONLY inside an authorized
scope. The brain is a capable model (Claude Opus by default) driving a tool-use loop.
"""

# Derive the version from the installed package metadata so it never drifts from pyproject again.
# Falls back to a literal only when running from a source checkout that isn't pip-installed.
try:
    from importlib.metadata import PackageNotFoundError, version as _pkg_version
    try:
        __version__ = _pkg_version("nexus-sec")
    except PackageNotFoundError:
        __version__ = "0.1.2"
except Exception:  # pragma: no cover - importlib.metadata is stdlib on 3.10+, this is belt-and-suspenders
    __version__ = "0.1.2"
