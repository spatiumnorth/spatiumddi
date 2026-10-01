"""Every hostname the shipped code knows is documented in docs/PRIVACY.md (#976, #1353).

SpatiumDDI's privacy statement claims something specific and checkable:
the software makes exactly one outbound connection nobody configured (a
daily anonymous release check against GitHub), and every other host it
can reach is listed with its default and its payload. A claim like that
rots the first time somebody adds a convenience fetch — the statement
does not become vague, it becomes *false*, which is worse than never
having made it.

So this is the guard, in the shape of ``lint_untyped_routes.py`` and
``test_response_media_types.py``: scan the shipped Python for hostname
literals and require each one to appear on the page. A new outbound host
fails CI until somebody writes down what it sends and when.

**What is scanned.** ``backend/app``, and since #1353 the four agent
packages under ``agent/`` — the code in the DNS, DHCP, looking-glass and
supervisor images. #976 scanned the backend only, and the connection the
page then failed to mention lived in the agent: PowerDNS's resolver,
hardcoded to ``1.1.1.1,8.8.8.8``. That is an IP literal, which
the hostname scan cannot see, so the agent packages are also scanned for
public IP literals in string constants. Agent ``tests/`` directories are
not shipped and are not scanned, the same way ``backend/tests`` is not.

**Both lists live in PRIVACY.md, not here.** A host that is *not* a
connection — a documentation link, a homepage shown in the UI, an
``example.com`` placeholder — goes in that page's appendix rather than
into an allowlist in this file. That costs a line of prose and buys the
property that matters: filing a real endpoint under "not a connection"
is a lie a human has to type into the document readers actually read,
instead of a quiet entry in a test fixture.

**What the guard cannot see**, stated in PRIVACY.md §8 as well:

* hosts assembled at runtime from operator input (``https://{host}/…``)
  — which is the point, those are the operator's own endpoints;
* the feed catalogues under ``backend/app/data/*.json`` (blocklist
  sources, resolver presets), which are covered as a category by the
  blocklist row and are all opt-in downloads;
* IP literals in ``backend/app``: there they are overwhelmingly example
  addresses in copilot tool descriptions and multicast range bounds, so
  the IP scan is limited to the agent packages, where an address in a
  string is far more likely to be somewhere a daemon is told to send
  packets.
"""

from __future__ import annotations

import ast
import ipaddress
import pathlib
import re

import pytest

# Spelled as an explicit repo-root escape (``parents[2]``) rather than
# ``backend/``.parent, because test_ci_backend_relevant.py scans for exactly
# that spelling to prove every cross-boundary read is declared in the CI
# must-run manifest — reaching the repo root by a route its regex cannot see
# would silently drop docs/PRIVACY.md out of the gate that runs this test.
_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_BACKEND = _REPO_ROOT / "backend"
_APP = _BACKEND / "app"
_AGENT = _REPO_ROOT / "agent"
_PRIVACY = _REPO_ROOT / "docs" / "PRIVACY.md"

# The shipped agent packages. Each one is ALSO a carve-out in
# .github/scripts/ci-backend-must-run.txt — agent/ is otherwise denied by the
# CI path filter, so an agent-only PR that adds an outbound host would never
# run this test. test_every_agent_package_is_scanned fails when a new package
# appears under agent/ without being added here (and so to the manifest).
_AGENT_PACKAGES = (
    "agent/dhcp/spatium_dhcp_agent",
    "agent/dns/spatium_dns_agent",
    "agent/looking-glass/spatium_lg_agent",
    "agent/supervisor/spatium_supervisor",
)

# The dev container copies only ``backend/`` into the image, so this skips
# there and runs for real in CI, which tests from a full checkout. Same
# convention as test_spatium_console.py and test_openapi_export.py.
pytestmark = pytest.mark.skipif(
    not _PRIVACY.exists(),
    reason="docs/PRIVACY.md not present in this checkout",
)

# The character class deliberately excludes ``{`` and ``$``, so an
# interpolated ``https://{host}/api`` yields no match at all rather than a
# bogus one.
_URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+)")

# A match has to look like a real hostname before we demand it be
# documented. This drops the debris of scanning source text: ``https://...``
# in a docstring ellipsis, a bare ``https://localhost``, a loopback literal,
# and the truncated fragments left by a URL hard-wrapped across two lines.
_HOSTNAME_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")

# Candidate IP literals inside a string constant. Both are only candidates —
# ``ipaddress`` decides — so a version string or a timestamp that happens to
# match is discarded rather than reported. The IPv6 lookahead refuses a
# trailing ``.`` too: otherwise ``64:ff9b::8.8.8.8`` yields the truncated
# ``64:ff9b::8``, a global address that is not the one written (the IPv4
# pattern still reports the embedded ``8.8.8.8``).
_IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:.])([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w:.])")

# Where the CI path filter's carve-outs live (see test_every_agent_package_is_scanned).
_MUST_RUN_MANIFEST = _REPO_ROOT / ".github" / "scripts" / "ci-backend-must-run.txt"

# Directories under agent/ that hold no shipped source: the agents' own test
# suites, and the debris a local checkout grows (a ``.venv``, an editable
# install's ``*.egg-info``, ``build/``). A gitignored venv under agent/dns/
# would otherwise fail the package check with every file in site-packages.
_NOT_SHIPPED_DIRS = frozenset({"tests", "build", "dist", "site-packages", "__pycache__"})


def _is_shipped_agent_path(path: pathlib.Path) -> bool:
    parts = path.relative_to(_AGENT).parts[:-1]
    return not any(
        part in _NOT_SHIPPED_DIRS or part.startswith(".") or part.endswith(".egg-info")
        for part in parts
    )


def _documented(literal: str, privacy: str) -> bool:
    """Is this address written on the page as itself, not inside a longer one?

    A plain substring test would accept ``1.1.1.1`` because the page says
    ``11.1.1.10``, or ``2.2.2.2`` inside ``12.2.2.25`` — a guard that passes
    on a different address. A trailing sentence ``.`` is still allowed.
    """
    pattern = rf"(?<![\w.:]){re.escape(literal)}(?![\w:]|\.\w)"
    return re.search(pattern, privacy) is not None


def _scanned_files() -> list[pathlib.Path]:
    files = sorted(_APP.rglob("*.py"))
    for package in _AGENT_PACKAGES:
        files.extend(sorted((_REPO_ROOT / package).rglob("*.py")))
    return files


def _hosts_in_source() -> dict[str, set[str]]:
    """Map each hostname literal in the scanned code to the files using it."""
    found: dict[str, set[str]] = {}
    for path in _scanned_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for host in _URL_RE.findall(text):
            host = host.lower().rstrip(".")
            if not _HOSTNAME_RE.match(host):
                continue
            found.setdefault(host, set()).add(str(path.relative_to(_REPO_ROOT)))
    return found


def _docstring_nodes(tree: ast.AST) -> set[int]:
    """ids of the Constant nodes that are docstrings — prose, not values."""
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                ids.add(id(first.value))
    return ids


def _public_ips_in_agent_source() -> dict[str, set[str]]:
    """Map each public unicast IP literal in an agent string constant to its files.

    Only string *values* count: comments are not in the AST, and docstrings
    are dropped, because both are where an example address like ``1.2.3.4``
    lives. Private, loopback, link-local, documentation (RFC 5737 / 3849),
    unspecified and multicast addresses are not destinations on the public
    internet and are skipped by ``is_global`` / ``is_multicast``.
    """
    found: dict[str, set[str]] = {}
    for package in _AGENT_PACKAGES:
        for path in sorted((_REPO_ROOT / package).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            docstrings = _docstring_nodes(tree)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                    continue
                if id(node) in docstrings:
                    continue
                for candidate in _IPV4_RE.findall(node.value) + _IPV6_RE.findall(node.value):
                    try:
                        addr = ipaddress.ip_address(candidate)
                    except ValueError:
                        continue
                    if addr.is_global and not addr.is_multicast:
                        found.setdefault(str(addr), set()).add(str(path.relative_to(_REPO_ROOT)))
    return found


def test_every_agent_package_is_scanned() -> None:
    """A new Python package under agent/ has to be added to the scan.

    Otherwise the guard quietly stops covering it — and because agent/ is
    denied by the CI path filter, the manifest carve-out that makes an
    agent-only PR run this test has to grow with it.
    """
    declared = {_REPO_ROOT / p for p in _AGENT_PACKAGES}
    for package in declared:
        assert package.is_dir(), f"{package.relative_to(_REPO_ROOT)} no longer exists"
    unscanned = sorted(
        str(path.relative_to(_REPO_ROOT))
        for path in _AGENT.rglob("*.py")
        if _is_shipped_agent_path(path) and not any(package in path.parents for package in declared)
    )
    assert not unscanned, (
        f"shipped agent Python outside the scanned packages: {unscanned}. Add its "
        "package to _AGENT_PACKAGES here, AND as a carve-out in "
        ".github/scripts/ci-backend-must-run.txt (plus _KNOWN_REPO_ROOT_READS in "
        "test_ci_backend_relevant.py), or an agent-only PR never runs this guard."
    )
    # The other half of that instruction, checked rather than trusted: a
    # package scanned here but missing from the manifest is covered only on
    # PRs that happen to touch something else the gate runs on.
    carve_outs = {
        line.split("#", 1)[0].strip()
        for line in _MUST_RUN_MANIFEST.read_text(encoding="utf-8").splitlines()
    }
    missing = sorted(p for p in _AGENT_PACKAGES if f"{p}/" not in carve_outs)
    assert not missing, (
        f"scanned agent package(s) {missing} are not carve-outs in "
        f"{_MUST_RUN_MANIFEST.relative_to(_REPO_ROOT)}, so an agent-only PR "
        "touching them skips the backend suite and never runs this guard."
    )


def test_every_hostname_is_in_the_privacy_statement() -> None:
    """A hostname the shipped code knows about is either a documented
    connection or a documented non-connection. There is no third category."""
    privacy = _PRIVACY.read_text(encoding="utf-8").lower()
    undocumented = {
        host: sorted(files) for host, files in _hosts_in_source().items() if host not in privacy
    }
    assert not undocumented, (
        "hostname(s) in backend/app or the agent packages that docs/PRIVACY.md does "
        "not mention: "
        + "; ".join(f"{h} ({', '.join(f)})" for h, f in sorted(undocumented.items()))
        + ". If it is an outbound connection, add a row to the table in §3 with its "
        "default and what it sends. If it is a documentation link or a placeholder, "
        "add it to the appendix. Do not add an allowlist to this test."
    )


def test_every_public_ip_in_agent_code_is_in_the_privacy_statement() -> None:
    """The hostname scan's blind spot, closed for the agents (#1353).

    PowerDNS's ALIAS resolver is ``1.1.1.1,8.8.8.8`` — no scheme, no
    hostname, so the URL scan above never saw it, and it went undocumented
    while the page claimed every connection was listed.
    """
    privacy = _PRIVACY.read_text(encoding="utf-8").lower()
    undocumented = {
        ip: sorted(files)
        for ip, files in _public_ips_in_agent_source().items()
        if not _documented(ip.lower(), privacy)
    }
    assert not undocumented, (
        "public IP literal(s) in the agent packages that docs/PRIVACY.md does not "
        "mention: "
        + "; ".join(f"{ip} ({', '.join(f)})" for ip, f in sorted(undocumented.items()))
        + ". An address a daemon is configured to send to is an outbound "
        "connection: add a row to §3 with its default and what it sends. If it is "
        "only an example value, move it into a docstring or comment, or use an "
        "RFC 5737 / RFC 3849 documentation address."
    )


def test_exactly_one_connection_is_enabled_by_default() -> None:
    """§3.1 stays a one-row table.

    The headline sentence — "no outbound connection you did not configure,
    with one exception" — is only true while this table has one row in it,
    and the README and the Settings copy both repeat it. Per
    CLAUDE.md non-negotiable #17 a second default-on connection needs an
    issue and a decision; this makes adding one a deliberate act rather
    than a table edit nobody noticed.
    """
    text = _PRIVACY.read_text(encoding="utf-8")
    section = text.split("### 3.1 Enabled by default", 1)
    assert len(section) == 2, "PRIVACY.md lost its '### 3.1 Enabled by default' heading"
    body = section[1].split("###", 1)[0]

    rows = [
        line
        for line in body.splitlines()
        if line.startswith("|") and not re.fullmatch(r"[|\s:-]+", line)
    ]
    # Header row + the single data row.
    assert len(rows) == 2, (
        f"§3.1 has {len(rows) - 1} default-on connection(s), expected 1. Adding one "
        "is a product decision (CLAUDE.md non-negotiable #17), and the README and "
        "Settings → Application → Updates both state there is exactly one."
    )
    # Read the first cell's code span and compare it whole. A substring test
    # would also pass on a row that merely mentions the host in prose — and
    # CodeQL flags ``"api.github.com" in row`` as incomplete URL sanitization,
    # correctly in general even though nothing is being sanitized here.
    first_cell = re.match(r"\|\s*`([^`]+)`", rows[1])
    assert (
        first_cell is not None
    ), f"§3.1's data row should name its host in a code span, got: {rows[1]!r}"
    assert first_cell.group(1) == "api.github.com", (
        f"the one default-on connection should be the release check, "
        f"not {first_cell.group(1)!r}"
    )
