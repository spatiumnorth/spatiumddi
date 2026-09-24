"""Both web tiers send the #400 security headers, on every location (#1157).

#400 gave the image's nginx template (``frontend/default.conf.template``) a
Content-Security-Policy, X-Frame-Options, X-Content-Type-Options and a
Referrer-Policy, and left HSTS to "the appliance HTTPS server block". That
block is ``charts/spatiumddi/templates/frontend-tls-config.yaml``, which the
appliance switches on (``frontend.tls.enabled``). #400 never touched it: its
edits went to the pre-k3s appliance config, which #194 had already orphaned
and #768 deleted. So the appliance, the deployment most exposed to a real
network, served the console with none of those headers.

nginx makes the next regression easy, and a request to ``/`` will not show
it: ``add_header`` does not inherit into a location that declares an
``add_header`` of its own. These guards read both configs (no nginx needed)
and fail when:

- either server block stops sending the set;
- a location with its own ``add_header`` drops it;
- the two tiers' policies drift apart;
- the API docs' assets stop reaching the api.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_frontend_security_headers.py -v

No appliance, no nginx, no cluster — this reads the two config files.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
IMAGE_TEMPLATE = REPO / "frontend" / "default.conf.template"
APPLIANCE_TEMPLATE = (
    REPO / "charts" / "spatiumddi" / "templates" / "frontend-tls-config.yaml"
)

CONFIGS = pytest.mark.parametrize(
    "path",
    [IMAGE_TEMPLATE, APPLIANCE_TEMPLATE],
    ids=["image-template", "appliance-tls-configmap"],
)

# What every HTML-capable response must carry, with the values #400 chose.
SECURITY_SET = {
    "content-security-policy": "$spatium_csp",
    "x-frame-options": '"DENY"',
    "x-content-type-options": '"nosniff"',
    "referrer-policy": '"no-referrer"',
}
HSTS = ("strict-transport-security", '"max-age=31536000"')


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _blocks(text: str, head: str) -> list[tuple[str, str]]:
    """Every ``<head …> { body }`` in ``text`` whose head matches the regex
    ``head``, as (head line, body), with braces balanced so a nested ``if``
    block stays inside its location."""
    out = []
    for match in re.finditer(rf"^[ \t]*({head})[^{{;\n]*\{{", text, re.MULTILINE):
        depth, i = 1, match.end()
        while depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        out.append(
            (match.group(0).strip().rstrip("{").strip(), text[match.end() : i - 1])
        )
    return out


def _flat(body: str) -> str:
    """``body`` without its nested blocks — the directives at this level."""
    while True:
        stripped = re.sub(r"\{[^{}]*\}", "", body)
        if stripped == body:
            return body
        body = stripped


def _headers(body: str) -> dict[str, str]:
    return {
        name.lower(): value.removesuffix(" always").strip()
        for name, value in re.findall(
            r"^\s*add_header\s+(\S+)\s+(.+?);\s*$", _flat(body), re.MULTILINE
        )
    }


def _https_server(path: Path) -> str:
    """The server block that serves the console: the image's only block, or
    the appliance ConfigMap's :443 block (its :80 block just redirects)."""
    servers = [body for _, body in _blocks(_text(path), r"server")]
    if path == APPLIANCE_TEMPLATE:
        servers = [body for body in servers if re.search(r"listen\s+443\s+ssl", body)]
    assert (
        len(servers) == 1
    ), f"{path.name}: expected one console server block, got {len(servers)}"
    return servers[0]


def _policy(path: Path, var: str = "spatium_csp") -> str:
    match = re.search(rf'set \${var} "([^"]+)";', _text(path))
    assert match, f"{path.name}: no `set ${var}` policy"
    return match.group(1)


def _directives(policy: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in policy.split(";"):
        tokens = part.split()
        if tokens:
            out.setdefault(tokens[0].lower(), tokens[1:])
    return out


def _wanted(path: Path) -> dict[str, str]:
    wanted = dict(SECURITY_SET)
    if path == APPLIANCE_TEMPLATE:
        wanted[HSTS[0]] = HSTS[1]
    return wanted


@CONFIGS
def test_console_server_sends_the_security_set(path: Path) -> None:
    """The server-level headers cover the SPA, its index and every proxied
    location that declares no add_header of its own."""
    sent = _headers(_https_server(path))
    for name, value in _wanted(path).items():
        assert sent.get(name) == value, (
            f"{path.name}: the console's server block sends {name}={sent.get(name)!r}, "
            f"want {value} — the #400 set (spatiumddi#1157)"
        )


@pytest.mark.parametrize("var", ["spatium_csp", "spatium_redoc_csp"])
def test_both_tiers_enforce_the_same_policy(var: str) -> None:
    """Same SPA bytes, same policy: an appliance-only relaxation, or a
    tightening only compose sees, is how the two drifted the first time."""
    assert _policy(IMAGE_TEMPLATE, var) == _policy(APPLIANCE_TEMPLATE, var)


@CONFIGS
def test_redoc_page_policy_grants_only_what_redoc_needs(path: Path) -> None:
    """``/api/redoc`` runs under the console's policy plus exactly two
    grants, measured in a browser (#1157). ``worker-src blob:`` is for
    ReDoc's search index. ``img-src https://cdn.redoc.ly`` is for its footer
    logo, which ReDoc hides when the load fails, so an air-gapped install
    loses only the logo. Scripts stay ``'self'``, and the grant must not
    spread to any other page."""
    console = _directives(_policy(path))
    redoc = _directives(_policy(path, "spatium_redoc_csp"))
    assert redoc.pop("img-src") == console.pop("img-src") + ["https://cdn.redoc.ly"]
    assert redoc.pop("worker-src") == ["blob:"]
    assert "worker-src" not in console
    assert (
        redoc == console
    ), "the ReDoc policy differs from the console's beyond its two grants"
    pages = [
        (head, body)
        for head, body in _blocks(_https_server(path), r"location")
        if "$spatium_redoc_csp" in body
    ]
    assert [head for head, _ in pages] == ["location = /api/redoc"], pages
    assert re.search(r"proxy_pass\s+\$api_upstream;", pages[0][1])


@CONFIGS
def test_policy_keeps_scripts_to_the_console_origin(path: Path) -> None:
    """The API docs are fixed by serving their assets, not by opening the
    policy: no inline script, no eval, no other origin, and no framing."""
    directives = _directives(_policy(path))
    assert directives.get("script-src") == ["'self'"], directives.get("script-src")
    assert directives.get("default-src") == ["'self'"], directives.get("default-src")
    assert directives.get("frame-ancestors") == ["'none'"], directives.get(
        "frame-ancestors"
    )


def _every_add_header(text: str) -> list[tuple[str, str]]:
    """Every ``add_header`` in ``text``, at any level, as (name, value)."""
    return [
        (name.lower(), value.removesuffix(" always").strip())
        for name, value in re.findall(
            r"^\s*add_header\s+(\S+)\s+(.+?);\s*$", text, re.MULTILINE
        )
    ]


def test_hsts_only_where_tls_terminates() -> None:
    """The appliance's :443 block sends HSTS as #400 set it: one year, with
    no ``includeSubDomains`` (the appliance serves no subdomains of its
    hostname) and no ``preload``. Plain HTTP must not send it (RFC 6797
    §7.2): not the appliance's :80 redirect, and not the image's block, which
    leaves TLS to whatever fronts it."""
    tls = _headers(_https_server(APPLIANCE_TEMPLATE))
    assert tls.get(HSTS[0]) == HSTS[1], tls.get(HSTS[0])
    for name, value in _every_add_header(_text(APPLIANCE_TEMPLATE)):
        if name == HSTS[0]:
            assert (
                value == HSTS[1]
            ), f"every HSTS header must read {HSTS[1]}, got {value}"
    plain = [
        body
        for _, body in _blocks(_text(APPLIANCE_TEMPLATE), r"server")
        if not re.search(r"listen\s+443\s+ssl", body)
    ]
    assert len(plain) == 1, "expected the appliance ConfigMap's :80 redirect block"
    assert all(name != HSTS[0] for name, _ in _every_add_header(plain[0]))
    assert all(
        name != HSTS[0] for name, _ in _every_add_header(_text(IMAGE_TEMPLATE))
    ), "the plain-HTTP image template must not send Strict-Transport-Security"


@CONFIGS
def test_locations_with_their_own_headers_re_emit_the_set(path: Path) -> None:
    """``add_header`` in a location REPLACES the server-level set there.
    Every location that declares one must re-emit the set, or its responses
    go out bare. A JSON-only location (``default_type application/json``)
    carries nosniff (and HSTS on TLS), matching the image template's
    @api_unavailable."""
    wanted = _wanted(path)
    checked = 0
    for head, body in _blocks(_https_server(path), r"location"):
        sent = _headers(body)
        if not sent:
            continue  # inherits the server-level set
        checked += 1
        json_only = re.search(r"default_type\s+application/json;", _flat(body))
        need = (
            {
                k: v
                for k, v in wanted.items()
                if k in ("x-content-type-options", HSTS[0])
            }
            if json_only
            else dict(wanted)
        )
        if head == "location = /api/redoc":  # its own policy, pinned above
            need["content-security-policy"] = "$spatium_redoc_csp"
        for name, value in need.items():
            assert sent.get(name) == value, (
                f"{path.name}: `{head}` declares its own add_header, so it must re-emit "
                f"{name}: {value} (found {sent.get(name)!r})"
            )
    assert (
        checked >= 4
    ), f"{path.name}: only {checked} locations with add_header — did the shape change?"


@CONFIGS
def test_api_docs_assets_reach_the_api(path: Path) -> None:
    """/api/docs and /api/redoc load their bundles from /api/docs/static/,
    which the api serves (#1157). The static-asset regex location would
    answer those ``.js`` / ``.css`` paths from the SPA's own disk (404) unless
    a ``^~`` prefix location claims them first."""
    server = _https_server(path)
    assert re.search(
        r"location\s+~\*\s+\\\.\(js\|css", server
    ), "static-asset regex location moved?"
    blocks = [
        body
        for head, body in _blocks(server, r"location")
        if head == "location ^~ /api/docs/static/"
    ]
    assert (
        len(blocks) == 1
    ), f"{path.name}: want one `location ^~ /api/docs/static/`, got {len(blocks)}"
    assert re.search(r"proxy_pass\s+\$api_upstream;", blocks[0]), blocks[0]
