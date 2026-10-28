"""``/health`` and ``/metrics`` are rate limited per client at the frontend (#2944).

``/health/ready`` and ``/health/platform`` are unauthenticated, reachable
through the frontend nginx, and each call runs database and Redis checks.
Since #2944 ``/health/ready`` checks the database over ONE connection of its
own, so an unthrottled flood through nginx could queue the kubelet's probe
behind it and take the pod out of the Service. Both nginx configs therefore
carry a ``limit_req_zone`` keyed on ``$binary_remote_addr`` (the address
after the real_ip module has resolved the end client behind a trusted
proxy) and a ``limit_req`` on the location that proxies ``/health``, except
``/health/platform``: the console's own Platform Health call has an exact
location of its own without the limit, so a browser whose allowance was spent
still renders the card (ddi-pg walk of #2947, case 5).

There are TWO hand-maintained copies of this config (the image's template
and the appliance's TLS ConfigMap); these read both. The behaviour itself
(the 22nd request in a burst answers 429, ``/nginx-health`` is unaffected, and
a trusted proxy's clients each get their own bucket) was checked against a
real nginx 1.31.8 when this landed.

    python3 -m pytest appliance/tests/test_frontend_health_rate_limit.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
IMAGE_TEMPLATE = REPO / "frontend" / "default.conf.template"
APPLIANCE_TEMPLATE = REPO / "charts" / "spatiumddi" / "templates" / "frontend-tls-config.yaml"
NGINX_CONFIGS = (IMAGE_TEMPLATE, APPLIANCE_TEMPLATE)

CONFIGS = pytest.mark.parametrize(
    "path", NGINX_CONFIGS, ids=["image-template", "appliance-tls-configmap"]
)

_ZONE_RE = re.compile(
    r"^\s*limit_req_zone\s+\$binary_remote_addr\s+zone=(\w+):\d+[km]\s+rate=(\d+)r/s;",
    re.M,
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _locations(text: str) -> dict[str, str]:
    """``location <spec> { ... }`` blocks, brace-matched."""
    out: dict[str, str] = {}
    for m in re.finditer(r"^\s*location\s+(\S+(?:\s+\S+)?)\s*\{", text, re.M):
        spec = m.group(1).strip()
        depth, i = 1, m.end()
        while depth and i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        out[spec] = text[m.end() : i - 1]
    return out


LIMITED = ("/health/ready", "/health/live", "/health/startup", "/metrics")
EXEMPT = "/health/platform"


def _serving(locs: dict[str, str], uri: str) -> tuple[str, str]:
    """The location nginx picks for ``uri``: an exact (``=``) match wins, then
    the longest ``^~`` prefix, then the first matching regex in file order,
    then the longest plain prefix."""
    exact = [(s, b) for s, b in locs.items() if s.startswith("= ") and s[2:].strip() == uri]
    if exact:
        return exact[0]
    prefixes = []
    for s, b in locs.items():
        parts = s.split()
        if parts[0] in ("~", "~*", "=") or parts[0].startswith("@"):
            continue
        path = parts[-1]
        if uri.startswith(path):
            prefixes.append((len(path), parts[0] == "^~", s, b))
    longest = max(prefixes, default=None)
    if longest and longest[1]:
        return longest[2], longest[3]
    for s, b in locs.items():  # dicts keep file order
        parts = s.split(None, 1)
        if parts[0] in ("~", "~*"):
            flags = re.I if parts[0] == "~*" else 0
            if re.search(parts[1], uri, flags):
                return s, b
    assert longest, uri
    return longest[2], longest[3]


def _limited(body: str) -> bool:
    return re.search(r"^\s*limit_req\s+zone=", body, re.M) is not None


def _proxies_health(spec: str, body: str) -> bool:
    """A location that proxies any ``/health`` or ``/metrics`` path upstream."""
    if "proxy_pass" not in body:
        return False
    if spec.startswith("~"):
        pattern = spec.split(None, 1)[1]
        return any(re.search(pattern, u) for u in (*LIMITED, EXEMPT))
    path = spec.split()[-1]
    return path != "/" and any(u.startswith(path) for u in (*LIMITED, EXEMPT))


def test_every_nginx_config_that_proxies_health_is_covered() -> None:
    """A third nginx config proxying /health must be added here, not skipped."""
    found = set()
    for path in (REPO / "frontend").glob("*.template"):
        found.add(path)
    for path in (REPO / "charts").rglob("*.yaml"):
        if "proxy_pass" in _text(path) and re.search(r"location\s+\S*.*health", _text(path)):
            found.add(path)
    for path in (REPO / "k8s").rglob("*.yaml"):
        if "proxy_pass" in _text(path):
            found.add(path)
    assert found <= set(NGINX_CONFIGS), sorted(str(p) for p in found - set(NGINX_CONFIGS))


@CONFIGS
@pytest.mark.parametrize("uri", LIMITED)
def test_probe_paths_are_rate_limited(path: Path, uri: str) -> None:
    spec, body = _serving(_locations(_text(path)), uri)
    assert "proxy_pass" in body, (path.name, uri, spec)
    assert _limited(body), f"{path.name}: {uri} is served by {spec} without limit_req"


@CONFIGS
def test_the_consoles_platform_health_is_not_limited(path: Path) -> None:
    """The Dashboard's Platform Health card reads /health/platform through
    this nginx; a browser whose allowance another tab or a script spent must
    still get it (ddi-pg walk of #2947, case 5)."""
    spec, body = _serving(_locations(_text(path)), EXEMPT)
    assert spec == f"= {EXEMPT}", (path.name, spec)
    assert "proxy_pass" in body
    assert not _limited(body), f"{path.name}: {EXEMPT} is rate limited"


@CONFIGS
def test_health_is_rate_limited_per_client(path: Path) -> None:
    text = _text(path)
    zones = dict(_ZONE_RE.findall(text))
    assert zones, f"{path.name}: no limit_req_zone keyed on $binary_remote_addr"
    health = {
        s: b for s, b in _locations(text).items() if _proxies_health(s, b) and s != f"= {EXEMPT}"
    }
    assert health, f"{path.name}: no location proxies /health"
    for spec, body in health.items():
        m = re.search(r"^\s*limit_req\s+zone=(\w+)\s+burst=(\d+)(\s+nodelay)?;", body, re.M)
        assert m, f"{path.name}: location {spec} proxies /health without limit_req"
        assert m.group(1) in zones, f"{path.name}: {spec} names an undeclared zone"
        assert re.search(r"^\s*limit_req_status\s+429;", body, re.M), (
            f"{path.name}: {spec} must answer 429, not nginx's default 503 -- a 503 "
            "reads as 'the api is down' to every monitor polling it"
        )


@CONFIGS
def test_the_limit_leaves_room_for_monitoring(path: Path) -> None:
    """A monitor polling every few seconds, and the dashboard's 30 s poll from
    every browser behind one NAT, must never trip it."""
    text = _text(path)
    zones = {name: int(rate) for name, rate in _ZONE_RE.findall(text)}
    for body in (b for s, b in _locations(text).items() if _proxies_health(s, b) and _limited(b)):
        m = re.search(r"limit_req\s+zone=(\w+)\s+burst=(\d+)", body)
        assert m
        assert zones[m.group(1)] >= 5
        assert int(m.group(2)) >= 20


def test_the_two_copies_agree() -> None:
    """The ConfigMap is a hand-kept copy of the image template: same zone, and
    the same verdict for every health path."""
    image = _ZONE_RE.findall(_text(IMAGE_TEMPLATE))
    appliance = _ZONE_RE.findall(_text(APPLIANCE_TEMPLATE))
    assert image and image == appliance

    def verdicts(path: Path) -> dict[str, tuple[str, bool, str | None]]:
        locs = _locations(_text(path))
        out = {}
        for uri in (*LIMITED, EXEMPT):
            spec, body = _serving(locs, uri)
            m = re.search(r"limit_req\s+zone=\w+\s+burst=\d+(?:\s+nodelay)?;", body)
            out[uri] = (spec, _limited(body), m.group(0) if m else None)
        return out

    assert verdicts(IMAGE_TEMPLATE) == verdicts(APPLIANCE_TEMPLATE)


def test_the_zone_is_keyed_after_real_ip() -> None:
    """``$binary_remote_addr`` is the real_ip-resolved client; keying on
    ``$realip_remote_addr`` or a header would bucket every client behind a
    proxy together, or let a client pick its own bucket."""
    for path in NGINX_CONFIGS:
        text = _text(path)
        assert "real_ip_header X-Forwarded-For;" in text
        for line in re.findall(r"^\s*limit_req_zone\s+(\S+)", text, re.M):
            assert line == "$binary_remote_addr", (path.name, line)
