"""``/health`` and ``/metrics`` are rate limited per client at the frontend (#2944).

``/health/ready`` and ``/health/platform`` are unauthenticated, reachable
through the frontend nginx, and each call runs database and Redis checks.
Since #2944 ``/health/ready`` checks the database over ONE connection of its
own, so an unthrottled flood through nginx could queue the kubelet's probe
behind it and take the pod out of the Service. Both nginx configs therefore
carry a ``limit_req_zone`` keyed on ``$binary_remote_addr`` (the address
after the real_ip module has resolved the end client behind a trusted
proxy) and a ``limit_req`` on the location that proxies ``/health``.

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


def _proxies_health(spec: str, body: str) -> bool:
    """A location that would serve ``/health/ready`` by proxying it upstream."""
    if "proxy_pass" not in body:
        return False
    if spec.startswith("~"):
        pattern = spec.split(None, 1)[1]
        return re.search(pattern, "/health/ready") is not None
    path = spec.split()[-1]
    return "/health/ready".startswith(path) and path not in ("/",)


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
def test_health_is_rate_limited_per_client(path: Path) -> None:
    text = _text(path)
    zones = dict(_ZONE_RE.findall(text))
    assert zones, f"{path.name}: no limit_req_zone keyed on $binary_remote_addr"
    health = {s: b for s, b in _locations(text).items() if _proxies_health(s, b)}
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
    for body in (b for s, b in _locations(text).items() if _proxies_health(s, b)):
        m = re.search(r"limit_req\s+zone=(\w+)\s+burst=(\d+)", body)
        assert m
        assert zones[m.group(1)] >= 5
        assert int(m.group(2)) >= 20


def test_the_two_copies_agree() -> None:
    """The ConfigMap is a hand-kept copy of the image template."""
    image = _ZONE_RE.findall(_text(IMAGE_TEMPLATE))
    appliance = _ZONE_RE.findall(_text(APPLIANCE_TEMPLATE))
    assert image == appliance


def test_the_zone_is_keyed_after_real_ip() -> None:
    """``$binary_remote_addr`` is the real_ip-resolved client; keying on
    ``$realip_remote_addr`` or a header would bucket every client behind a
    proxy together, or let a client pick its own bucket."""
    for path in NGINX_CONFIGS:
        text = _text(path)
        assert "real_ip_header X-Forwarded-For;" in text
        for line in re.findall(r"^\s*limit_req_zone\s+(\S+)", text, re.M):
            assert line == "$binary_remote_addr", (path.name, line)
