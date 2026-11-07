"""A HELD POST with no ready api must get a retryable answer (#3679).

The server-level ``error_page 502 504 @starting`` redirects the request to a
static file, and nginx answers a POST to a static file with its HTML
"405 Not Allowed". A PBX asking where a phone is therefore got a status it
cannot retry on and a body it cannot parse. ``/held`` now carries its own
``error_page 502 504 =503 @held_unavailable``: 503, ``Retry-After`` and an
RFC 5985 ``generalLisError`` document. ``/.well-known/acme-challenge/`` gets
the JSON ``@api_unavailable``. Both nginx configs are checked, and the image
template is also run against a dead upstream when docker is available.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_frontend_held_unavailable_3679.py -v
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
IMAGE_TEMPLATE = REPO / "frontend" / "default.conf.template"
APPLIANCE_TEMPLATE = REPO / "charts" / "spatiumddi" / "templates" / "frontend-tls-config.yaml"
NGINX_IMAGE = "nginx:1.31.8-alpine"

CONFIGS = pytest.mark.parametrize(
    "path", [IMAGE_TEMPLATE, APPLIANCE_TEMPLATE], ids=["image-template", "appliance-tls-configmap"]
)


def _block(text: str, header: str) -> str:
    m = re.search(re.escape(header) + r"\s*\{(.*?)\n\s*\}", text, re.S)
    assert m, f"no `{header} {{ … }}` block"
    return m.group(1)


@CONFIGS
def test_held_location_has_its_own_unavailable_answer(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert re.search(
        r"error_page\s+502\s+504\s+=503\s+@held_unavailable;", _block(text, "location /held")
    )
    named = _block(text, "location @held_unavailable")
    assert "application/held+xml" in named
    assert re.search(r"add_header\s+Retry-After\s+\d+\s+always;", named)
    assert "return 503 " in named
    assert 'xmlns="urn:ietf:params:xml:ns:geopriv:held"' in named
    assert 'code="generalLisError"' in named


@CONFIGS
def test_acme_challenge_answers_json_when_api_is_down(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    block = _block(text, "location /.well-known/acme-challenge/")
    assert "error_page 502 504 @api_unavailable;" in block


@CONFIGS
def test_every_api_proxy_location_has_an_unavailable_answer(path: Path) -> None:
    """Any non-UI location proxying to the api, bar probes, must not fall to @starting."""
    text = path.read_text(encoding="utf-8")
    exempt = ("/health", "(health|metrics)", "/_api_up", "/_about_session")
    for m in re.finditer(r"location\s+([^{]+?)\s*\{(.*?)\n\s*\}", text, re.S):
        name, body = m.group(1), m.group(2)
        if "proxy_pass" not in body or any(e in name for e in exempt):
            continue
        assert re.search(
            r"error_page\s+502\s+504\s+(=503\s+)?@(api|held)_unavailable;", body
        ), f"{path.name}: `location {name}` proxies to the api with no @…_unavailable answer"


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker not available")
def test_held_post_against_dead_upstream_is_503_xml() -> None:
    have = subprocess.run(
        ["docker", "image", "inspect", NGINX_IMAGE], capture_output=True, check=False
    )
    if have.returncode != 0:
        pytest.skip(f"{NGINX_IMAGE} not present locally")
    script = r"""
set -e
apk add -q curl >/dev/null 2>&1
export API_UPSTREAM_HOST=127.0.0.1 API_UPSTREAM_PORT=9 NGINX_LOCAL_RESOLVERS=127.0.0.1 \
  SPATIUM_TRUSTED_GEO= SPATIUM_LISTEN6_80= SPATIUM_REAL_IP_FROM= SPATIUM_RESOLVER_IPV6=
envsubst '${API_UPSTREAM_HOST} ${API_UPSTREAM_PORT} ${NGINX_LOCAL_RESOLVERS} ${SPATIUM_TRUSTED_GEO} ${SPATIUM_LISTEN6_80} ${SPATIUM_REAL_IP_FROM} ${SPATIUM_RESOLVER_IPV6}' \
  < /t/default.conf.template > /etc/nginx/conf.d/default.conf
nginx -t >/dev/null 2>&1
nginx
sleep 1
curl -si -H 'Content-Type: application/held+xml' -d '<locationRequest/>' http://127.0.0.1/held || true
"""
    out = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-u",
            "0",
            "-v",
            f"{IMAGE_TEMPLATE.parent}:/t:ro",
            "--entrypoint",
            "sh",
            NGINX_IMAGE,
            "-c",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    ).stdout
    assert " 503 " in out, out
    assert "Retry-After:" in out, out
    assert "application/held+xml" in out, out
    assert 'code="generalLisError"' in out, out
    assert "405" not in out, out
