"""A HELD POST with no ready api must get a retryable answer (#3679).

The server-level ``error_page 502 504 @starting`` redirects the request to a
static file, and nginx answers a POST to a static file with its HTML
"405 Not Allowed". A PBX asking where a phone is therefore got a status it
cannot retry on and a body it cannot parse. ``/held`` now carries its own
``error_page 502 504 =503 @held_unavailable``: 503, ``Retry-After`` and an
RFC 5985 ``generalLisError`` document. ``/.well-known/acme-challenge/`` gets
the JSON ``@api_unavailable``. Both nginx configs are checked, and when docker
and the pinned nginx image are present (offline, ``--network none``) the image
template is run against a dead upstream, and against a live one to pin that the
api's own HELD errors (429 / 500 / 502 / 504) pass through unchanged.

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
    m = re.search(re.escape(header) + r"\s*\{(.*?)\n\s*\}", text, re.DOTALL)
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
    for m in re.finditer(r"location\s+([^{]+?)\s*\{(.*?)\n\s*\}", text, re.DOTALL):
        name, body = m.group(1), m.group(2)
        if "proxy_pass" not in body or any(e in name for e in exempt):
            continue
        assert re.search(
            r"error_page\s+502\s+504\s+(=503\s+)?@(api|held)_unavailable;", body
        ), f"{path.name}: `location {name}` proxies to the api with no @…_unavailable answer"


def _run_nginx(probe: str, setup: str = "") -> str:
    """Run ``setup``, start nginx, run ``probe``; return stdout.

    Uses the pinned nginx image, offline on purpose (``--network none``): it
    already carries curl, so nothing is installed at run time. Skips when
    docker or the image is absent, which is the case on CI's hermetic
    appliance job.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    have = subprocess.run(
        ["docker", "image", "inspect", NGINX_IMAGE], capture_output=True, check=False
    )
    if have.returncode != 0:
        pytest.skip(f"{NGINX_IMAGE} not present locally")
    prologue = r"""
export API_UPSTREAM_HOST=127.0.0.1 API_UPSTREAM_PORT=9 NGINX_LOCAL_RESOLVERS=127.0.0.1 \
  SPATIUM_TRUSTED_GEO= SPATIUM_LISTEN6_80= SPATIUM_REAL_IP_FROM= SPATIUM_RESOLVER_IPV6=
envsubst '${API_UPSTREAM_HOST} ${API_UPSTREAM_PORT} ${NGINX_LOCAL_RESOLVERS} ${SPATIUM_TRUSTED_GEO} ${SPATIUM_LISTEN6_80} ${SPATIUM_REAL_IP_FROM} ${SPATIUM_RESOLVER_IPV6}' \
  < /t/default.conf.template > /etc/nginx/conf.d/default.conf
"""
    start = r"""
nginx -t >/dev/null 2>&1 || { echo NGINX-T-FAILED; exit 0; }
nginx 2>/dev/null
sleep 1
"""
    out = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-u",
            "0",
            "-v",
            f"{IMAGE_TEMPLATE.parent}:/t:ro",
            "--entrypoint",
            "sh",
            NGINX_IMAGE,
            "-c",
            prologue + setup + start + probe,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    ).stdout
    assert "NGINX-T-FAILED" not in out, out
    return out


def _responses(out: str) -> dict[str, str]:
    """Split ``== <label>`` sections of curl -si output (nginx access-log
    lines go to the same stdout, so read the status line with ``_status``)."""
    parts = re.split(r"^== (\S+)$", out, flags=re.MULTILINE)
    return {parts[i]: parts[i + 1] for i in range(1, len(parts) - 1, 2)}


def _status(section: str) -> int | None:
    m = re.search(r"^HTTP/1\.1 (\d{3}) ", section, re.MULTILINE)
    return int(m.group(1)) if m else None


def test_held_post_against_dead_upstream_is_503_xml() -> None:
    # Nothing listens on :9, so the proxy gets connection refused -> 502,
    # which is what an api Service with no ready endpoint gives nginx.
    out = _run_nginx(r"""
for p in /held /held/self; do
  echo "== $p"
  curl -si -H 'Content-Type: application/held+xml' -d '<locationRequest/>' http://127.0.0.1$p
  echo
done
echo "== acme"
curl -si http://127.0.0.1/.well-known/acme-challenge/tok
""")
    got = _responses(out)
    for p in ("/held", "/held/self"):
        r = got.get(p, "")
        assert _status(r) == 503, out
        assert re.search(r"^Retry-After: 2\r?$", r, re.MULTILINE), out
        assert re.search(r"^Content-Type: application/held\+xml\r?$", r, re.MULTILINE), out
        assert 'xmlns="urn:ietf:params:xml:ns:geopriv:held"' in r, out
        assert 'code="generalLisError"' in r, out
    acme = got.get("acme", "")
    assert _status(acme) == 502, out
    assert re.search(r"^Content-Type: application/json\r?$", acme, re.MULTILINE), out


def test_api_own_held_errors_pass_through_unchanged() -> None:
    # The api's own 429 / 500 / 502 / 504 HELD answers must reach the client
    # as sent: error_page only fires for errors nginx generates itself (no
    # proxy_intercept_errors), and this pins that.
    upstream = r"""
cat > /etc/nginx/conf.d/upstream.conf <<'X'
server {
  listen 9;
  default_type application/held+xml;
  location = /held { return 429 'API-OWN-429'; }
  location = /held/self { return 500 'API-OWN-500'; }
  location = /held/a { return 502 'API-OWN-502'; }
  location = /held/b { return 504 'API-OWN-504'; }
  location /.well-known/acme-challenge/ { default_type text/plain; return 200 'tok.thumb'; }
}
X
"""
    out = _run_nginx(
        r"""
for p in /held /held/self /held/a /held/b; do
  echo "== $p"
  curl -si -d '<locationRequest/>' http://127.0.0.1$p
  echo
done
echo "== acme"
curl -si http://127.0.0.1/.well-known/acme-challenge/tok
""",
        setup=upstream,
    )
    got = _responses(out)
    for p, status in (("/held", 429), ("/held/self", 500), ("/held/a", 502), ("/held/b", 504)):
        r = got.get(p, "")
        assert _status(r) == status, out
        assert f"API-OWN-{status}" in r, out
        assert "generalLisError" not in r, out
    acme = got.get("acme", "")
    assert _status(acme) == 200, out
    assert "tok.thumb" in acme, out
