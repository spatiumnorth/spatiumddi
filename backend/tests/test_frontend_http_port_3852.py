"""The frontend nginx listens on a configurable port (#3852).

OpenShift runs the pod as a random unprivileged uid, which cannot bind :80, so
the chart sets ``FRONTEND_HTTP_PORT=8080`` there. The default MUST stay 80 or
Docker Compose and the appliance (hostNetwork :80) change under their feet.
The renderer scripts are run here and the template is substituted the way the
nginx image's envsubst step does; nothing is inferred from the text.
"""

from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_PORT = _REPO_ROOT / "frontend" / "14-http-port.envsh"
_IPV6 = _REPO_ROOT / "frontend" / "17-ipv6.envsh"
_TEMPLATE = _REPO_ROOT / "frontend" / "default.conf.template"
_DOCKERFILE = _REPO_ROOT / "frontend" / "Dockerfile"

pytestmark = pytest.mark.skipif(
    not _TEMPLATE.exists(), reason="frontend/ not present in this checkout (dev container)"
)


def _listen_lines(port: str | None) -> list[str]:
    """Source both scripts in entrypoint order, then substitute the template."""
    script = (
        f". {_PORT} && SPATIUM_FRONTEND_IPV6=on . {_IPV6} && "
        'printf "%s\\n%s\\n" "$SPATIUM_HTTP_PORT" "$SPATIUM_LISTEN6_80"'
    )
    env = {"PATH": "/usr/bin:/bin"}
    if port is not None:
        env["FRONTEND_HTTP_PORT"] = port
    proc = subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    http_port, listen6 = proc.stdout.splitlines()
    rendered = _TEMPLATE.read_text()
    rendered = rendered.replace("${SPATIUM_HTTP_PORT}", http_port)
    rendered = rendered.replace("${SPATIUM_LISTEN6_80}", listen6)
    return re.findall(r"^\s*listen\s[^;]+;", rendered, flags=re.M)


def test_the_default_is_still_port_80() -> None:
    assert [line.strip() for line in _listen_lines(None)] == ["listen 80;", "listen [::]:80;"]


def test_an_unprivileged_port_reaches_both_listeners() -> None:
    assert [line.strip() for line in _listen_lines("8080")] == [
        "listen 8080;",
        "listen [::]:8080;",
    ]


@pytest.mark.parametrize("bad", ["abc", "80; evil", "0", "70000", "-1"])
def test_anything_but_a_port_number_stops_the_container(bad: str) -> None:
    proc = subprocess.run(
        ["sh", "-c", f". {_PORT}"],
        env={"PATH": "/usr/bin:/bin", "FRONTEND_HTTP_PORT": bad},
        capture_output=True,
        text=True,
    )
    assert proc.returncode != 0
    assert "FRONTEND_HTTP_PORT" in proc.stderr


def test_the_script_ships_in_the_image_and_is_executable() -> None:
    # nginx's entrypoint sources only EXECUTABLE .envsh files and ignores the
    # rest with a log line, so a mode 644 here silently renders a literal
    # ``${SPATIUM_HTTP_PORT}`` into the config.
    assert "14-http-port.envsh" in _DOCKERFILE.read_text()
    assert _PORT.stat().st_mode & 0o111
