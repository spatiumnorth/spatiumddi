"""The frontend nginx listens and resolves on IPv6 where the container has it
(#2308).

``listen 80;`` alone left an IPv6-only cluster's frontend unreachable, and
``resolver … ipv6=off`` made an api Service with only AAAA records
unresolvable. But nginx refuses to start when told to listen on an IPv6
address the container lacks, so both are rendered by
``frontend/17-ipv6.envsh`` from whether the container has IPv6. The script is
run here, not read; the templates are checked for using what it renders.
"""

from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "frontend" / "17-ipv6.envsh"
_PLAIN = _REPO_ROOT / "frontend" / "default.conf.template"
_TLS = _REPO_ROOT / "charts" / "spatiumddi" / "templates" / "frontend-tls-config.yaml"

pytestmark = pytest.mark.skipif(
    not _PLAIN.exists(), reason="frontend/ not present in this checkout (dev container)"
)

_VARS = (
    "SPATIUM_LISTEN6_80",
    "SPATIUM_LISTEN6_80_DS",
    "SPATIUM_LISTEN6_443_DS",
    "SPATIUM_RESOLVER_IPV6",
)


def _render(mode: str) -> dict[str, str]:
    script = f". {_SCRIPT} && " + " && ".join(f'printf "%s=%s\\n" {v} "${v}"' for v in _VARS)
    proc = subprocess.run(
        ["sh", "-c", script],
        env={"PATH": "/usr/bin:/bin", "SPATIUM_FRONTEND_IPV6": mode},
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return dict(line.split("=", 1) for line in proc.stdout.splitlines())


def test_ipv6_on_renders_the_listeners_and_a_resolver_that_asks_for_aaaa() -> None:
    out = _render("on")
    assert out["SPATIUM_LISTEN6_80"] == "listen [::]:80;"
    assert out["SPATIUM_LISTEN6_80_DS"] == "listen [::]:80 default_server;"
    assert out["SPATIUM_LISTEN6_443_DS"] == "listen [::]:443 ssl default_server;"
    assert "ipv6=off" not in out["SPATIUM_RESOLVER_IPV6"]


def test_ipv6_off_renders_no_ipv6_listener_and_keeps_the_resolver_v4_only() -> None:
    out = _render("off")
    assert out["SPATIUM_LISTEN6_80"] == ""
    assert out["SPATIUM_LISTEN6_80_DS"] == ""
    assert out["SPATIUM_LISTEN6_443_DS"] == ""
    assert out["SPATIUM_RESOLVER_IPV6"] == "ipv6=off"


def test_auto_is_a_known_answer() -> None:
    out = _render("auto")
    assert out["SPATIUM_RESOLVER_IPV6"] in ("", "ipv6=off")
    assert (out["SPATIUM_LISTEN6_80"] != "") == (out["SPATIUM_RESOLVER_IPV6"] == "")


@pytest.mark.parametrize("path", [_PLAIN, _TLS], ids=["plain", "tls"])
def test_templates_use_the_rendered_values_not_literals(path: pathlib.Path) -> None:
    text = path.read_text()
    assert "${SPATIUM_RESOLVER_IPV6}" in text
    assert "ipv6=off" not in re.sub(r"#.*", "", text), "resolver must not hardcode ipv6=off"
    # A literal IPv6 listen would stop nginx starting in a container without IPv6.
    assert not re.search(r"^\s*listen \[::\]", text, re.M)


def test_both_templates_listen_on_ipv6_via_the_script() -> None:
    assert "${SPATIUM_LISTEN6_80}" in _PLAIN.read_text()
    tls = _TLS.read_text()
    assert "${SPATIUM_LISTEN6_80_DS}" in tls and "${SPATIUM_LISTEN6_443_DS}" in tls


def test_image_ships_the_script() -> None:
    assert "17-ipv6.envsh" in (_REPO_ROOT / "frontend" / "Dockerfile").read_text()
