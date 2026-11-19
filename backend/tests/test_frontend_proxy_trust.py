"""The frontend nginx trusts an outer proxy's headers only from configured
peers (#1868).

Before, every ``/api/`` location set ``X-Forwarded-Proto $scheme`` and
``X-Real-IP $remote_addr``, so behind an operator's TLS-terminating proxy the
api saw ``http`` and the proxy's own address: SSO callbacks built as http://,
and one shared login-throttle bucket for the whole organisation. The fix is a
trust map plus ``real_ip_*`` driven by ``FRONTEND_TRUSTED_PROXY_CIDRS``,
rendered by ``frontend/16-trusted-proxies.envsh``. These pin the renderer (it is run, not
read) and that no ``/api`` location can bypass the map.
"""

from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "frontend" / "16-trusted-proxies.envsh"
_TEMPLATES = (
    _REPO_ROOT / "frontend" / "default.conf.template",
    _REPO_ROOT / "charts" / "spatiumddi" / "templates" / "frontend-tls-config.yaml",
)

pytestmark = pytest.mark.skipif(
    not _TEMPLATES[0].exists(), reason="frontend/ not present in this checkout (dev container)"
)


def _render(cidrs: str | None, **extra: str) -> tuple[int, str, str, str]:
    """Source the entrypoint script the way nginx's entrypoint does; return
    (rc, SPATIUM_REAL_IP_FROM, SPATIUM_TRUSTED_GEO, stderr)."""
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", **extra}
    if cidrs is not None:
        env["FRONTEND_TRUSTED_PROXY_CIDRS"] = cidrs
    proc = subprocess.run(
        [
            "sh",
            "-c",
            f'. {_SCRIPT} && printf \'%s\\0%s\' "$SPATIUM_REAL_IP_FROM" "$SPATIUM_TRUSTED_GEO"',
        ],
        env=env,
        capture_output=True,
        text=True,
    )
    real, _, geo = proc.stdout.partition("\0")
    return proc.returncode, real, geo, proc.stderr


@pytest.mark.parametrize("cidrs", [None, "", "  ", " , "])
def test_unset_or_empty_trusts_no_proxy(cidrs: str | None) -> None:
    """A direct install keeps today's behaviour: nothing a client sends in
    X-Forwarded-* is believed. Deliberately not the api's private-range
    default: a LAN client reaching this nginx directly is in those ranges."""
    rc, real, geo, _ = _render(cidrs)
    assert (rc, real, geo) == (0, "", "")


def test_the_apis_trusted_proxy_list_is_not_the_frontends() -> None:
    """The api's TRUSTED_PROXY_CIDRS names the frontend (its peer); the
    frontend's list names the operator's proxy (ITS peer). Reading the api's
    list here would make the frontend trust the whole compose / pod network,
    and on an install that had uncommented the api's private-range default,
    every private address: any LAN client reaching the frontend directly could
    then choose the address the login throttle and audit rows record."""
    rc, real, geo, _ = _render(None, TRUSTED_PROXY_CIDRS="10.0.0.0/8,172.16.0.0/12")
    assert (rc, real, geo) == (0, "", "")


def test_each_entry_becomes_one_directive_per_line() -> None:
    rc, real, geo, _ = _render("10.0.0.0/8, 192.168.1.5 ,fd00::/8")
    assert rc == 0
    assert real.split("\n")[:-1] == [
        "    set_real_ip_from 10.0.0.0/8;",
        "    set_real_ip_from 192.168.1.5;",
        "    set_real_ip_from fd00::/8;",
    ]
    assert geo.split("\n")[:-1] == ["    10.0.0.0/8 1;", "    192.168.1.5 1;", "    fd00::/8 1;"]


def test_star_trusts_every_peer_in_both_families() -> None:
    rc, real, geo, _ = _render("*")
    assert rc == 0
    assert "set_real_ip_from 0.0.0.0/0;" in real and "set_real_ip_from ::/0;" in real
    assert "0.0.0.0/0 1;" in geo and "::/0 1;" in geo


@pytest.mark.parametrize(
    "cidrs",
    [
        "10.0.0.0/8;x",
        "10.0.0.0/8, evil.example.com",
        "1.2.3.4 } server {",
        "$(id)",
        "10.0.0.0/8\nreal_ip_header X-Real-IP",
        "10.0.0.0/8\tdeny",
        "10.0.0.0/8 #",
    ],
)
def test_an_entry_that_is_not_an_address_refuses_to_start(cidrs: str) -> None:
    """The entries are written into nginx config: anything but address
    characters must fail the container, never reach the config."""
    rc, real, geo, stderr = _render(cidrs)
    assert rc != 0 and "FRONTEND_TRUSTED_PROXY_CIDRS" in stderr
    assert (real, geo) == ("", "")


@pytest.mark.parametrize("template", _TEMPLATES, ids=lambda p: p.name)
def test_no_location_overwrites_the_forwarded_scheme_with_its_own(
    template: pathlib.Path,
) -> None:
    text = template.read_text()
    values = re.findall(r"proxy_set_header\s+X-Forwarded-Proto\s+(\S+);", text)
    assert values, "template sets no X-Forwarded-Proto at all"
    assert set(values) == {"$spatium_forwarded_proto"}
    # ...and the map behind it keys on the TCP peer being a listed proxy.
    assert "geo $realip_remote_addr $spatium_proxy_trusted" in text
    assert re.search(r'"~\*\^1:https"\s+https;', text)
    assert "real_ip_header X-Forwarded-For;" in text and "real_ip_recursive on;" in text


@pytest.mark.parametrize("template", _TEMPLATES, ids=lambda p: p.name)
def test_streaming_routes_are_unbuffered_with_a_long_timeout(template: pathlib.Path) -> None:
    text = template.read_text()
    m = re.search(
        r"location ~ \^/api/v1/\(appliance/cluster/health/stream\|[^\n]*\{(.*?)\n\s*\}", text, re.S
    )
    assert m, "no location for the cluster-health / logs streams"
    body = m.group(1)
    assert "proxy_buffering       off;" in body
    assert re.search(r"proxy_read_timeout\s+3600s;", body)
    assert "appliance/containers/.+/logs/stream" in text
