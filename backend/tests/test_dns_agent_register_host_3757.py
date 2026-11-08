"""Chart-deployed DNS agents register a host the API pod can resolve (#3757).

The Helm chart used to give the agent only its bare pod name, stored as both
``DNSServer.name`` and ``DNSServer.host``; drift and pull-from-server then
failed with "could not resolve". Registration now takes an optional ``host``,
and a transfer whose host does not resolve falls back to ``last_seen_ip``.
"""

from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns import _axfr
from app.drivers.dns._axfr import axfr_zone_records
from app.models.dns import DNSServer
from app.services.dns import tsig as tsig_mod

from .test_axfr_vip_fallback_1470 import ZONE, _Responder

FQDN = "dns-bind9-ns1-0.dns-bind9-ns1-headless.spatium.svc.cluster.local"
URL = "/api/v1/dns/agents/register"


def _body(**extra: object) -> dict:
    return {
        "hostname": "dns-bind9-ns1-0",
        "fingerprint": "f1",
        "agent_id": "11111111-1111-1111-1111-111111111111",
        "group_name": "g3757",
        **extra,
    }


async def _register(client: AsyncClient, monkeypatch: pytest.MonkeyPatch, **extra: object):
    monkeypatch.setenv("DNS_AGENT_KEY", "k")
    return await client.post(URL, headers={"X-DNS-Agent-Key": "k"}, json=_body(**extra))


async def _server(db: AsyncSession) -> DNSServer:
    db.expire_all()
    return (
        await db.execute(select(DNSServer).where(DNSServer.name == "dns-bind9-ns1-0"))
    ).scalar_one()


@pytest.mark.asyncio
async def test_register_stores_host_and_keeps_name(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    r = await _register(client, monkeypatch, host=FQDN)
    assert r.status_code == 200, r.text
    srv = await _server(db_session)
    assert (srv.name, srv.host) == ("dns-bind9-ns1-0", FQDN)


@pytest.mark.asyncio
async def test_register_without_host_uses_hostname(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (await _register(client, monkeypatch)).status_code == 200
    assert (await _server(db_session)).host == "dns-bind9-ns1-0"


@pytest.mark.asyncio
async def test_reregister_heals_host_only_when_sent(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (await _register(client, monkeypatch)).status_code == 200
    # An older agent re-registers without a host: untouched.
    assert (await _register(client, monkeypatch)).status_code == 200
    assert (await _server(db_session)).host == "dns-bind9-ns1-0"
    # An updated agent sends one: the existing row heals.
    assert (await _register(client, monkeypatch, host=FQDN)).status_code == 200
    assert (await _server(db_session)).host == FQDN
    # ...and an old agent afterwards leaves the healed value alone.
    assert (await _register(client, monkeypatch)).status_code == 200
    assert (await _server(db_session)).host == FQDN


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        "bad host!",
        "a;b",
        "../etc",
        # Not a form of the agent's own name: an IP literal, another
        # service, a name merely starting with the same characters.
        "10.1.2.3",
        "fd00::5",
        "postgres.spatium.svc.cluster.local",
        "dns-bind9-ns1-0x.example.com",
        "dns-bind9-ns1-0.bad label.example.com",
    ],
)
async def test_register_ignores_a_host_it_will_not_store(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    # Ignored, not refused: a refused agent re-bootstraps in a loop.
    r = await _register(client, monkeypatch, host=bad)
    assert r.status_code == 200, r.text
    assert (await _server(db_session)).host == "dns-bind9-ns1-0"
    # Nor can a later registration point an existing row at it.
    assert (await _register(client, monkeypatch, host=bad)).status_code == 200
    assert (await _server(db_session)).host == "dns-bind9-ns1-0"


@pytest.mark.asyncio
async def test_reregister_keeps_an_operator_edited_host(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (await _register(client, monkeypatch)).status_code == 200
    srv = await _server(db_session)
    srv.host = "192.0.2.10"
    await db_session.commit()
    assert (await _register(client, monkeypatch, host=FQDN)).status_code == 200
    assert (await _server(db_session)).host == "192.0.2.10"


@pytest.mark.asyncio
async def test_reregister_does_not_move_host_while_pending_approval(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert (await _register(client, monkeypatch)).status_code == 200
    monkeypatch.setenv("DNS_REQUIRE_AGENT_APPROVAL", "true")
    # A different fingerprint flips the row to pending approval; the host it
    # sends must wait for the operator too.
    r = await _register(client, monkeypatch, host=FQDN, fingerprint="f2")
    assert r.status_code == 200, r.text
    srv = await _server(db_session)
    assert srv.pending_approval is True
    assert srv.host == "dns-bind9-ns1-0"


def _srv(driver: str, agent: bool, seen: str | None) -> SimpleNamespace:
    return SimpleNamespace(
        driver=driver, agent_id="a1" if agent else None, host="ns1-0", last_seen_ip=seen
    )


def test_unresolved_fallback_applies_without_a_vip() -> None:
    # No VIP: the refusal fallback stays off (a refusal is a real answer)...
    assert tsig_mod.transfer_fallback_kwargs(_srv("bind9", True, "10.42.1.7"), "") == {
        "unresolved_fallback_hosts": ["10.42.1.7"]
    }
    # ...with a VIP both apply, as before plus the resolution one.
    assert tsig_mod.transfer_fallback_kwargs(_srv("bind9", True, "10.42.1.7"), "192.0.2.53") == {
        "fallback_hosts": ["10.42.1.7"],
        "unresolved_fallback_hosts": ["10.42.1.7"],
    }
    # Never redirected: Windows, cloud, operator BIND9; or no address known.
    for s in (_srv("windows_dns", False, "10.0.0.5"), _srv("bind9", False, "10.0.0.5")):
        assert tsig_mod.transfer_fallback_kwargs(s, "192.0.2.53") == {}
    assert tsig_mod.transfer_fallback_kwargs(_srv("bind9", True, None), "") == {}


@pytest.fixture
def daemon():
    d = _Responder()
    yield d
    d.close()


@pytest.fixture(autouse=True)
def _no_such_host(monkeypatch: pytest.MonkeyPatch) -> None:
    real = socket.getaddrinfo

    def fake(host, *a, **k):  # type: ignore[no-untyped-def]
        if host == "ns1-0":
            raise socket.gaierror(-2, "Name or service not known")
        return real(host, *a, **k)

    monkeypatch.setattr(_axfr.socket, "getaddrinfo", fake)


@pytest.mark.asyncio
async def test_unresolvable_host_retried_at_last_seen_ip(daemon: _Responder) -> None:
    out = await axfr_zone_records(
        host="ns1-0",
        port=daemon.port,
        zone_name=ZONE,
        unresolved_fallback_hosts=["127.0.0.2"],
    )
    assert any(r.name == "www" for r in out)
    assert daemon.connections == 1


@pytest.mark.asyncio
async def test_unresolvable_host_without_fallback_still_errors() -> None:
    with pytest.raises(RuntimeError, match="could not resolve 'ns1-0'"):
        await axfr_zone_records(host="ns1-0", port=53, zone_name=ZONE)


@pytest.mark.asyncio
async def test_refusal_does_not_use_the_unresolved_fallback(daemon: _Responder) -> None:
    # 127.0.0.1 is up with nothing listening: a real refusal, no VIP -> no retry.
    with pytest.raises(RuntimeError):
        await axfr_zone_records(
            host="127.0.0.1",
            port=daemon.port,
            zone_name=ZONE,
            unresolved_fallback_hosts=["127.0.0.2"],
        )
    assert daemon.connections == 0
