"""#1537 — zone create/delete/move on agentless servers was not atomic
across servers, and a disabled server still got the push.

``_push_zone_to_agentless_servers`` drove every agentless-with-creds
server in the group one after another and raised a single 502 after the
loop. The DB transaction rolled back, but the changes already made on
the servers that succeeded were not undone and no op row recorded
them: a create left the zone live on server 1 while SpatiumDDI said
the create failed (and a retry then failed there with "already
exists"); a delete left the zone answering on the failed servers; a
move could leave it live in both groups. The target query also had no
``is_enabled`` filter, so a paused server still received zone writes —
and if it was unreachable it blocked every zone operation in the group,
while the record path deliberately skips disabled agentless servers.

Fixed here: disabled servers are excluded from the fan-out, and on a
partial failure the servers that succeeded receive the inverse op as
compensation (create → delete, delete → create) before the 502 is
raised, with the outcome named in the error detail. What remains
tracked in #1537: making each driver itself treat "already exists" on
create and "not found" on delete as success.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.router import _push_zone_to_agentless_servers
from app.core.crypto import encrypt_dict
from app.models.dns import DNSServer, DNSServerGroup, DNSZone


class _FakeDriver:
    """Records zone pushes; raises for servers named in ``fail_on``."""

    def __init__(self, fail_on: set[str] | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self.fail_on = fail_on or set()

    async def apply_zone_change(self, server: DNSServer, zone: DNSZone, op: str) -> None:
        self.calls.append((server.name, op))
        if server.name in self.fail_on:
            raise RuntimeError(f"{server.name} unreachable")


async def _group(db: AsyncSession) -> DNSServerGroup:
    g = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db.add(g)
    await db.flush()
    return g


async def _server(
    db: AsyncSession, group: DNSServerGroup, name: str, *, is_enabled: bool = True
) -> DNSServer:
    s = DNSServer(
        group_id=group.id,
        name=name,
        driver="route53",
        host=name,
        port=53,
        roles=["authoritative"],
        status="active",
        is_enabled=is_enabled,
        credentials_encrypted=encrypt_dict({"aws_access_key_id": "x"}),
    )
    db.add(s)
    await db.flush()
    return s


def _zone(group: DNSServerGroup) -> DNSZone:
    return DNSZone(name="example.com", group_id=group.id)


@pytest.fixture
def fake_driver(monkeypatch: pytest.MonkeyPatch) -> _FakeDriver:
    fake = _FakeDriver()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    return fake


async def test_disabled_agentless_server_gets_no_zone_push(
    db_session: AsyncSession, fake_driver: _FakeDriver
) -> None:
    grp = await _group(db_session)
    await _server(db_session, grp, "on")
    await _server(db_session, grp, "off", is_enabled=False)
    fake_driver.fail_on = {"off"}  # would 502 the whole op if it were pushed

    await _push_zone_to_agentless_servers(db_session, _zone(grp), "create")

    assert fake_driver.calls == [("on", "create")]


async def test_partial_create_failure_compensates_the_succeeded_server(
    db_session: AsyncSession, fake_driver: _FakeDriver
) -> None:
    grp = await _group(db_session)
    await _server(db_session, grp, "first")
    await _server(db_session, grp, "second")
    fake_driver.fail_on = {"second"}

    with pytest.raises(HTTPException) as excinfo:
        await _push_zone_to_agentless_servers(db_session, _zone(grp), "create")

    assert excinfo.value.status_code == 502
    # The zone created on "first" was deleted again before the raise, so
    # a retry starts clean instead of failing there with "already exists".
    assert ("first", "create") in fake_driver.calls
    assert ("first", "delete") in fake_driver.calls
    assert "Rolled back on: first" in excinfo.value.detail


async def test_partial_delete_failure_recreates_on_the_succeeded_server(
    db_session: AsyncSession, fake_driver: _FakeDriver
) -> None:
    grp = await _group(db_session)
    await _server(db_session, grp, "first")
    await _server(db_session, grp, "second")
    fake_driver.fail_on = {"second"}

    with pytest.raises(HTTPException) as excinfo:
        await _push_zone_to_agentless_servers(db_session, _zone(grp), "delete")

    assert excinfo.value.status_code == 502
    assert ("first", "delete") in fake_driver.calls
    assert ("first", "create") in fake_driver.calls


async def test_full_success_pushes_every_enabled_server_once(
    db_session: AsyncSession, fake_driver: _FakeDriver
) -> None:
    grp = await _group(db_session)
    await _server(db_session, grp, "first")
    await _server(db_session, grp, "second")

    await _push_zone_to_agentless_servers(db_session, _zone(grp), "create")

    assert sorted(fake_driver.calls) == [("first", "create"), ("second", "create")]
