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
raised, with the outcome named in the error detail. The drivers then
learned to treat "already exists" on create and "not found" on delete
as success, and to say so (``apply_zone_change`` returns False), so the
compensation skips a server that was already in the requested state.
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


# ── #1613 QA: a rolled-back delete restores the zone's records ─────────────


class _RecordingDriver(_FakeDriver):
    """``_FakeDriver`` plus the record half of a driver: reads the zone back
    as empty (it was just re-created) and records every record push."""

    def __init__(self, fail_on: set[str] | None = None, record_fail_on: set[str] | None = None):
        super().__init__(fail_on)
        self.record_fail_on = record_fail_on or set()
        self.record_pushes: list[tuple[str, str, str, str]] = []

    async def pull_zone_records(
        self, server: DNSServer, zone_name: str, *, tsig=None
    ):  # noqa: ANN001, ANN201
        return []

    async def apply_record_changes(self, server: DNSServer, changes):  # noqa: ANN001, ANN201
        from app.drivers.dns.base import RecordChangeResult

        results = []
        for ch in changes:
            self.record_pushes.append((server.name, ch.op, ch.record.name, ch.record.record_type))
            if server.name in self.record_fail_on:
                results.append(RecordChangeResult(ok=False, change=ch, error="quota exceeded"))
            else:
                results.append(RecordChangeResult(ok=True, change=ch))
        return results


async def _persisted_zone_with_records(db: AsyncSession, grp: DNSServerGroup) -> DNSZone:
    from app.models.dns import DNSRecord

    zone = DNSZone(name="example.com.", group_id=grp.id)
    db.add(zone)
    await db.flush()
    db.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    db.add(DNSRecord(zone_id=zone.id, name="mail", record_type="A", value="10.0.0.2"))
    await db.flush()
    return zone


@pytest.fixture
def recording_driver(monkeypatch: pytest.MonkeyPatch) -> _RecordingDriver:
    fake = _RecordingDriver()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    return fake


async def test_rolled_back_delete_restores_the_zones_records(
    db_session: AsyncSession, recording_driver: _RecordingDriver
) -> None:
    """Re-creating the zone alone left the healthy server answering for an
    EMPTY zone until someone ran Sync with Servers, while the 502 said the
    delete had been rolled back."""
    grp = await _group(db_session)
    await _server(db_session, grp, "first")
    await _server(db_session, grp, "second")
    zone = await _persisted_zone_with_records(db_session, grp)
    recording_driver.fail_on = {"second"}

    with pytest.raises(HTTPException) as excinfo:
        await _push_zone_to_agentless_servers(db_session, zone, "delete")

    assert ("first", "create") in recording_driver.calls
    assert sorted(recording_driver.record_pushes) == [
        ("first", "create", "mail", "A"),
        ("first", "create", "www", "A"),
    ]
    assert "Rolled back on: first" in excinfo.value.detail
    assert "could not all be restored" not in excinfo.value.detail


async def test_record_restore_failure_is_reported_not_called_a_rollback(
    db_session: AsyncSession, recording_driver: _RecordingDriver
) -> None:
    grp = await _group(db_session)
    await _server(db_session, grp, "first")
    await _server(db_session, grp, "second")
    zone = await _persisted_zone_with_records(db_session, grp)
    recording_driver.fail_on = {"second"}
    recording_driver.record_fail_on = {"first"}

    with pytest.raises(HTTPException) as excinfo:
        await _push_zone_to_agentless_servers(db_session, zone, "delete")

    detail = excinfo.value.detail
    assert "Rolled back on" not in detail
    assert "Zone re-created on first" in detail
    assert "quota exceeded" in detail
    assert "Sync with Servers" in detail


async def test_failure_names_the_actual_driver_and_a_non_empty_cause(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every agentless failure used to read "on Windows DNS", and an
    exception with an empty str() (a refused httpx connection) left the
    cause blank after the server name."""

    class _Silent(_FakeDriver):
        async def apply_zone_change(self, server: DNSServer, zone: DNSZone, op: str) -> None:
            self.calls.append((server.name, op))
            raise ConnectionRefusedError()

    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: _Silent())
    grp = await _group(db_session)
    await _server(db_session, grp, "r53")

    with pytest.raises(HTTPException) as excinfo:
        await _push_zone_to_agentless_servers(db_session, _zone(grp), "create")

    detail = excinfo.value.detail
    assert "Windows DNS" not in detail
    assert "Route 53" in detail
    assert "r53: ConnectionRefusedError" in detail


# ── #1607 × #1613: a provider conflict still compensates ───────────────────


class _ConflictDriver(_FakeDriver):
    """Raises ``CloudDNSConflictError`` for servers in ``conflict_on`` — the
    #1607 Route 53 refusal to adopt a same-name hosted zone it did not
    create — and a plain error for servers in ``fail_on``."""

    def __init__(self, conflict_on: set[str], fail_on: set[str] | None = None) -> None:
        super().__init__(fail_on)
        self.conflict_on = conflict_on

    async def apply_zone_change(self, server: DNSServer, zone: DNSZone, op: str) -> None:
        from app.drivers.dns._cloud_base import CloudDNSConflictError

        self.calls.append((server.name, op))
        if server.name in self.conflict_on and op == "create":
            raise CloudDNSConflictError(f"{server.name}: a hosted zone named example.com exists")
        if server.name in self.fail_on:
            raise RuntimeError(f"{server.name} unreachable")


async def test_conflict_on_second_server_rolls_back_the_first_and_answers_409(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The conflict used to be raised from inside the fan-out loop, so the
    zone created on the first server stayed there while the 409 said nothing
    had been saved — and a retry then conflicted on the first server too."""
    fake = _ConflictDriver(conflict_on={"second"})
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    grp = await _group(db_session)
    await _server(db_session, grp, "first")
    await _server(db_session, grp, "second")

    with pytest.raises(HTTPException) as excinfo:
        await _push_zone_to_agentless_servers(db_session, _zone(grp), "create")

    assert excinfo.value.status_code == 409
    assert fake.calls == [("first", "create"), ("second", "create"), ("first", "delete")]
    detail = excinfo.value.detail
    assert "hosted zone named example.com exists" in detail
    assert "Rolled back on: first" in detail
    assert "not saved" in detail


async def test_conflict_mixed_with_another_failure_is_still_a_502(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Resolving the conflict alone would not make a retry succeed, so a
    conflict next to an unreachable server is not reported as a 409."""
    fake = _ConflictDriver(conflict_on={"second"}, fail_on={"third"})
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    grp = await _group(db_session)
    for name in ("first", "second", "third"):
        await _server(db_session, grp, name)

    with pytest.raises(HTTPException) as excinfo:
        await _push_zone_to_agentless_servers(db_session, _zone(grp), "create")

    assert excinfo.value.status_code == 502
    assert ("first", "delete") in fake.calls
    detail = excinfo.value.detail
    assert "hosted zone named example.com exists" in detail
    assert "third unreachable" in detail
    assert "Rolled back on: first" in detail


# ── A server already in the requested state is not "rolled back" ──────────


class _NoopDriver(_FakeDriver):
    """Reports "no change" (``False``) for servers named in ``noop_on``.

    Models a driver that found the zone already there on create, or
    already gone on delete — the converged answers #1537 made success.
    """

    def __init__(self, noop_on: set[str], fail_on: set[str]) -> None:
        super().__init__(fail_on)
        self.noop_on = noop_on

    async def apply_zone_change(  # type: ignore[override]
        self, server: DNSServer, zone: DNSZone, op: str
    ) -> bool:
        await super().apply_zone_change(server, zone, op)
        return server.name not in self.noop_on


@pytest.mark.parametrize("op", ["create", "delete"])
async def test_server_already_in_state_is_left_as_found_on_partial_failure(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, op: str
) -> None:
    """A create that FOUND the zone must not be compensated with a delete.

    "first" already held the zone before this request (an operator-seeded
    zone, or one a previous attempt left behind). When "second" fails, a
    compensating delete on "first" would tear down a zone this request
    never created — on Cloudflare / Azure that deletes every record in it.
    The mirror case: a delete that found the zone already gone is not
    "rolled back" by re-creating it.
    """
    fake = _NoopDriver(noop_on={"first"}, fail_on={"second"})
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    grp = await _group(db_session)
    await _server(db_session, grp, "first")
    await _server(db_session, grp, "second")

    with pytest.raises(HTTPException) as excinfo:
        await _push_zone_to_agentless_servers(db_session, _zone(grp), op)

    assert excinfo.value.status_code == 502
    # Each server tried once, and no inverse op anywhere.
    assert sorted(fake.calls) == [("first", op), ("second", op)]
    assert "Rolled back on" not in excinfo.value.detail
    assert "Left as found on: first" in excinfo.value.detail


async def test_changed_server_is_still_compensated_next_to_an_unchanged_one(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _NoopDriver(noop_on={"found"}, fail_on={"broken"})
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    grp = await _group(db_session)
    for name in ("made", "found", "broken"):
        await _server(db_session, grp, name)

    with pytest.raises(HTTPException) as excinfo:
        await _push_zone_to_agentless_servers(db_session, _zone(grp), "create")

    assert ("made", "delete") in fake.calls
    assert ("found", "delete") not in fake.calls
    assert "Rolled back on: made" in excinfo.value.detail
    assert "Left as found on: found" in excinfo.value.detail
