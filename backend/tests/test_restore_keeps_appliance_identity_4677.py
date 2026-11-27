"""A restore onto a fresh install keeps the running appliance (#4677).

The replay swaps the appliance registry and the CA for the archive's, so the
supervisor on this node, holding a certificate from the CA that was just
replaced, was refused as unknown and revoked itself. The live rows are now
captured before the replay and merged back after it.

The replay itself is simulated: the "archive" is whatever rows the test writes
between ``snapshot`` and ``adopt``.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.appliance import Appliance, ApplianceCA
from app.models.dhcp import DHCPServer, DHCPServerGroup
from app.models.dns import DNSServer, DNSServerGroup
from app.models.network import ApplianceLldpNeighbour
from app.services.backup import appliance_identity as ident
from tests.conftest import _TestSessionLocal


def _appliance(host: str, **kw) -> Appliance:
    der = uuid.uuid4().bytes
    base = dict(
        hostname=host,
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state="approved",
        cert_pem=f"CERT-{host}",
        cert_serial="01",
        last_seen_at=datetime.now(UTC),
        assigned_roles=["dns-bind9", "dhcp-kea"],
        cluster_role="primary",
    )
    base.update(kw)
    return Appliance(**base)


def _ca(pem: str) -> ApplianceCA:
    return ApplianceCA(
        id=1,
        subject_cn="ca",
        algorithm="rsa2048",
        cert_pem=pem,
        key_encrypted=b"\x00\x01key-" + pem.encode(),
        expires_at=datetime.now(UTC) + timedelta(days=365),
    )


async def _replay_with(db: AsyncSession, rows: list, ca: ApplianceCA | None) -> None:
    """What the archive replay does to the registry."""
    await db.execute(delete(Appliance))
    await db.execute(delete(ApplianceCA))
    await db.execute(delete(DNSServerGroup))
    await db.commit()
    for r in rows:
        db.add(r)
    if ca is not None:
        db.add(ca)
    await db.commit()


@pytest.mark.asyncio
async def test_fresh_install_restore_keeps_running_appliance(db_session: AsyncSession) -> None:
    group = DNSServerGroup(name="meridian-dns")
    live = _appliance("node1", assigned_dns_group_id=None)
    db_session.add_all([group, _ca("LIVE-CA")])
    await db_session.flush()
    live.assigned_dns_group_id = group.id
    db_session.add(live)
    await db_session.commit()
    live_id = live.id
    live_cert = live.cert_pem

    snap = await ident.snapshot(str(settings.database_url))
    assert snap is not None

    # The archive: another install's registry, CA and groups, same host name.
    old = _appliance("NODE1", cert_pem="OLD-CERT")
    other = _appliance("node9")
    await _replay_with(db_session, [old, other], _ca("ARCHIVE-CA"))
    archive_group = DNSServerGroup(name="meridian-dns")
    db_session.add(archive_group)
    await db_session.commit()
    old_id, other_id, archive_gid = old.id, other.id, archive_group.id

    out = await ident.adopt(str(settings.database_url), snap)
    assert out.ca_replaced
    assert [a["id"] for a in out.adopted] == [str(live_id)]

    db_session.expire_all()
    ca = (await db_session.execute(select(ApplianceCA))).scalar_one()
    assert ca.cert_pem == "LIVE-CA" and ca.key_encrypted.endswith(b"LIVE-CA")
    rows = {r.id: r for r in (await db_session.execute(select(Appliance))).scalars()}
    assert live_id in rows and rows[live_id].cert_pem == live_cert
    assert rows[live_id].state == "approved"
    assert rows[live_id].assigned_roles == ["dns-bind9", "dhcp-kea"]
    # Group id re-pointed by name at the archive's group.
    assert rows[live_id].assigned_dns_group_id == archive_gid
    assert old_id not in rows  # the same host's stale identity
    assert other_id in rows  # another node of the archive is left alone
    assert any("appliance identity" in w for w in out.warnings)


@pytest.mark.asyncio
async def test_same_install_restore_changes_nothing(db_session: AsyncSession) -> None:
    live = _appliance("node1")
    db_session.add_all([live, _ca("SAME-CA")])
    await db_session.commit()
    snap = await ident.snapshot(str(settings.database_url))
    assert snap is not None

    out = await ident.adopt(str(settings.database_url), snap)
    assert out.adopted == [] and not out.ca_replaced and out.warnings == []


@pytest.mark.asyncio
async def test_no_appliance_rows_means_no_snapshot(db_session: AsyncSession) -> None:
    assert await ident.snapshot(str(settings.database_url)) is None


@pytest.mark.asyncio
async def test_apply_backup_restore_keeps_the_running_appliance(
    db_session: AsyncSession, monkeypatch
) -> None:
    """Through the real ``apply_backup_restore``, the replay stubbed to swap
    the registry the way a restore of another install's archive does."""
    import os

    from app.services.backup import restore as restore_mod
    from app.services.backup.migrations import MigrationOutcome
    from app.services.backup.rewrap import RewrapOutcome

    live = _appliance("node1")
    db_session.add_all([live, _ca("LIVE-CA")])
    await db_session.commit()
    live_id = live.id

    manifest = {"format_version": next(iter(restore_mod.SUPPORTED_FORMAT_VERSIONS))}

    async def _async(value):
        return value

    monkeypatch.setattr(
        restore_mod, "extract_archive_members", lambda _b: (manifest, b"dump", "custom", b"enc")
    )
    monkeypatch.setattr(restore_mod, "decrypt_secrets", lambda *_a, **_k: {})
    monkeypatch.setattr(restore_mod, "schema_direction_error", lambda _v: None)
    monkeypatch.setattr(restore_mod, "_write_pre_restore_safety_dump", lambda _db: _async(None))
    monkeypatch.setattr(
        restore_mod,
        "maybe_upgrade_after_restore",
        lambda **_k: _async(
            MigrationOutcome(
                state="up_to_date", source_head=None, local_head=None, migrations_applied=[]
            )
        ),
    )
    monkeypatch.setattr(restore_mod, "rewrap_secrets", lambda **_k: _async(RewrapOutcome()))
    monkeypatch.setattr(restore_mod, "_collect_post_restore_warnings", lambda _u: _async([]))

    async def _replay(_dump_path, _url):
        async with _TestSessionLocal() as s:
            await _replay_with(s, [_appliance("node1", cert_pem="OLD")], _ca("ARCHIVE-CA"))

    monkeypatch.setattr(restore_mod, "_run_pg_restore", _replay)

    outcome = await restore_mod.apply_backup_restore(
        db_session,
        db_url=os.environ["DATABASE_URL"],
        archive_bytes=b"zip",
        passphrase="hunter2hunter2",
        confirmation_phrase=restore_mod.CONFIRM_PHRASE,
    )

    assert [a["id"] for a in outcome.adopted_appliances] == [str(live_id)]
    async with _TestSessionLocal() as s:
        rows = (await s.execute(select(Appliance))).scalars().all()
        assert [(r.id, r.cert_pem) for r in rows] == [(live_id, "CERT-node1")]
        assert (await s.execute(select(ApplianceCA))).scalar_one().cert_pem == "LIVE-CA"


@pytest.mark.asyncio
async def test_same_id_row_takes_the_live_identity(db_session: AsyncSession) -> None:
    """An archive that carries the running row's id but an older copy of it
    (taken before approval, a revoke or a rotation) must not log the supervisor out."""
    live = _appliance("node1", cert_pem="LIVE-CERT", cert_serial="0a")
    db_session.add_all([live, _ca("SAME-CA")])
    await db_session.commit()
    live_id, live_der = live.id, live.public_key_der
    snap = await ident.snapshot(str(settings.database_url))
    assert snap is not None

    stale = _appliance(
        "node1",
        id=live_id,
        state="pending_approval",
        cert_pem=None,
        cert_serial=None,
        revoked_at=datetime.now(UTC),
        assigned_roles=["dns-bind9"],
    )
    await _replay_with(db_session, [stale], _ca("SAME-CA"))

    out = await ident.adopt(str(settings.database_url), snap)
    assert out.refreshed == ["node1"] and out.adopted == []

    db_session.expire_all()
    row = (await db_session.execute(select(Appliance))).scalar_one()
    assert row.id == live_id and row.state == "approved" and row.revoked_at is None
    assert row.cert_pem == "LIVE-CERT" and row.cert_serial == "0a"
    assert row.public_key_der == live_der
    # Everything that is not identity stays the archive's.
    assert row.assigned_roles == ["dns-bind9"]


@pytest.mark.asyncio
async def test_rows_of_the_stale_identity_move_to_the_live_one(
    db_session: AsyncSession,
) -> None:
    live = _appliance("node1")
    db_session.add_all([live, _ca("LIVE-CA")])
    await db_session.commit()
    live_id = live.id
    snap = await ident.snapshot(str(settings.database_url))
    assert snap is not None

    old = _appliance("node1", cert_pem="OLD")
    await _replay_with(db_session, [old], _ca("ARCHIVE-CA"))
    db_session.add(
        ApplianceLldpNeighbour(
            appliance_id=old.id,
            local_iface="eth0",
            remote_chassis_id="aa",
            remote_port_id="1",
            last_seen=datetime.now(UTC),
        )
    )
    await db_session.commit()

    await ident.adopt(str(settings.database_url), snap)

    db_session.expire_all()
    neighbours = (await db_session.execute(select(ApplianceLldpNeighbour))).scalars().all()
    assert [n.appliance_id for n in neighbours] == [live_id]


@pytest.mark.asyncio
async def test_unreadable_identity_is_reported_not_hidden(
    db_session: AsyncSession, monkeypatch
) -> None:
    """A failed capture must not pass silently into the outage."""
    import os

    from app.services.backup import restore as restore_mod
    from app.services.backup.migrations import MigrationOutcome
    from app.services.backup.rewrap import RewrapOutcome

    async def _boom(_url):
        raise RuntimeError("db hiccup")

    async def _async(value):
        return value

    manifest = {"format_version": next(iter(restore_mod.SUPPORTED_FORMAT_VERSIONS))}
    monkeypatch.setattr(restore_mod.appliance_identity, "snapshot", _boom)
    monkeypatch.setattr(
        restore_mod, "extract_archive_members", lambda _b: (manifest, b"dump", "custom", b"enc")
    )
    monkeypatch.setattr(restore_mod, "decrypt_secrets", lambda *_a, **_k: {})
    monkeypatch.setattr(restore_mod, "schema_direction_error", lambda _v: None)
    monkeypatch.setattr(restore_mod, "_write_pre_restore_safety_dump", lambda _db: _async(None))
    monkeypatch.setattr(
        restore_mod,
        "maybe_upgrade_after_restore",
        lambda **_k: _async(
            MigrationOutcome(
                state="up_to_date", source_head=None, local_head=None, migrations_applied=[]
            )
        ),
    )
    monkeypatch.setattr(restore_mod, "rewrap_secrets", lambda **_k: _async(RewrapOutcome()))
    monkeypatch.setattr(restore_mod, "_collect_post_restore_warnings", lambda _u: _async([]))
    monkeypatch.setattr(restore_mod, "_run_pg_restore", lambda *_a: _async(None))

    outcome = await restore_mod.apply_backup_restore(
        db_session,
        db_url=os.environ["DATABASE_URL"],
        archive_bytes=b"zip",
        passphrase="hunter2hunter2",
        confirmation_phrase=restore_mod.CONFIRM_PHRASE,
    )
    assert any("could not be read" in w and "db hiccup" in w for w in outcome.warnings)


@pytest.mark.asyncio
async def test_restored_servers_of_the_adopted_appliance_keep_the_live_agent_identity(
    db_session: AsyncSession,
) -> None:
    """Finding of the #4680 walk: the agent registers onto the restored row
    (matched by hostname), whose fingerprint is the archive install's, so the
    DHCP handler un-approves it and the config long-poll answers pending."""
    live = _appliance("node1")
    db_session.add_all([live, _ca("LIVE-CA")])
    await db_session.flush()
    live_agent = uuid.uuid4()
    dgroup = DHCPServerGroup(name="g")
    nsgroup = DNSServerGroup(name="ns")
    db_session.add_all([dgroup, nsgroup])
    await db_session.flush()
    db_session.add_all(
        [
            DHCPServer(
                name="node1",
                driver="kea",
                host="node1",
                appliance_id=live.id,
                server_group_id=dgroup.id,
                agent_id=live_agent,
                agent_approved=True,
                agent_fingerprint="live-fp",
            ),
            DNSServer(
                name="node1",
                driver="bind9",
                host="node1",
                appliance_id=live.id,
                group_id=nsgroup.id,
                agent_id=uuid.uuid4(),
                agent_fingerprint="live-dns-fp",
                pending_approval=False,
            ),
        ]
    )
    await db_session.commit()
    live_id = live.id
    snap = await ident.snapshot(str(settings.database_url))
    assert snap is not None

    # The replay: the archive's group, its row for the same host, and an
    # unrelated server whose name happens to match nothing of ours.
    old = _appliance("node1", cert_pem="OLD")
    await _replay_with(db_session, [old], _ca("ARCHIVE-CA"))
    await db_session.execute(delete(DHCPServer))
    await db_session.execute(delete(DNSServer))
    await db_session.commit()
    ng = DNSServerGroup(name="ns")
    dg2 = DHCPServerGroup(name="g2")
    db_session.add_all([ng, dg2])
    await db_session.flush()
    db_session.add_all(
        [
            DHCPServer(
                name="node1",
                driver="kea",
                host="node1",
                appliance_id=old.id,
                server_group_id=dg2.id,
                agent_id=uuid.uuid4(),
                agent_approved=False,
                agent_fingerprint="archive-fp",
            ),
            DHCPServer(
                name="other",
                driver="kea",
                host="other",
                appliance_id=None,
                agent_id=uuid.uuid4(),
                agent_approved=False,
                agent_fingerprint="other-fp",
            ),
            DNSServer(
                name="node1",
                driver="bind9",
                host="node1",
                appliance_id=old.id,
                group_id=ng.id,
                agent_id=uuid.uuid4(),
                agent_fingerprint="archive-dns-fp",
                pending_approval=True,
            ),
        ]
    )
    await db_session.commit()

    await ident.adopt(str(settings.database_url), snap)

    db_session.expire_all()
    dhcp = {r.name: r for r in (await db_session.execute(select(DHCPServer))).scalars()}
    assert dhcp["node1"].appliance_id == live_id
    assert dhcp["node1"].agent_fingerprint == "live-fp"
    assert dhcp["node1"].agent_id == live_agent
    assert dhcp["node1"].agent_approved is True
    # A hostname the live appliance does not own is the archive's, untouched.
    assert dhcp["other"].agent_fingerprint == "other-fp" and dhcp["other"].agent_approved is False
    dns = (await db_session.execute(select(DNSServer))).scalar_one()
    assert dns.agent_fingerprint == "live-dns-fp" and dns.pending_approval is False


@pytest.mark.asyncio
async def test_agent_identity_clash_is_reported_not_silent(db_session: AsyncSession) -> None:
    """The carry runs in a savepoint; a unique agent_id clash must surface as
    a restore warning, not leave the server waiting for approval unannounced."""
    live = _appliance("node1")
    db_session.add_all([live, _ca("LIVE-CA")])
    await db_session.flush()
    live_agent = uuid.uuid4()
    g = DHCPServerGroup(name="g")
    db_session.add(g)
    await db_session.flush()
    db_session.add(
        DHCPServer(
            name="node1",
            driver="kea",
            host="node1",
            appliance_id=live.id,
            server_group_id=g.id,
            agent_id=live_agent,
            agent_approved=True,
            agent_fingerprint="live-fp",
        )
    )
    await db_session.commit()
    snap = await ident.snapshot(str(settings.database_url))
    assert snap is not None

    old = _appliance("node1", cert_pem="OLD")
    await _replay_with(db_session, [old], _ca("ARCHIVE-CA"))
    await db_session.execute(delete(DHCPServer))
    await db_session.commit()
    g2 = DHCPServerGroup(name="g2")
    db_session.add(g2)
    await db_session.flush()
    db_session.add_all(
        [
            DHCPServer(
                name="node1",
                driver="kea",
                host="node1",
                appliance_id=old.id,
                server_group_id=g2.id,
                agent_id=uuid.uuid4(),
                agent_approved=False,
                agent_fingerprint="archive-fp",
            ),
            DHCPServer(
                name="squatter",
                driver="kea",
                host="s",
                agent_id=live_agent,
                agent_approved=False,
                agent_fingerprint="s-fp",
            ),
        ]
    )
    await db_session.commit()

    out = await ident.adopt(str(settings.database_url), snap)
    assert any("agent identity" in w and "node1" in w for w in out.warnings)


@pytest.mark.asyncio
async def test_servers_with_null_appliance_id_keep_the_live_identity(
    db_session: AsyncSession,
) -> None:
    """Round 2 of the #4680 walk: on a real appliance the local agents'
    server rows have appliance_id NULL on both installs. They belong to the
    appliance by host == hostname, and only those do."""
    live = _appliance("node1")
    db_session.add_all([live, _ca("LIVE-CA")])
    await db_session.flush()
    live_agent = uuid.uuid4()
    dgroup = DHCPServerGroup(name="g")
    nsgroup = DNSServerGroup(name="ns")
    db_session.add_all([dgroup, nsgroup])
    await db_session.flush()
    db_session.add_all(
        [
            DHCPServer(
                name="node1",
                driver="kea",
                host="node1",
                server_group_id=dgroup.id,
                agent_id=live_agent,
                agent_approved=True,
                agent_fingerprint="live-fp",
            ),
            DNSServer(
                name="node1",
                driver="bind9",
                host="NODE1.",
                group_id=nsgroup.id,
                agent_id=uuid.uuid4(),
                agent_fingerprint="live-dns-fp",
                pending_approval=False,
            ),
        ]
    )
    await db_session.commit()
    snap = await ident.snapshot(str(settings.database_url))
    assert snap is not None

    old = _appliance("node1", cert_pem="OLD")
    await _replay_with(db_session, [old], _ca("ARCHIVE-CA"))
    await db_session.execute(delete(DHCPServer))
    await db_session.execute(delete(DNSServer))
    await db_session.commit()
    ng = DNSServerGroup(name="ns")
    dg2 = DHCPServerGroup(name="g2")
    db_session.add_all([ng, dg2])
    await db_session.flush()
    db_session.add_all(
        [
            # The archive's own rows, FK NULL as on every appliance.
            DHCPServer(
                name="node1",
                driver="kea",
                host="node1",
                server_group_id=dg2.id,
                agent_id=uuid.uuid4(),
                agent_approved=False,
                agent_fingerprint="archive-fp",
            ),
            DNSServer(
                name="node1",
                driver="bind9",
                host="node1",
                group_id=ng.id,
                agent_id=uuid.uuid4(),
                agent_fingerprint="archive-dns-fp",
                pending_approval=True,
            ),
            # A remote agent that shares the NAME but is another host.
            DHCPServer(
                name="NODE1",
                driver="kea",
                host="remote-host",
                server_group_id=dg2.id,
                agent_id=uuid.uuid4(),
                agent_approved=False,
                agent_fingerprint="remote-fp",
            ),
            DHCPServer(
                name="other",
                driver="kea",
                host="other",
                agent_id=uuid.uuid4(),
                agent_approved=False,
                agent_fingerprint="other-fp",
            ),
        ]
    )
    await db_session.commit()

    out = await ident.adopt(str(settings.database_url), snap)
    assert not any("agent identity" in w for w in out.warnings)

    db_session.expire_all()
    dhcp = {r.host: r for r in (await db_session.execute(select(DHCPServer))).scalars()}
    assert dhcp["node1"].agent_fingerprint == "live-fp"
    assert dhcp["node1"].agent_id == live_agent
    assert dhcp["node1"].agent_approved is True
    for host, fp in (("remote-host", "remote-fp"), ("other", "other-fp")):
        assert dhcp[host].agent_fingerprint == fp and dhcp[host].agent_approved is False
    dns = (await db_session.execute(select(DNSServer))).scalar_one()
    assert dns.agent_fingerprint == "live-dns-fp" and dns.pending_approval is False


@pytest.mark.asyncio
async def test_unapproved_live_null_fk_server_is_not_approved_by_the_carry(
    db_session: AsyncSession,
) -> None:
    live = _appliance("node1")
    g = DHCPServerGroup(name="g")
    db_session.add_all([live, _ca("LIVE-CA"), g])
    await db_session.flush()
    db_session.add(
        DHCPServer(
            name="node1",
            driver="kea",
            host="node1",
            server_group_id=g.id,
            agent_id=uuid.uuid4(),
            agent_approved=False,
            agent_fingerprint="live-fp",
        )
    )
    await db_session.commit()
    snap = await ident.snapshot(str(settings.database_url))
    assert snap is not None
    old = _appliance("node1", cert_pem="OLD")
    await _replay_with(db_session, [old], _ca("ARCHIVE-CA"))
    await db_session.execute(delete(DHCPServer))
    db_session.add(
        DHCPServer(
            name="node1",
            driver="kea",
            host="node1",
            agent_id=uuid.uuid4(),
            agent_approved=True,
            agent_fingerprint="archive-fp",
        )
    )
    await db_session.commit()
    await ident.adopt(str(settings.database_url), snap)
    db_session.expire_all()
    row = (await db_session.execute(select(DHCPServer))).scalar_one()
    assert row.agent_fingerprint == "live-fp" and row.agent_approved is False
