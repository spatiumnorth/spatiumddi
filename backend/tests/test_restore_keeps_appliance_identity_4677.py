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
from app.models.dns import DNSServerGroup
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
