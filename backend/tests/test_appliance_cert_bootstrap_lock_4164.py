"""The startup cert bootstrap does not race the reconcile loops (#4164).

During a rolling upgrade every api pod runs ``ensure_self_signed_cert`` while
the other pods' reconcile loops may be regenerating the self-signed cert for a
joined member. The bootstrap used to read the active row and PATCH the Secret
with no lock, so a pod that read the row just before a sibling committed a
regenerated cert wrote its stale copy over the Secret: the Web UI certificate
flipped to the old one and back within a tick, and every member supervisor met
a certificate it had not pinned. It now takes the reconcile advisory lock; a
pod that loses it changes nothing and the loops converge on the active row.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.db import AsyncSessionLocal
from app.models.appliance import CERT_SOURCE_SELF_SIGNED, ApplianceCertificate
from app.services.appliance import bootstrap
from app.services.appliance.bootstrap import (
    _CERT_RECONCILE_LOCK_KEY,
    _generate_self_signed_cert,
    ensure_self_signed_cert,
)
from app.services.appliance.tls import parse_pem_certificate


def _settings(monkeypatch: pytest.MonkeyPatch, host_ips: str = "192.168.0.199") -> None:
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", True)
    monkeypatch.setattr(bootstrap.settings, "appliance_hostname", "ddi1")
    monkeypatch.setattr(bootstrap.settings, "appliance_host_ips", host_ips)
    monkeypatch.setattr(bootstrap.settings, "appliance_extra_cert_sans", "")


async def _active_cert(db: AsyncSession, ips: list[str]) -> tuple[str, str]:
    cert_pem, key_pem, info = _generate_self_signed_cert("ddi1", ips, [])
    parsed = parse_pem_certificate(cert_pem)
    db.add(
        ApplianceCertificate(
            name="self-signed-default-x",
            source=CERT_SOURCE_SELF_SIGNED,
            cert_pem=cert_pem,
            key_encrypted=encrypt_str(key_pem),
            is_active=True,
            subject_cn="ddi1",
            sans_json=info["sans"],
            issuer_cn="ddi1",
            fingerprint_sha256=parsed.fingerprint_sha256,
            valid_from=parsed.valid_from,
            valid_to=parsed.valid_to,
        )
    )
    await db.commit()
    return cert_pem, key_pem


class _Spies:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, deployed: tuple[str, str] | None) -> None:
        self.patched: list[tuple[str, str]] = []
        monkeypatch.setattr(bootstrap, "read_deployed_cert", lambda: deployed)

        def _deploy(cert_pem: str, key_pem: str, *, name: str = "") -> bool:
            self.patched.append((cert_pem, key_pem))
            return True

        monkeypatch.setattr(bootstrap, "deploy_active_cert", _deploy)
        monkeypatch.setattr(bootstrap, "deploy_and_reload", _deploy)

        async def _snapshot(_cert: str) -> None:
            return None

        monkeypatch.setattr(bootstrap, "_write_served_cert_snapshot", _snapshot)


async def _hold_reconcile_lock():  # type: ignore[no-untyped-def]
    other = AsyncSessionLocal()
    await other.execute(text("select pg_advisory_xact_lock(:k)"), {"k": _CERT_RECONCILE_LOCK_KEY})
    return other


@pytest.mark.asyncio
async def test_startup_does_not_overwrite_secret_while_reconcile_holds_lock(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A sibling mid-regeneration: this pod must not PATCH its (stale) row."""
    _settings(monkeypatch)
    await _active_cert(db_session, ["192.168.0.199"])
    spies = _Spies(monkeypatch, deployed=("some other cert", "some other key"))

    other = await _hold_reconcile_lock()
    try:
        await ensure_self_signed_cert()
    finally:
        await other.rollback()
        await other.close()

    assert spies.patched == []


@pytest.mark.asyncio
async def test_startup_does_not_regenerate_while_reconcile_holds_lock(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Three pods all seeing a SAN gap must not each mint a cert."""
    _settings(monkeypatch, host_ips="192.168.0.199,192.168.0.200")
    await _active_cert(db_session, ["192.168.0.199"])
    spies = _Spies(monkeypatch, deployed=None)

    other = await _hold_reconcile_lock()
    try:
        await ensure_self_signed_cert()
    finally:
        await other.rollback()
        await other.close()

    assert spies.patched == []
    rows = (await db_session.execute(select(ApplianceCertificate))).scalars().all()
    assert len(rows) == 1 and rows[0].is_active


@pytest.mark.asyncio
async def test_startup_restores_a_reverted_secret_and_leaves_a_matching_one(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Path A still repairs a wiped / reverted Secret, and is a no-op otherwise."""
    _settings(monkeypatch)
    cert_pem, key_pem = await _active_cert(db_session, ["192.168.0.199"])

    spies = _Spies(monkeypatch, deployed=(cert_pem, key_pem))
    await ensure_self_signed_cert()
    assert spies.patched == []

    spies = _Spies(monkeypatch, deployed=("first-boot cert", "first-boot key"))
    await ensure_self_signed_cert()
    assert spies.patched == [(cert_pem, key_pem)]
