"""Self-signed cert SAN coverage incl. the control-plane VIP (#272 Phase 6).

The appliance self-signed bootstrap must put the control-plane VIP in
the cert SANs so a cert served on the floating IP validates, and must
regenerate an existing self-signed cert that doesn't yet cover a
newly-configured VIP. These cover the pure-logic helpers plus a
round-trip parse of the generated cert to prove the VIP lands in the
SubjectAlternativeName extension.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import uuid

import pytest
from cryptography import x509
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.models.appliance import (
    APPLIANCE_STATE_APPROVED,
    CERT_SOURCE_SELF_SIGNED,
    CERT_SOURCE_UPLOADED,
    CLUSTER_ROLE_MEMBER,
    CLUSTER_ROLE_PRIMARY,
    Appliance,
    ApplianceCertificate,
)
from app.models.settings import PlatformSettings
from app.services.appliance import bootstrap
from app.services.appliance.bootstrap import (
    _desired_sans,
    _generate_self_signed_cert,
    _parse_extra_sans,
    _sans_cover,
    reconcile_cluster_cert_sans,
)


def test_parse_extra_sans_ips_and_dns_drop_loopback() -> None:
    assert _parse_extra_sans("192.0.2.10, vip.example.com ,127.0.0.1,, 192.0.2.10") == [
        "192.0.2.10",
        "vip.example.com",
    ]
    assert _parse_extra_sans("") == []


def test_desired_sans_dedupes_preserving_order() -> None:
    assert _desired_sans("host1", ["10.0.0.5", "10.0.0.5"], ["192.0.2.10", "host1"]) == [
        "host1",
        "10.0.0.5",
        "192.0.2.10",
    ]


def test_sans_cover() -> None:
    have = ["host1", "10.0.0.5", "192.0.2.10"]
    assert _sans_cover(have, ["host1", "192.0.2.10"])
    assert not _sans_cover(have, ["host1", "192.0.2.99"])
    # Legacy / missing sans_json covers nothing.
    assert not _sans_cover(None, ["host1"])
    assert _sans_cover(None, [])


def test_generated_cert_carries_vip_in_san() -> None:
    cert_pem, _key_pem, info = _generate_self_signed_cert(
        "appliance1", ["10.0.0.5"], ["192.0.2.241", "vip.example.com"]
    )
    # Reported SANs include host + ips + extras.
    assert info["sans"] == ["appliance1", "10.0.0.5", "192.0.2.241", "vip.example.com"]

    # Parse the real cert back and confirm the VIP is in the SAN ext.
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    ip_sans = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    dns_sans = set(san.get_values_for_type(x509.DNSName))
    assert ipaddress.ip_address("192.0.2.241") in {ipaddress.ip_address(s) for s in ip_sans}
    assert ipaddress.ip_address("10.0.0.5") in {ipaddress.ip_address(s) for s in ip_sans}
    # Subset assertion (not ``"literal" in set``) so CodeQL's URL
    # substring-sanitization heuristic doesn't flag the hostname literal.
    assert {"vip.example.com", "appliance1"} <= dns_sans


def test_generated_cert_no_extras_unchanged_shape() -> None:
    _cert_pem, _key, info = _generate_self_signed_cert("appliance1", ["10.0.0.5"])
    assert info["sans"] == ["appliance1", "10.0.0.5"]


# ── Cluster SAN reconcile (#272 Phase 7c) ────────────────────────────


async def _seed_appliance(db: AsyncSession, hostname: str, node_ip: str, role: str) -> None:
    der = os.urandom(32)
    db.add(
        Appliance(
            id=uuid.uuid4(),
            hostname=hostname,
            public_key_der=der,
            public_key_fingerprint=hashlib.sha256(der).hexdigest(),
            state=APPLIANCE_STATE_APPROVED,
            deployment_kind="appliance",
            cluster_role=role,
            node_ip=node_ip,
        )
    )


async def _seed_active_cert(db: AsyncSession, source: str, sans: list[str]) -> None:
    db.add(
        ApplianceCertificate(
            id=uuid.uuid4(),
            name=f"cert-{uuid.uuid4().hex[:8]}",
            source=source,
            cert_pem="-----BEGIN CERTIFICATE-----\nstub\n-----END CERTIFICATE-----",
            key_encrypted=encrypt_str("stub-key"),
            is_active=True,
            subject_cn=sans[0],
            sans_json=sans,
        )
    )


async def _set_vip(db: AsyncSession, vip: str) -> None:
    ps = (
        await db.execute(select(PlatformSettings).where(PlatformSettings.id == 1))
    ).scalar_one_or_none()
    if ps is None:
        ps = PlatformSettings(id=1)
        db.add(ps)
    ps.control_plane_vip = vip


@pytest.mark.asyncio
async def test_reconcile_grows_self_signed_to_cover_members(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", True)
    monkeypatch.setattr(bootstrap.settings, "appliance_hostname", "ddi1")
    monkeypatch.setattr(bootstrap.settings, "appliance_host_ips", "192.168.0.199")
    monkeypatch.setattr(bootstrap.settings, "appliance_extra_cert_sans", "")

    # Active self-signed cert only covers the seed; two more members
    # have since joined + a VIP was configured.
    await _seed_active_cert(db_session, CERT_SOURCE_SELF_SIGNED, ["ddi1", "192.168.0.199"])
    await _seed_appliance(db_session, "ddi1", "192.168.0.199", CLUSTER_ROLE_PRIMARY)
    await _seed_appliance(db_session, "ddi2", "192.168.0.125", CLUSTER_ROLE_MEMBER)
    await _seed_appliance(db_session, "sp2", "192.168.0.133", CLUSTER_ROLE_MEMBER)
    await _set_vip(db_session, "192.168.0.240")
    await db_session.commit()

    result = await reconcile_cluster_cert_sans()
    assert result["status"] == "regenerated", result

    active = (
        await db_session.execute(
            select(ApplianceCertificate).where(ApplianceCertificate.is_active.is_(True))
        )
    ).scalar_one()
    sans = set(active.sans_json or [])
    # Every member IP + hostname + the VIP is now covered.
    for s in ("192.168.0.125", "192.168.0.133", "ddi2", "sp2", "192.168.0.240", "ddi1"):
        assert s in sans, f"{s} missing from {sans}"
    # Exactly one active row (old one deactivated).
    n_active = len(
        (
            await db_session.execute(
                select(ApplianceCertificate).where(ApplianceCertificate.is_active.is_(True))
            )
        )
        .scalars()
        .all()
    )
    assert n_active == 1


@pytest.mark.asyncio
async def test_reconcile_skips_operator_cert(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", True)
    monkeypatch.setattr(bootstrap.settings, "appliance_hostname", "ddi1")
    monkeypatch.setattr(bootstrap.settings, "appliance_host_ips", "192.168.0.199")
    monkeypatch.setattr(bootstrap.settings, "appliance_extra_cert_sans", "")

    # Operator uploaded their own cert — never auto-replace it, even
    # though members' IPs aren't in the SANs.
    await _seed_active_cert(db_session, CERT_SOURCE_UPLOADED, ["ddi1"])
    await _seed_appliance(db_session, "ddi2", "192.168.0.125", CLUSTER_ROLE_MEMBER)
    await db_session.commit()

    result = await reconcile_cluster_cert_sans()
    assert result["status"] == "operator-cert", result


@pytest.mark.asyncio
async def test_reconcile_noop_when_covered(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", True)
    monkeypatch.setattr(bootstrap.settings, "appliance_hostname", "ddi1")
    monkeypatch.setattr(bootstrap.settings, "appliance_host_ips", "192.168.0.199")
    monkeypatch.setattr(bootstrap.settings, "appliance_extra_cert_sans", "")

    await _seed_active_cert(
        db_session,
        CERT_SOURCE_SELF_SIGNED,
        ["ddi1", "192.168.0.199", "ddi2", "192.168.0.125"],
    )
    await _seed_appliance(db_session, "ddi1", "192.168.0.199", CLUSTER_ROLE_PRIMARY)
    await _seed_appliance(db_session, "ddi2", "192.168.0.125", CLUSTER_ROLE_MEMBER)
    await db_session.commit()

    result = await reconcile_cluster_cert_sans()
    assert result["status"] == "covered", result


@pytest.mark.asyncio
async def test_reconcile_adds_the_appliance_fqdn_san(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#4550 — a domain given at install puts ``hostname.domain`` in the SANs.

    An existing self-signed cert that covers only the short name is regenerated;
    with no domain configured the same cert is left alone."""
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", True)
    monkeypatch.setattr(bootstrap.settings, "appliance_hostname", "ddi1")
    monkeypatch.setattr(bootstrap.settings, "appliance_host_ips", "192.168.0.199")
    monkeypatch.setattr(bootstrap.settings, "appliance_extra_cert_sans", "")
    monkeypatch.setattr(bootstrap.settings, "appliance_fqdn", "ddi1.corp.example.com.")

    await _seed_active_cert(db_session, CERT_SOURCE_SELF_SIGNED, ["ddi1", "192.168.0.199"])
    await _seed_appliance(db_session, "ddi1", "192.168.0.199", CLUSTER_ROLE_PRIMARY)
    await db_session.commit()

    result = await reconcile_cluster_cert_sans()
    assert result["status"] == "regenerated", result
    active = (
        await db_session.execute(
            select(ApplianceCertificate).where(ApplianceCertificate.is_active.is_(True))
        )
    ).scalar_one()
    assert "ddi1.corp.example.com" in set(active.sans_json or [])


def test_with_fqdn_is_a_noop_without_a_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bootstrap.settings, "appliance_fqdn", "")
    assert bootstrap._with_fqdn(["10.0.0.1"]) == ["10.0.0.1"]
    monkeypatch.setattr(bootstrap.settings, "appliance_fqdn", "a.b.example")
    assert bootstrap._with_fqdn(["a.b.example"]) == ["a.b.example"]
    assert bootstrap._with_fqdn(["10.0.0.1"]) == ["10.0.0.1", "a.b.example"]
