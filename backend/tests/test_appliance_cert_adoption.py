"""Startup cert bootstrap adopts the cert firstboot already deployed (#767).

A fresh appliance had TWO self-signed cert generators racing: firstboot
mints one into the ``spatium-appliance-tls`` Secret before the chart
bootstraps (so the frontend nginx serves it from its first request), and
then the api's startup bootstrap minted a rival one, PATCHed the Secret,
and rolled the frontend. The operator saw two browser trust prompts and
a frontend restart mid-boot.

These cover the adopt path: when the Secret already holds a usable cert
covering every desired SAN, it becomes the active row and NOTHING is
deployed. Everything that isn't adoptable still falls through to the
original generate-and-deploy behaviour.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import (
    CERT_SOURCE_SELF_SIGNED,
    CERT_SOURCE_UPLOADED,
    ApplianceCertificate,
)
from app.services.appliance import bootstrap, deployment
from app.services.appliance.bootstrap import (
    _generate_self_signed_cert,
    ensure_self_signed_cert,
)
from app.services.appliance.tls import _format_fingerprint


def _firstboot_cert() -> tuple[str, str]:
    """A stand-in for what ``spatiumddi-firstboot`` writes into the Secret.

    Same shape: the appliance hostname + its host IP, plus the
    ``localhost`` / ``127.0.0.1`` SANs firstboot always adds — i.e. a
    strict superset of what the api would ask for.
    """
    cert_pem, key_pem, _info = _generate_self_signed_cert(
        "ddi1", ["192.168.0.199"], ["localhost", "127.0.0.1"]
    )
    return cert_pem, key_pem


def _appliance_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", True)
    monkeypatch.setattr(bootstrap.settings, "appliance_hostname", "ddi1")
    monkeypatch.setattr(bootstrap.settings, "appliance_host_ips", "192.168.0.199")
    monkeypatch.setattr(bootstrap.settings, "appliance_extra_cert_sans", "")


class _DeploySpy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def __call__(self, cert_pem: str, key_pem: str, *, name: str = "") -> bool:
        self.calls.append((cert_pem, key_pem))
        return True


async def _active_row(db: AsyncSession) -> ApplianceCertificate:
    return (
        await db.execute(
            select(ApplianceCertificate).where(ApplianceCertificate.is_active.is_(True))
        )
    ).scalar_one()


@pytest.mark.asyncio
async def test_adopts_deployed_cert_without_redeploying(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Secret's cert becomes the active row, and nothing is deployed."""
    _appliance_settings(monkeypatch)
    cert_pem, key_pem = _firstboot_cert()
    spy = _DeploySpy()
    monkeypatch.setattr(bootstrap, "read_deployed_cert", lambda: (cert_pem, key_pem))
    monkeypatch.setattr(bootstrap, "deploy_and_reload", spy)

    await ensure_self_signed_cert()

    row = await _active_row(db_session)
    assert row.source == CERT_SOURCE_SELF_SIGNED
    # The adopted PEM is byte-identical to what nginx is already serving —
    # this is the whole point: one cert identity across the boot.
    assert row.cert_pem == cert_pem
    assert row.name.startswith("self-signed-firstboot-")
    # ...and the frontend was NOT rolled.
    assert spy.calls == []


@pytest.mark.asyncio
async def test_adopted_fingerprint_matches_the_served_cert(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Metadata is parsed from the real cert, not assumed."""
    _appliance_settings(monkeypatch)
    cert_pem, key_pem = _firstboot_cert()
    monkeypatch.setattr(bootstrap, "read_deployed_cert", lambda: (cert_pem, key_pem))
    monkeypatch.setattr(bootstrap, "deploy_and_reload", _DeploySpy())

    await ensure_self_signed_cert()

    row = await _active_row(db_session)
    expected = _format_fingerprint(
        x509.load_pem_x509_certificate(cert_pem.encode()).fingerprint(hashes.SHA256())
    )
    assert row.fingerprint_sha256 == expected
    assert row.subject_cn == "ddi1"
    # firstboot's extra SANs are recorded as-is, not trimmed to what the
    # api happened to ask for.
    sans = set(row.sans_json or [])
    assert {"ddi1", "192.168.0.199", "localhost", "127.0.0.1"} <= sans


@pytest.mark.asyncio
async def test_generates_when_deployed_cert_misses_a_san(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Secret cert that doesn't cover the VIP is not adoptable."""
    _appliance_settings(monkeypatch)
    monkeypatch.setattr(bootstrap.settings, "appliance_extra_cert_sans", "192.168.0.240")
    cert_pem, key_pem = _firstboot_cert()  # no VIP in its SANs
    spy = _DeploySpy()
    monkeypatch.setattr(bootstrap, "read_deployed_cert", lambda: (cert_pem, key_pem))
    monkeypatch.setattr(bootstrap, "deploy_and_reload", spy)

    await ensure_self_signed_cert()

    row = await _active_row(db_session)
    assert row.cert_pem != cert_pem
    assert "192.168.0.240" in set(row.sans_json or [])
    # Fresh cert → it MUST be pushed to the Secret + the frontend rolled.
    assert len(spy.calls) == 1


@pytest.mark.asyncio
async def test_generates_when_key_does_not_match_cert(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mismatched cert/key pair in the Secret is never adopted."""
    _appliance_settings(monkeypatch)
    cert_pem, _key_pem = _firstboot_cert()
    _other_cert, other_key = _firstboot_cert()  # different keypair
    spy = _DeploySpy()
    monkeypatch.setattr(bootstrap, "read_deployed_cert", lambda: (cert_pem, other_key))
    monkeypatch.setattr(bootstrap, "deploy_and_reload", spy)

    await ensure_self_signed_cert()

    row = await _active_row(db_session)
    assert row.cert_pem != cert_pem
    assert len(spy.calls) == 1


@pytest.mark.asyncio
async def test_generates_when_secret_is_unreadable(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not on k8s / Secret absent → the original generate path."""
    _appliance_settings(monkeypatch)
    spy = _DeploySpy()
    monkeypatch.setattr(bootstrap, "read_deployed_cert", lambda: None)
    monkeypatch.setattr(bootstrap, "deploy_and_reload", spy)

    await ensure_self_signed_cert()

    row = await _active_row(db_session)
    assert row.name.startswith("self-signed-default-")
    assert len(spy.calls) == 1


def _ca_issued_cert() -> tuple[str, str]:
    """A leaf signed by a separate CA — issuer != subject.

    Stands in for a Let's Encrypt / operator-uploaded cert left in the
    Secret after the DB was reprovisioned.
    """
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuing CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ddi1")]))
        .issuer_name(ca.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("ddi1"),
                    x509.IPAddress(__import__("ipaddress").ip_address("192.168.0.199")),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        leaf.public_bytes(serialization.Encoding.PEM).decode(),
        leaf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
    )


@pytest.mark.asyncio
async def test_ca_issued_cert_is_not_adopted_as_self_signed(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real CA cert in the Secret must land in the operator-owned bucket.

    Recording it ``self-signed`` would let ``reconcile_cluster_cert_sans``
    overwrite the operator's cert on the next SAN growth — that loop only
    auto-replaces self-signed rows.
    """
    _appliance_settings(monkeypatch)
    cert_pem, key_pem = _ca_issued_cert()
    spy = _DeploySpy()
    monkeypatch.setattr(bootstrap, "read_deployed_cert", lambda: (cert_pem, key_pem))
    monkeypatch.setattr(bootstrap, "deploy_and_reload", spy)

    await ensure_self_signed_cert()

    row = await _active_row(db_session)
    assert row.source == CERT_SOURCE_UPLOADED
    assert row.issuer_cn == "Test Issuing CA"
    # Still adopted, not replaced — clobbering an operator's cert with a
    # self-signed one would be worse than either alternative.
    assert row.cert_pem == cert_pem
    assert spy.calls == []


@pytest.mark.asyncio
async def test_read_deployed_cert_preserves_secret_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Byte-identical, or the NEXT boot re-deploys and rolls the frontend."""
    monkeypatch.setattr(deployment.settings, "appliance_mode", True)
    cert_pem, key_pem = _firstboot_cert()  # both end in a trailing newline
    assert cert_pem.endswith("\n"), "fixture should carry the newline under test"
    monkeypatch.setattr(
        deployment.k8s,
        "get_secret",
        lambda name, namespace=None: (200, {"tls.crt": cert_pem, "tls.key": key_pem}),
    )

    assert deployment.read_deployed_cert() == (cert_pem, key_pem)


@pytest.mark.asyncio
async def test_read_deployed_cert_rejects_blank_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deployment.settings, "appliance_mode", True)
    monkeypatch.setattr(
        deployment.k8s,
        "get_secret",
        lambda name, namespace=None: (200, {"tls.crt": "\n  \n", "tls.key": "x"}),
    )
    assert deployment.read_deployed_cert() is None


@pytest.mark.asyncio
async def test_path_a_does_not_redeploy_an_already_deployed_cert(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An api restart must not re-push the cert it finds deployed (#767).

    Live on the #767 VM, before #1173: Path A re-pushed the identical cert
    on the first api start after adoption, which wrote the frontend's old
    ``tls-secret-checksum`` pod-template annotation for the first time and
    rolled the frontend to a new ReplicaSet for no reason. The api no longer
    rolls anything, but a re-push is still a Secret write nobody asked for.
    """
    _appliance_settings(monkeypatch)
    cert_pem, key_pem = _firstboot_cert()
    from app.core.crypto import encrypt_str

    db_session.add(
        ApplianceCertificate(
            name="self-signed-firstboot-abcd1234",
            source=CERT_SOURCE_SELF_SIGNED,
            cert_pem=cert_pem,
            key_encrypted=encrypt_str(key_pem),
            is_active=True,
            subject_cn="ddi1",
            sans_json=["ddi1", "192.168.0.199", "localhost", "127.0.0.1"],
        )
    )
    await db_session.commit()

    spy = _DeploySpy()
    # The Secret already holds exactly this cert — the steady state.
    monkeypatch.setattr(bootstrap, "read_deployed_cert", lambda: (cert_pem, key_pem))
    monkeypatch.setattr(bootstrap, "deploy_and_reload", spy)

    await ensure_self_signed_cert()

    assert spy.calls == [], "an already-deployed cert must not be re-pushed"


@pytest.mark.asyncio
async def test_path_a_still_recovers_a_wiped_secret(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The skip must not break what Path A exists for."""
    _appliance_settings(monkeypatch)
    cert_pem, key_pem = _firstboot_cert()
    from app.core.crypto import encrypt_str

    db_session.add(
        ApplianceCertificate(
            name="self-signed-firstboot-abcd1234",
            source=CERT_SOURCE_SELF_SIGNED,
            cert_pem=cert_pem,
            key_encrypted=encrypt_str(key_pem),
            is_active=True,
            subject_cn="ddi1",
            sans_json=["ddi1", "192.168.0.199", "localhost", "127.0.0.1"],
        )
    )
    await db_session.commit()

    spy = _DeploySpy()
    monkeypatch.setattr(bootstrap, "read_deployed_cert", lambda: None)  # Secret wiped
    monkeypatch.setattr(bootstrap, "deploy_and_reload", spy)

    await ensure_self_signed_cert()

    assert spy.calls == [(cert_pem, key_pem)]


@pytest.mark.asyncio
async def test_existing_active_row_still_wins_over_the_secret(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Adoption is Path B only — an existing active row is still re-deployed.

    Guards the upgrade case: an appliance that already has an operator's
    cert in the DB must not adopt whatever happens to be in the Secret.
    """
    _appliance_settings(monkeypatch)
    existing_pem, existing_key = _firstboot_cert()
    from app.core.crypto import encrypt_str

    db_session.add(
        ApplianceCertificate(
            name="operator-cert",
            source="uploaded",
            cert_pem=existing_pem,
            key_encrypted=encrypt_str(existing_key),
            is_active=True,
            subject_cn="ddi1",
            sans_json=["ddi1", "192.168.0.199"],
        )
    )
    await db_session.commit()

    secret_pem, secret_key = _firstboot_cert()
    spy = _DeploySpy()
    monkeypatch.setattr(bootstrap, "read_deployed_cert", lambda: (secret_pem, secret_key))
    monkeypatch.setattr(bootstrap, "deploy_and_reload", spy)

    await ensure_self_signed_cert()

    row = await _active_row(db_session)
    assert row.name == "operator-cert"
    # Path A re-deploys the DB's cert over whatever the Secret held.
    assert spy.calls == [(existing_pem, existing_key)]


# ── #1173: deploying a certificate writes the Secret and nothing else ──────


def test_deploying_a_certificate_leaves_the_frontend_deployment_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Live on a three-node control plane (#1173): each certificate change
    bumped the frontend's pod template, and the roll that followed is
    terminate-first on hostNetwork, so every node's web port refused
    connections in turn, for about 23 s on the seed when a member joined.

    The Secret is mounted into the frontend as a directory, so its running
    pods see the new files, and the image reloads nginx when they change
    (frontend/40-tls-reload-watch.sh). That also covers #1219's write-back
    after a #1215 revert: the files change twice and nginx reloads twice,
    with no annotation left to name the wrong certificate."""
    import json

    monkeypatch.setattr(deployment.settings, "appliance_mode", True)
    patched: list[tuple[str, dict[str, str]]] = []
    kubeapi: list[tuple[str, str]] = []
    annotations: list[tuple[str, str, str]] = []
    secret = {
        "data": {"tls.crt": "QUNUSVZF", "tls.key": "S0VZ"},
        "metadata": {"resourceVersion": "100"},
    }

    class _Cfg:
        namespace = "spatium"

    monkeypatch.setattr(deployment.k8s, "get_config", lambda: _Cfg())
    monkeypatch.setattr(
        deployment.k8s,
        "patch_secret",
        lambda name, data, namespace=None: (patched.append((name, data)) or (True, None)),
    )
    monkeypatch.setattr(
        deployment.k8s,
        "_request",
        lambda method, path: (kubeapi.append((method, path)) or (200, json.dumps(secret).encode())),
    )
    monkeypatch.setattr(
        deployment.k8s,
        "patch_deployment_annotation",
        lambda name, key, value: (annotations.append((name, key, value)) or (True, None)),
    )

    assert deployment.deploy_and_reload("CERT", "KEY", name="operator-cert")
    assert patched == [("spatium-appliance-tls", {"tls.crt": "CERT", "tls.key": "KEY"})]
    assert annotations == [], "a certificate change must not roll the frontend"
    assert not [path for _, path in kubeapi if "/deployments/" in path]
