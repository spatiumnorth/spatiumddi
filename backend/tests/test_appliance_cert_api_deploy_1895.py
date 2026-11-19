"""A Let's Encrypt cert issued in the worker is deployed by the api (#1895).

The worker's ServiceAccount cannot patch (or read) ``spatium-appliance-tls``
(#983 / #1445), so ``_store_certificate`` commits the row and wakes the api;
the api's ``sync_active_cert_to_secret`` (wake + periodic tick) does the
patch, and publishes what the Secret holds so the ``secret_expiring`` alert —
evaluated in the worker — can judge the cert actually served. The frontend
picks the new files up itself and reloads nginx in place: the api no longer
rolls its Deployment (#1173).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import APPLIANCE_CERT_DEPLOY
from app.core.crypto import encrypt_str
from app.db import AsyncSessionLocal
from app.models.acme_client import ACME_ORDER_PENDING, ACMEClientAccount, ACMEOrder
from app.models.alerts import AlertRule
from app.models.appliance import CERT_SOURCE_LETSENCRYPT, ApplianceCertificate
from app.services import alerts
from app.services.acme_client import orchestrator
from app.services.appliance import bootstrap, deployment
from app.services.appliance.bootstrap import _generate_self_signed_cert
from app.services.appliance.tls import parse_pem_certificate


class _FakeRedis:
    """Just enough of an async Redis client for the served-cert snapshot,
    backed by one dict so a write is visible to a later client's read."""

    def __init__(self, store: dict[str, Any]) -> None:
        self._store = store

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._store[key] = value

    async def get(self, key: str) -> str | None:
        return self._store.get(key)

    async def aclose(self) -> None:
        return None


@pytest.fixture
def redis_store(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    store: dict[str, Any] = {}
    monkeypatch.setattr(
        "app.core.redis_client.make_async_redis", lambda *_a, **_k: _FakeRedis(store)
    )
    return store


async def _order(db: AsyncSession) -> ACMEOrder:
    acct = ACMEClientAccount(
        directory_url="https://acme-staging-v02.api.letsencrypt.org/directory",
        email="ops@example.com",
        account_key_encrypted=encrypt_str("-stub-"),
    )
    db.add(acct)
    await db.flush()
    order = ACMEOrder(
        account_id=acct.id,
        domains=["ui.example.com"],
        challenge_type="dns-01",
        status=ACME_ORDER_PENDING,
    )
    db.add(order)
    await db.commit()
    return order


async def _active_le_cert(db: AsyncSession) -> tuple[str, str]:
    cert_pem, key_pem, _ = _generate_self_signed_cert("ui.example.com", [], [])
    info = parse_pem_certificate(cert_pem)
    db.add(
        ApplianceCertificate(
            name="le-x",
            subject_cn="ui.example.com",
            source=CERT_SOURCE_LETSENCRYPT,
            cert_pem=cert_pem,
            key_encrypted=encrypt_str(key_pem),
            is_active=True,
            fingerprint_sha256=info.fingerprint_sha256,
            valid_to=info.valid_to,
        )
    )
    await db.commit()
    return cert_pem, key_pem


@pytest.mark.asyncio
async def test_worker_issue_wakes_api_and_api_deploys(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, redis_store: dict[str, Any]
) -> None:
    monkeypatch.setattr(deployment.settings, "appliance_mode", True)
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", True)
    cert_pem, key_pem, _ = _generate_self_signed_cert("ui.example.com", [], [])
    order = await _order(db_session)

    # Worker side: the SA cannot patch the Secret, so any attempt would fail.
    wake = AsyncMock()
    patch_secret = MagicMock(return_value=(False, "forbidden"))
    with (
        patch.object(orchestrator, "publish_wake", wake, create=True),
        patch.object(deployment.k8s, "patch_secret", patch_secret),
        patch.object(orchestrator, "wake_dns_groups_serving_cert", AsyncMock()),
    ):
        row = await orchestrator._store_certificate(db_session, order, cert_pem, key_pem)
    patch_secret.assert_not_called()
    wake.assert_awaited_once_with(APPLIANCE_CERT_DEPLOY)
    assert row.is_active

    # Api side: Secret holds the old cert -> patch it, and only it (#1173).
    deploy = MagicMock(return_value=True)
    roll = MagicMock(return_value=(True, None))
    with (
        patch.object(bootstrap, "read_deployed_cert", lambda: ("old", "old")),
        patch.object(bootstrap, "deploy_active_cert", deploy, create=True),
        patch.object(deployment.k8s, "patch_deployment_annotation", roll),
    ):
        out = await bootstrap.sync_active_cert_to_secret()
    assert out["status"] == "deployed"
    assert deploy.call_args.args == (row.cert_pem, key_pem)
    roll.assert_not_called()
    # The worker-readable snapshot now names the cert just deployed.
    valid_to, fp = await bootstrap.read_served_cert_snapshot()
    info = parse_pem_certificate(cert_pem)
    assert (valid_to, fp) == (info.valid_to, info.fingerprint_sha256)


@pytest.mark.asyncio
async def test_periodic_reconcile_catches_missed_wake_and_is_idempotent(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, redis_store: dict[str, Any]
) -> None:
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", True)
    cert_pem, key_pem = await _active_le_cert(db_session)

    deploy = MagicMock(return_value=True)
    roll = MagicMock(return_value=(True, None))
    served = {"v": ("stale", "stale")}
    with (
        patch.object(bootstrap, "read_deployed_cert", lambda: served["v"]),
        patch.object(bootstrap, "deploy_active_cert", deploy, create=True),
        patch.object(deployment.k8s, "patch_deployment_annotation", roll),
    ):
        assert (await bootstrap.sync_active_cert_to_secret())["status"] == "deployed"
        served["v"] = (cert_pem, key_pem)
        # Converged: a second tick writes nothing.
        assert (await bootstrap.sync_active_cert_to_secret())["status"] == "in-sync"
    assert deploy.call_count == 1
    roll.assert_not_called()


@pytest.mark.asyncio
async def test_a_replica_holding_the_lock_keeps_the_others_out(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, redis_store: dict[str, Any]
) -> None:
    """The lock is the SAN reconcile's, so it also keeps that loop from
    committing a regenerated cert under a sync that read the old one."""
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", True)
    await _active_le_cert(db_session)

    deploy = MagicMock(return_value=True)
    async with AsyncSessionLocal() as other:
        got = (
            await other.execute(
                text("select pg_try_advisory_xact_lock(:k)"),
                {"k": bootstrap._CERT_RECONCILE_LOCK_KEY},
            )
        ).scalar()
        assert got
        with (
            patch.object(bootstrap, "read_deployed_cert", lambda: ("stale", "stale")),
            patch.object(bootstrap, "deploy_active_cert", deploy, create=True),
        ):
            out = await bootstrap.sync_active_cert_to_secret()
        await other.rollback()
    assert out["status"] == "locked"
    deploy.assert_not_called()


@pytest.mark.asyncio
async def test_sync_is_a_noop_off_the_appliance(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", False)
    deploy = MagicMock()
    read = MagicMock()
    with (
        patch.object(bootstrap, "deploy_active_cert", deploy, create=True),
        patch.object(bootstrap, "read_deployed_cert", read),
    ):
        assert (await bootstrap.sync_active_cert_to_secret())["status"] == "disabled"
    deploy.assert_not_called()
    read.assert_not_called()


async def _rule(db: AsyncSession) -> AlertRule:
    rule = AlertRule(
        name="Secret expiry",
        rule_type="secret_expiring",
        severity="warning",
        threshold_days=30,
        enabled=True,
    )
    db.add(rule)
    await db.commit()
    return rule


@pytest.mark.asyncio
async def test_secret_expiring_judges_the_cert_actually_served(
    db_session: AsyncSession, redis_store: dict[str, Any]
) -> None:
    """The alert runs in the worker, which cannot read the Secret, so it
    reads the snapshot the api published from it."""
    # Served: an old cert. "Now" is 3 days before it expires; the stored,
    # renewed cert has 89 days left.
    old_pem, _, _ = _generate_self_signed_cert("ui.example.com", [], [])
    served = parse_pem_certificate(old_pem)
    now = served.valid_to - timedelta(days=3)
    db_session.add(
        ApplianceCertificate(
            name="le-renewed",
            source=CERT_SOURCE_LETSENCRYPT,
            cert_pem="x",
            key_encrypted=encrypt_str("k"),
            is_active=True,
            subject_cn="ui.example.com",
            fingerprint_sha256="NEW",
            valid_to=now + timedelta(days=89),
        )
    )
    rule = await _rule(db_session)

    # Before the api has published anything (or off the appliance) the
    # stored row is all there is, and it is healthy.
    assert await alerts._matching_secret_expiring_subjects(db_session, rule, now) == []

    await bootstrap._write_served_cert_snapshot(old_pem)
    subjects = await alerts._matching_secret_expiring_subjects(db_session, rule, now)
    assert len(subjects) == 1
    assert "not deployed" in subjects[0][2]


@pytest.mark.asyncio
async def test_secret_expiring_quiet_when_the_served_cert_is_the_stored_one(
    db_session: AsyncSession, redis_store: dict[str, Any]
) -> None:
    cert_pem, _ = await _active_le_cert(db_session)
    rule = await _rule(db_session)
    await bootstrap._write_served_cert_snapshot(cert_pem)
    now = datetime.now(UTC)
    assert await alerts._matching_secret_expiring_subjects(db_session, rule, now) == []
