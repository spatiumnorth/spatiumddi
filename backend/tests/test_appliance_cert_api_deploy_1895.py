"""A Let's Encrypt cert issued in the worker is deployed by the api (#1895).

The worker's ServiceAccount cannot patch ``spatium-appliance-tls`` (#983 /
#1445), so ``_store_certificate`` commits the row and wakes the api; the
api's ``sync_active_cert_to_secret`` (wake + periodic tick) does the patch.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import APPLIANCE_CERT_DEPLOY
from app.core.crypto import encrypt_str
from app.models.acme_client import ACME_ORDER_PENDING, ACMEClientAccount, ACMEOrder
from app.models.appliance import CERT_SOURCE_LETSENCRYPT, ApplianceCertificate
from app.services.acme_client import orchestrator
from app.services.appliance import bootstrap, deployment
from app.services.appliance.bootstrap import _generate_self_signed_cert
from app.services.appliance.tls import parse_pem_certificate


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


@pytest.mark.asyncio
async def test_worker_issue_wakes_api_and_api_deploys(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
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

    # Api side: Secret holds the old cert -> deploy the active one.
    deploy = MagicMock(return_value=True)
    with (
        patch.object(bootstrap, "read_deployed_cert", lambda: ("old", "old")),
        patch.object(bootstrap, "deploy_and_reload", deploy),
    ):
        out = await bootstrap.sync_active_cert_to_secret()
    assert out["status"] == "deployed"
    assert deploy.call_args.args == (row.cert_pem, key_pem)


@pytest.mark.asyncio
async def test_periodic_reconcile_catches_missed_wake_and_is_idempotent(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", True)
    cert_pem, key_pem, _ = _generate_self_signed_cert("ui.example.com", [], [])
    info = parse_pem_certificate(cert_pem)
    db_session.add(
        ApplianceCertificate(
            name="le-x",
            subject_cn="ui.example.com",
            source=CERT_SOURCE_LETSENCRYPT,
            cert_pem=cert_pem,
            key_encrypted=encrypt_str(key_pem),
            is_active=True,
            valid_to=info.valid_to,
        )
    )
    await db_session.commit()

    deploy = MagicMock(return_value=True)
    served = {"v": ("stale", "stale")}
    with (
        patch.object(bootstrap, "read_deployed_cert", lambda: served["v"]),
        patch.object(bootstrap, "deploy_and_reload", deploy),
    ):
        assert (await bootstrap.sync_active_cert_to_secret())["status"] == "deployed"
        served["v"] = (cert_pem, key_pem)
        # Converged: a second tick writes nothing and rolls nothing.
        assert (await bootstrap.sync_active_cert_to_secret())["status"] == "in-sync"
    assert deploy.call_count == 1


@pytest.mark.asyncio
async def test_sync_is_a_noop_off_the_appliance(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bootstrap.settings, "appliance_mode", False)
    deploy = MagicMock()
    with patch.object(bootstrap, "deploy_and_reload", deploy):
        assert (await bootstrap.sync_active_cert_to_secret())["status"] == "disabled"
    deploy.assert_not_called()


@pytest.mark.asyncio
async def test_secret_expiring_judges_the_cert_actually_served(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.models.alerts import AlertRule
    from app.services import alerts

    now = datetime.now(UTC)
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
    rule = AlertRule(
        name="Secret expiry",
        rule_type="secret_expiring",
        severity="warning",
        threshold_days=30,
        enabled=True,
    )
    db_session.add(rule)
    await db_session.commit()

    served = AsyncMock(return_value=(now + timedelta(days=3), "OLD"))
    with patch.object(alerts, "_served_web_cert_expiry", served):
        subjects = await alerts._matching_secret_expiring_subjects(db_session, rule, now)
    assert len(subjects) == 1
    assert "not deployed" in subjects[0][2]

    # Served == stored: the healthy renewed cert does not alert.
    served = AsyncMock(return_value=(now + timedelta(days=89), "NEW"))
    with patch.object(alerts, "_served_web_cert_expiry", served):
        assert await alerts._matching_secret_expiring_subjects(db_session, rule, now) == []
