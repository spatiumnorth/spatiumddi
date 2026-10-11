"""#1686: an ACME order whose CA cannot be reached ends, and says why.

``run_order`` re-raises a transient ``httpx.TransportError`` (connection
refused, timed out, reset) so that the Celery task ``run_acme_order`` retries
it. Nothing settled the order once those retries were spent. It stayed
``processing`` with ``last_error`` empty for good, the UI kept polling, and the
renewal sweep skipped that certificate's domains as "already being
(re)issued" from then on.

The task tests drive the real task through Celery's own retry loop (eager
``apply`` runs each retry at once), so they follow the task's retry policy
rather than restating it. Only the CA client is faked. It cannot connect,
like a CA that is down, a wrong directory URL, or a firewall in the way.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.db import task_session
from app.models.acme_client import (
    ACME_ORDER_INVALID,
    ACME_ORDER_PENDING,
    ACME_ORDER_PROCESSING,
    ACMEClientAccount,
    ACMEOrder,
)
from app.models.appliance import CERT_SOURCE_LETSENCRYPT, ApplianceCertificate
from app.models.settings import PlatformSettings
from app.services.acme_client import orchestrator
from app.tasks import acme as acme_tasks

_DIRECTORY = "https://ca.unreachable.test:14000/directory"
_DOMAINS = ["www.example.com"]


class _UnreachableCA:
    """An ACME client whose CA never answers: every attempt fails to connect.

    With ``watch`` set to an order id, it records the ``last_error`` that
    order carried (committed) each time an attempt reached the CA, which is
    what the API showed while that attempt ran.
    """

    watch: uuid.UUID | None = None
    seen: list[str | None] = []

    def __init__(self, directory_url: str, *a: object, **kw: object) -> None:
        self._directory_url = directory_url

    async def __aenter__(self) -> _UnreachableCA:
        return self

    async def __aexit__(self, *exc: object) -> None:
        return None

    async def ensure_account(self, *, email: object = None) -> str:
        if self.watch is not None:
            async with task_session() as db:
                row = await db.get(ACMEOrder, self.watch)
                type(self).seen.append(row.last_error if row is not None else "<gone>")
        raise httpx.ConnectError(
            "All connection attempts failed",
            request=httpx.Request("GET", self._directory_url),
        )


async def _seed_order(db: AsyncSession) -> uuid.UUID:
    """An account at the unreachable CA and a ``pending`` order, committed
    (the task runs in its own session)."""
    account = ACMEClientAccount(
        directory_url=_DIRECTORY,
        email="ops@example.com",
        account_key_encrypted=encrypt_str("-stub-account-key-"),
    )
    db.add(account)
    await db.flush()
    order = ACMEOrder(
        account_id=account.id,
        domains=list(_DOMAINS),
        challenge_type="dns-01",
        status=ACME_ORDER_PENDING,
    )
    db.add(order)
    await db.commit()
    return order.id


async def _run_task(order_id: uuid.UUID) -> list[str | None]:
    """Run ``run_acme_order`` through every retry Celery makes, eagerly.

    The task calls ``asyncio.run()``, so it gets a thread with no running
    loop. ``run_order``'s cleanup sessions come from a per-call engine here,
    as the task's own session does, so no pooled connection outlives that
    thread's event loop (app/db.py, "Per-task DB session for Celery").
    Returns the ``last_error`` each attempt saw on the order.
    """
    _UnreachableCA.watch = order_id
    _UnreachableCA.seen = []
    try:
        with (
            patch.object(orchestrator, "ACMEClient", _UnreachableCA),
            patch.object(orchestrator, "AsyncSessionLocal", task_session),
        ):
            await asyncio.to_thread(acme_tasks.run_acme_order.apply, args=[str(order_id)])
    finally:
        _UnreachableCA.watch = None
    return list(_UnreachableCA.seen)


@pytest.mark.asyncio
async def test_a_transient_ca_error_leaves_the_order_processing_with_a_retrying_note(
    db_session: AsyncSession,
) -> None:
    """One attempt that cannot reach the CA re-raises for the Celery retry and
    leaves the order ``processing``, now saying why it waits."""
    oid = await _seed_order(db_session)

    with (
        patch.object(orchestrator, "ACMEClient", _UnreachableCA),
        pytest.raises(httpx.ConnectError),
    ):
        await orchestrator.run_order(db_session, oid)

    db_session.expire_all()
    order = await db_session.get(ACMEOrder, oid)
    assert order is not None
    assert order.status == ACME_ORDER_PROCESSING
    assert order.last_error is not None
    assert order.last_error.startswith("retrying: "), order.last_error
    assert "ConnectError" in order.last_error, order.last_error


@pytest.mark.asyncio
async def test_the_order_ends_invalid_with_the_ca_error_once_its_retries_are_spent(
    db_session: AsyncSession,
) -> None:
    """The last attempt Celery makes ends the order ``invalid`` with
    ``last_error`` naming the error and the CA. Every retry before it ran
    with the "retrying: ..." note on the order."""
    oid = await _seed_order(db_session)

    seen = await _run_task(oid)

    # The first run plus every retry the task's policy allows reached the CA.
    assert len(seen) == acme_tasks.run_acme_order.max_retries + 1, seen
    db_session.expire_all()
    order = await db_session.get(ACMEOrder, oid)
    assert order is not None
    assert order.status == ACME_ORDER_INVALID, (order.status, order.last_error)
    assert order.last_error is not None
    assert not order.last_error.startswith("retrying"), order.last_error
    assert "ConnectError" in order.last_error, order.last_error
    assert "ca.unreachable.test" in order.last_error, order.last_error
    assert seen[0] is None, seen  # nothing had failed yet
    assert all(s is not None and s.startswith("retrying: ") for s in seen[1:]), seen


@pytest.mark.asyncio
async def test_an_order_that_could_not_reach_the_ca_no_longer_blocks_renewal(
    db_session: AsyncSession,
) -> None:
    """Once the unreachable order has ended, the renewal sweep re-issues the
    certificate it covers instead of skipping it as "already being
    (re)issued" for as long as the order exists."""
    settings = await db_session.get(PlatformSettings, 1)
    if settings is None:
        settings = PlatformSettings(id=1)
        db_session.add(settings)
    settings.acme_enabled = True
    settings.acme_auto_renew = True
    settings.acme_domains = []  # renew with the cert's own SANs
    db_session.add(
        ApplianceCertificate(
            name=f"le-{uuid.uuid4().hex[:8]}",
            source=CERT_SOURCE_LETSENCRYPT,
            key_encrypted=encrypt_str("-stub-key-"),
            subject_cn=_DOMAINS[0],
            sans_json=list(_DOMAINS),
            is_active=True,
            valid_to=datetime.now(UTC) + timedelta(days=10),
        )
    )
    oid = await _seed_order(db_session)

    await _run_task(oid)

    with patch.object(acme_tasks.run_acme_order, "delay") as delay:
        result = await acme_tasks._renew()
    assert result == "renewed=1", result
    delay.assert_called_once()
    assert delay.call_args.args[0] != str(oid)


# ── Every shape of "the CA cannot be reached", through the real client ──
#
# The tests above fake the client. These drive the real ``ACMEClient``, with
# only its HTTP transport replaced, so the exception each shape raises is the
# one httpx really raises for it, and assert the order ends with an error that
# names what went wrong on every one of them.


def _account_key_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return (
        ec.generate_private_key(ec.SECP256R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


def _raising(exc_type: type[httpx.TransportError], message: str):  # type: ignore[no-untyped-def]
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc_type(message, request=request)

    return handler


def _answering(status: int):  # type: ignore[no-untyped-def]
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, text="upstream unavailable")

    return handler


_SHAPES = [
    # (id, handler, substrings the final last_error must carry)
    (
        "dns-failure",
        _raising(httpx.ConnectError, "[Errno -2] Name or service not known"),
        ("ConnectError", "Name or service not known", "ca.unreachable.test", "no retries left"),
    ),
    (
        "connection-refused",
        _raising(httpx.ConnectError, "[Errno 111] Connection refused"),
        ("ConnectError", "Connection refused", "ca.unreachable.test", "no retries left"),
    ),
    (
        "tls-error",
        _raising(httpx.ConnectError, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"),
        ("ConnectError", "CERTIFICATE_VERIFY_FAILED", "ca.unreachable.test", "no retries left"),
    ),
    (
        "connect-timeout",
        _raising(httpx.ConnectTimeout, ""),
        ("ConnectTimeout", "ca.unreachable.test", "no retries left"),
    ),
    (
        "read-timeout",
        _raising(httpx.ReadTimeout, ""),
        ("ReadTimeout", "ca.unreachable.test", "no retries left"),
    ),
    (
        "connection-reset",
        _raising(httpx.RemoteProtocolError, "Server disconnected without sending a response."),
        ("RemoteProtocolError", "ca.unreachable.test", "no retries left"),
    ),
    # A CA that answers, but with a 5xx, is a protocol failure: no retry, the
    # order ends on the first attempt with the status code.
    ("http-503", _answering(503), ("directory fetch failed", "HTTP 503")),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler", "expected"),
    [pytest.param(h, e, id=i) for i, h, e in _SHAPES],
)
async def test_every_unreachable_ca_shape_ends_the_order_with_its_error(
    db_session: AsyncSession, handler, expected  # type: ignore[no-untyped-def]
) -> None:
    oid = await _seed_order(db_session)
    seeded = await db_session.get(ACMEOrder, oid)
    assert seeded is not None
    account = await db_session.get(ACMEClientAccount, seeded.account_id)
    assert account is not None
    # The real client parses the account key in its constructor.
    account.account_key_encrypted = encrypt_str(_account_key_pem())
    await db_session.commit()

    real_async_client = httpx.AsyncClient
    calls: list[str] = []

    def counting(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return handler(request)

    def client_factory(*a: object, **kw: object) -> httpx.AsyncClient:
        kw["transport"] = httpx.MockTransport(counting)
        return real_async_client(*a, **kw)  # type: ignore[arg-type]

    from app.services.acme_client import engine

    with (
        patch.object(engine.httpx, "AsyncClient", client_factory),
        patch.object(orchestrator, "AsyncSessionLocal", task_session),
    ):
        await asyncio.to_thread(acme_tasks.run_acme_order.apply, args=[str(oid)])

    db_session.expire_all()
    order = await db_session.get(ACMEOrder, oid)
    assert order is not None
    assert order.status == ACME_ORDER_INVALID, (order.status, order.last_error)
    assert order.last_error is not None
    assert not order.last_error.startswith("retrying"), order.last_error
    for needle in expected:
        assert needle in order.last_error, (needle, order.last_error)
    # Only the origin is named, never the directory path.
    assert "/directory" not in order.last_error, order.last_error
    assert calls, "the CA was never contacted"
