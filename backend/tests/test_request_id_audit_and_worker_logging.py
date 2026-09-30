"""Audit rows carry the request id, and the worker logs like the api (#1245, #1246).

#1245: ``audit_log.request_id`` existed, was part of the tamper-evidence
hash, and was never set, although the docs say it links an audit row to its
request's log lines. It is now filled from the structlog context BEFORE the
hash is computed, so the chain still verifies.

#1246: ``configure_logging`` ran only in the api, so the worker and beat wrote
Celery's plain text with no ``service`` and no ``request_id``. They now share
the api's pipeline, stdlib records included, and a task binds its id as the
``request_id`` — which is how an audit row written by a task gets one.
"""

from __future__ import annotations

import io
import json
import logging
import uuid

import pytest
import structlog
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.celery_app import (
    _bind_task_request_id,
    _celery_service,
    _unbind_task_request_id,
)
from app.core.security import create_access_token, hash_password
from app.log import configure_logging
from app.main import _client_request_id
from app.models.audit import AuditLog
from app.models.auth import User
from app.services.audit_chain import verify_chain


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"rid-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="rid",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    user.groups = []  # mark loaded — is_effective_superadmin walks .groups (#351)
    db.add(user)
    await db.flush()
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _audited_create(client: AsyncClient, headers: dict[str, str]) -> str:
    """One audited mutation; returns the response's X-Request-ID."""
    r = await client.post(
        "/api/v1/dns/groups",
        json={"name": f"g-{uuid.uuid4().hex[:6]}"},
        headers=headers,
    )
    assert r.status_code == 201, r.text
    return r.headers["x-request-id"]


async def _row_for(db: AsyncSession, request_id: str) -> AuditLog | None:
    result = await db.execute(select(AuditLog).where(AuditLog.request_id == request_id))
    return result.scalars().first()


# ── #1245: the audit row ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_audit_row_carries_the_request_id_and_the_chain_verifies(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _admin_headers(db_session)
    rid = await _audited_create(client, {**headers, "X-Request-ID": "client-corr-42"})
    assert rid == "client-corr-42"

    row = await _row_for(db_session, rid)
    assert row is not None and row.action == "create"
    # The id went in BEFORE the hash: a row filled after hashing would fail
    # verification as a content edit.
    result = await verify_chain(db_session)
    assert result.ok, result.breaks


@pytest.mark.asyncio
async def test_a_generated_id_is_recorded_when_the_client_sends_none(
    client: AsyncClient, db_session: AsyncSession
):
    headers = await _admin_headers(db_session)
    rid = await _audited_create(client, headers)
    assert uuid.UUID(rid)
    assert await _row_for(db_session, rid) is not None


@pytest.mark.parametrize(
    "value",
    ["x" * 65, "has space", "semi;colon", "", "ünïcode"],
)
def test_an_unusable_client_id_is_replaced_not_truncated(value: str):
    # It would fail the 64-character column, or be unfit for a log field;
    # a truncated id would no longer match the caller's, so it is replaced.
    assert _client_request_id(value) is None


def test_a_plain_client_id_is_adopted():
    assert _client_request_id("req-01HZX.abc:9") == "req-01HZX.abc:9"


@pytest.mark.asyncio
async def test_the_bound_id_is_used_outside_a_request_and_an_explicit_one_wins(
    db_session: AsyncSession,
):
    structlog.contextvars.bind_contextvars(request_id="task-abc")
    try:
        implicit = AuditLog(
            action="t",
            resource_type="x",
            resource_id="1",
            resource_display="x",
            user_display_name="system",
        )
        explicit = AuditLog(
            action="t",
            user_display_name="system",
            resource_type="x",
            resource_id="2",
            resource_display="x",
            request_id="given",
        )
        db_session.add_all([implicit, explicit])
        await db_session.flush()
    finally:
        structlog.contextvars.unbind_contextvars("request_id")
    assert implicit.request_id == "task-abc"
    assert explicit.request_id == "given"
    assert (await verify_chain(db_session)).ok


# ── #1246: the worker and beat ────────────────────────────────────────


def test_the_command_line_names_the_service():
    assert _celery_service(["celery", "-A", "app.celery_app", "beat", "--loglevel=info"]) == "beat"
    assert _celery_service(["celery", "-A", "app.celery_app", "worker", "-Q", "dns"]) == "worker"


def test_a_task_binds_its_id_and_unbinds_it_after():
    class _Task:
        name = "app.tasks.example"

    _bind_task_request_id(task_id="t-1", task=_Task())
    try:
        ctx = structlog.contextvars.get_contextvars()
        assert ctx["request_id"] == "t-1"
        assert ctx["task"] == "app.tasks.example"
    finally:
        _unbind_task_request_id()
    assert "request_id" not in structlog.contextvars.get_contextvars()


def test_celery_is_told_not_to_install_its_own_logging():
    # Any receiver on setup_logging stops Celery hijacking the root logger
    # and redirecting stdout, which would wrap each JSON line in a text one.
    from celery.signals import setup_logging

    assert setup_logging.receivers


@pytest.fixture
def worker_logging(monkeypatch: pytest.MonkeyPatch):
    """configure_logging as the worker, writing into a buffer; restored after."""
    from app import log as log_module

    monkeypatch.setattr(log_module.settings, "log_format", "json")
    buffer = io.StringIO()
    configure_logging(service="worker", stream=buffer)
    yield buffer
    root = logging.getLogger()
    for handler in list(root.handlers):
        if getattr(handler, log_module._HANDLER_FLAG, False):
            root.removeHandler(handler)
    structlog.reset_defaults()


def _lines(buffer: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line.strip()]


def test_stdlib_and_structlog_lines_are_both_json_with_service(worker_logging: io.StringIO):
    structlog.contextvars.bind_contextvars(request_id="t-9")
    try:
        # Celery's own lines are stdlib records: this is the shape of
        # "Task … received" / "succeeded".
        logging.getLogger("celery.app.trace").info("Task example succeeded")
        structlog.get_logger("app.tasks").info("task_did_work", n=3)
    finally:
        structlog.contextvars.unbind_contextvars("request_id")

    lines = _lines(worker_logging)
    assert len(lines) == 2
    for line in lines:
        assert line["service"] == "worker"
        assert line["request_id"] == "t-9"
        assert "timestamp" in line and "level" in line
    assert lines[0]["event"] == "Task example succeeded"
    assert lines[0]["logger"] == "celery.app.trace"
    assert lines[1]["event"] == "task_did_work"


def test_configuring_twice_does_not_duplicate_lines(worker_logging: io.StringIO):
    configure_logging(service="worker", stream=worker_logging)
    logging.getLogger("x").warning("once")
    assert len(_lines(worker_logging)) == 1


def test_an_explicit_service_on_a_line_is_kept(worker_logging: io.StringIO):
    structlog.get_logger().info("startup", service="api")
    assert _lines(worker_logging)[0]["service"] == "api"
