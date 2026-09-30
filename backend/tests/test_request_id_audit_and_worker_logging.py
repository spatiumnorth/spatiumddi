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
    rid = await _audited_create(client, headers)

    row = await _row_for(db_session, rid)
    assert row is not None and row.action == "create"
    # The id went in BEFORE the hash: a row filled after hashing would fail
    # verification as a content edit.
    result = await verify_chain(db_session)
    assert result.ok, result.breaks


@pytest.mark.asyncio
async def test_a_client_id_is_echoed_but_never_stored_in_the_audit_row(
    client: AsyncClient, db_session: AsyncSession
):
    # The audit column is inside the tamper-evidence hash: a caller-chosen
    # id there would let a caller make its rows claim another request's id.
    headers = await _admin_headers(db_session)
    echoed = await _audited_create(client, {**headers, "X-Request-ID": "victim-request-7"})
    assert echoed == "victim-request-7"  # the caller still gets its own id back
    assert await _row_for(db_session, "victim-request-7") is None
    newest = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "create").order_by(AuditLog.seq.desc())
            )
        )
        .scalars()
        .first()
    )
    assert newest is not None and uuid.UUID(newest.request_id)


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
    ["x" * 65, "has space", "semi;colon", "", "ünïcode", "abc\n"],
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


@pytest.mark.parametrize(
    ("argv", "service"),
    [
        (["celery", "-A", "app.celery_app", "beat", "--loglevel=info"], "beat"),
        (["celery", "--app=app.celery_app", "beat"], "beat"),
        (["celery", "-A", "app.celery_app", "-b", "redis://x", "beat"], "beat"),
        (["celery", "-A", "app.celery_app", "worker", "-Q", "dns"], "worker"),
        # A queue NAMED beat is still a worker; so is an embedded scheduler.
        (["celery", "-A", "app.celery_app", "worker", "-Q", "beat"], "worker"),
        (["celery", "-A", "app.celery_app", "worker", "-B"], "worker"),
    ],
)
def test_the_subcommand_names_the_service(argv: list[str], service: str):
    assert _celery_service(argv) == service


class _Task:
    name = "app.tasks.example"


def test_a_task_binds_its_id_and_clears_it_after():
    _bind_task_request_id(task_id="t-1", task=_Task())
    ctx = structlog.contextvars.get_contextvars()
    assert ctx["request_id"] == "t-1"
    assert ctx["task"] == "app.tasks.example"
    _unbind_task_request_id(task_id="t-1")
    assert "request_id" not in structlog.contextvars.get_contextvars()
    assert "task" not in structlog.contextvars.get_contextvars()


def test_an_eager_task_restores_its_callers_id():
    # .apply() / task_always_eager run the task inside an API request or
    # another task; clearing would leave the caller with no request_id.
    tokens = structlog.contextvars.bind_contextvars(request_id="outer-request")
    try:
        _bind_task_request_id(task_id="t-2", task=_Task())
        assert structlog.contextvars.get_contextvars()["request_id"] == "t-2"
        _unbind_task_request_id(task_id="t-2")
        assert structlog.contextvars.get_contextvars()["request_id"] == "outer-request"
        assert "task" not in structlog.contextvars.get_contextvars()
    finally:
        structlog.contextvars.reset_contextvars(**tokens)


def test_our_receiver_is_what_stops_celery_installing_its_own_logging():
    # A receiver on setup_logging stops Celery hijacking the root logger and
    # redirecting stdout, which would wrap each JSON line in a text one. It
    # must be OURS: another library's receiver would keep a bare
    # "any receivers" check green with ours removed.
    import weakref

    from celery.signals import setup_logging

    from app.celery_app import _configure_structured_logging

    connected = [
        ref() if isinstance(ref, weakref.ReferenceType) else ref
        for _key, ref in setup_logging.receivers
    ]
    assert _configure_structured_logging in connected


@pytest.fixture
def worker_logging(monkeypatch: pytest.MonkeyPatch):
    """configure_logging as the worker, writing into a buffer.

    Restores what it replaced — the structlog config, the root handlers and
    the root level — rather than resetting to defaults, so a later test sees
    the configuration it would have seen had this one never run.
    """
    from app import log as log_module

    saved_config = structlog.get_config()
    root = logging.getLogger()
    saved_handlers = list(root.handlers)
    saved_level = root.level
    monkeypatch.setattr(log_module.settings, "log_format", "json")
    monkeypatch.setattr(log_module.settings, "log_level", "INFO")
    buffer = io.StringIO()
    configure_logging(service="worker", stream=buffer)
    yield buffer
    root.handlers[:] = saved_handlers
    root.setLevel(saved_level)
    structlog.configure(**saved_config)


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


def test_a_more_verbose_loglevel_wins_and_a_quieter_one_does_not(worker_logging: io.StringIO):
    # Celery no longer applies --loglevel itself once we own setup_logging,
    # so configure_logging takes it: --loglevel=debug must still show debug,
    # and a quieter command-line default must not hide LOG_LEVEL's info.
    configure_logging(service="worker", stream=worker_logging, level="DEBUG")
    logging.getLogger("x").debug("debug-visible")
    configure_logging(service="worker", stream=worker_logging, level=logging.WARNING)
    logging.getLogger("x").info("info-still-visible")
    events = [line["event"] for line in _lines(worker_logging)]
    assert events == ["debug-visible", "info-still-visible"]


def test_logfile_receives_json_and_a_reconfigure_closes_the_old_handle(tmp_path, monkeypatch):
    from app import celery_app as capp
    from app import log as log_module

    saved_config = structlog.get_config()
    root = logging.getLogger()
    saved_handlers, saved_level = list(root.handlers), root.level
    monkeypatch.setattr(log_module.settings, "log_format", "json")
    try:
        first = tmp_path / "worker-1.log"
        capp._configure_structured_logging(loglevel=logging.INFO, logfile=str(first))
        handle = capp._LOGFILE_STREAM
        logging.getLogger("celery.app.trace").info("to the file")
        assert json.loads(first.read_text().splitlines()[-1])["event"] == "to the file"

        capp._configure_structured_logging(loglevel=logging.INFO, logfile=None)
        assert handle is not None and handle.closed
        assert capp._LOGFILE_STREAM is None
    finally:
        if capp._LOGFILE_STREAM is not None:
            capp._LOGFILE_STREAM.close()
            capp._LOGFILE_STREAM = None
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
        structlog.configure(**saved_config)
