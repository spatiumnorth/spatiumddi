"""Reading appliance log text takes ``admin`` on ``appliance`` and is redacted.

Host log files and pod logs carry whatever a process printed, including
connection strings, keys and tokens. A role holding only ``read`` on
``appliance`` (the builtin Viewer shape) can see the appliance's state but
not its raw log lines; a role holding ``admin`` can, and every line it
receives has been passed through the support bundle's secret redaction.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.appliance import containers as containers_route
from app.api.v1.appliance import diagnostics as diagnostics_route
from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User

DSN_LINE = "connecting to postgresql+asyncpg://spatium:hunter2-db-pass@db:5432/spatiumddi"
PEM_BLOCK = (
    "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
)
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl"
RAW_LOG = f"starting up\n{DSN_LINE}\n{PEM_BLOCK}\nbearer {JWT}\nready"

SECRETS = ("hunter2-db-pass", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", JWT)

LOG_ROUTES = (
    "/api/v1/appliance/diagnostics/logs",
    "/api/v1/appliance/diagnostics/logs/syslog",
    "/api/v1/appliance/containers/api-0/logs",
    "/api/v1/appliance/containers/api-0/logs/stream",
    "/api/v1/appliance/containers/workloads/api/logs/stream",
)


async def _headers(db: AsyncSession, action: str) -> dict[str, str]:
    """A non-superadmin holding ``action`` on ``appliance`` and nothing else."""
    user = User(
        username=f"u{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="n",
        hashed_password=hash_password("x"),
        is_superadmin=False,
        force_password_change=False,
    )
    db.add(user)
    await db.flush()
    role = Role(
        name=f"r-{uuid.uuid4().hex[:6]}",
        description="",
        permissions=[{"action": action, "resource_type": "appliance"}],
    )
    db.add(role)
    await db.flush()
    group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    group.roles = [role]
    group.users = [user]
    db.add(group)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.fixture
def stub_log_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every log source returns the same secret-bearing text."""

    async def _finite_stream(
        _name: str, tail: int = 100, container: str | None = None
    ) -> AsyncIterator[str]:
        yield RAW_LOG

    monkeypatch.setattr(diagnostics_route, "list_log_sources", lambda: ["syslog"])
    monkeypatch.setattr(diagnostics_route, "read_log_tail", lambda _n, lines=500: RAW_LOG)
    monkeypatch.setattr(containers_route, "get_container_logs", lambda _n, tail=200: RAW_LOG)
    monkeypatch.setattr(containers_route, "stream_container_logs", _finite_stream)
    monkeypatch.setattr(containers_route, "resolve_workload_pod", lambda _c: ("api-0", "api"))


@pytest.mark.usefixtures("stub_log_sources")
@pytest.mark.parametrize("path", LOG_ROUTES)
async def test_read_only_role_cannot_read_appliance_logs(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    headers = await _headers(db_session, "read")
    r = await client.get(path, headers=headers)
    assert r.status_code == 403, r.text


@pytest.mark.usefixtures("stub_log_sources")
@pytest.mark.parametrize("path", LOG_ROUTES)
async def test_admin_role_can_read_appliance_logs(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    headers = await _headers(db_session, "admin")
    r = await client.get(path, headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.usefixtures("stub_log_sources")
@pytest.mark.parametrize("path", LOG_ROUTES[1:])
async def test_appliance_log_text_is_redacted(
    client: AsyncClient, db_session: AsyncSession, path: str
) -> None:
    headers = await _headers(db_session, "admin")
    r = await client.get(path, headers=headers)
    assert r.status_code == 200, r.text
    body = r.text
    for secret in SECRETS:
        assert secret not in body, f"{secret!r} reached the response for {path}"
    # The rest of the log survives: redaction replaces the secret, not the line.
    assert "starting up" in body
    assert "ready" in body
    assert "db:5432" in body


async def test_read_only_role_still_sees_the_container_list(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the log text moves to ``admin``; the pod list stays ``read``."""
    monkeypatch.setattr(containers_route, "svc_list_containers", lambda: [])
    headers = await _headers(db_session, "read")
    r = await client.get("/api/v1/appliance/containers", headers=headers)
    assert r.status_code == 200, r.text


# ── Forms a log line takes ──────────────────────────────────────────────
#
# A process prints a credential in whatever form its library uses, and a
# private key arrives across several lines. Each form below is checked on
# every route that returns log text.

KEY_BODY = (
    "MIIEpAIBAAKCAQEAzK3yLogBodyLineOne0123456789abcdefghijklmnopqrstuv",
    "LogBodyLineTwo0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn",
    "TailQ==",
)


def _key(label: str) -> str:
    return "\n".join(
        (f"-----BEGIN {label}-----", *KEY_BODY, f"-----END {label}-----"),
    )


KEY_LABELS = (
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
)

# (name, log text, the secret that must not reach the response)
LOG_FORMS: tuple[tuple[str, str, str], ...] = (
    (
        "libpq keyword dsn",
        "dsn host=db port=5432 user=spatium password=kwpass-1 dbname=x",
        "kwpass-1",
    ),
    ("quoted keyword dsn", "connect: password='kwpass 2' host=db", "kwpass 2"),
    ("ado connection string", "Server=db;Database=x;Uid=sa;Pwd=kwpass-3;", "kwpass-3"),
    ("env assignment", "+ PGPASSWORD=kwpass-4 psql -h db", "kwpass-4"),
    ("prefixed env assignment", "POSTGRES_PASSWORD=kwpass-5", "kwpass-5"),
    ("json field", '{"event": "connect", "password": "kwpass-6"}', "kwpass-6"),
    ("escaped json field", '{"msg": "{\\"password\\": \\"kwpass-7\\"}"}', "kwpass-7"),
    ("yaml field", "  password: kwpass-8", "kwpass-8"),
    ("redis url", "redis://:kwpass-9@redis:6379/0", "kwpass-9"),
    ("rediss url", "rediss://default:kwpass-10@redis:6380", "kwpass-10"),
    ("amqp url", "amqp://guest:kwpass-11@rabbit:5672//", "kwpass-11"),
    ("mongodb srv url", "mongodb+srv://u:kwpass-12@c0.example.net/db", "kwpass-12"),
    ("mysql url", "mysql://root:kwpass-13@db/x", "kwpass-13"),
    *(
        (f"{label} block", f"loading key\n{_key(label)}\nkey loaded", "LogBodyLineTwo")
        for label in KEY_LABELS
    ),
    (
        "key in escaped json",
        '{"key": "' + _key("PRIVATE KEY").replace("\n", "\\n") + '"}',
        "LogBodyLineTwo",
    ),
    # A tail that starts inside a key has its END but not its BEGIN.
    (
        "key without begin",
        "\n".join((*KEY_BODY, "-----END PRIVATE KEY-----", "next")),
        "LogBodyLineTwo",
    ),
    # A tail that stops inside a key has its BEGIN but not its END.
    (
        "key without end",
        "\n".join(("first", "-----BEGIN PRIVATE KEY-----", *KEY_BODY[:2])),
        "LogBodyLineTwo",
    ),
)

TEXT_ROUTES = LOG_ROUTES[1:]


def _stub_text(monkeypatch: pytest.MonkeyPatch, text: str, *, line_per_chunk: bool) -> None:
    async def _stream(
        _name: str, tail: int = 100, container: str | None = None
    ) -> AsyncIterator[str]:
        if line_per_chunk:
            # What the pod-log source really does: one line per chunk.
            for line in text.split("\n"):
                yield line
        else:
            yield text

    monkeypatch.setattr(diagnostics_route, "read_log_tail", lambda _n, lines=500: text)
    monkeypatch.setattr(containers_route, "get_container_logs", lambda _n, tail=200: text)
    monkeypatch.setattr(containers_route, "stream_container_logs", _stream)
    monkeypatch.setattr(containers_route, "resolve_workload_pod", lambda _c: ("api-0", "api"))


@pytest.mark.parametrize("line_per_chunk", [True, False], ids=["line-chunks", "one-chunk"])
@pytest.mark.parametrize("path", TEXT_ROUTES)
@pytest.mark.parametrize(("form", "text", "secret"), LOG_FORMS, ids=[f[0] for f in LOG_FORMS])
async def test_every_log_form_is_redacted_on_every_route(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    form: str,
    text: str,
    secret: str,
    line_per_chunk: bool,
) -> None:
    if line_per_chunk and "stream" not in path:
        pytest.skip("chunking applies to the streams only")
    _stub_text(monkeypatch, text, line_per_chunk=line_per_chunk)
    headers = await _headers(db_session, "admin")
    r = await client.get(path, headers=headers)
    assert r.status_code == 200, r.text
    assert secret not in r.text, f"{form}: {secret!r} reached {path}"
    for line in KEY_BODY:
        assert line not in r.text, f"{form}: key body reached {path}"
    assert "[REDACTED]" in r.text


async def test_a_quiet_line_that_looks_like_base64_is_still_sent(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Held-back lines are released once the next line shows they were not
    a key, and at the end of the stream."""
    text = "digest\nAbCdEfGhIjKlMnOpQrStUvWxYz012345\nnext line\nZyXwVuTsRqPoNmLkJiHgFeDcBa543210"
    _stub_text(monkeypatch, text, line_per_chunk=True)
    headers = await _headers(db_session, "admin")
    r = await client.get(LOG_ROUTES[3], headers=headers)
    assert r.status_code == 200, r.text
    assert "AbCdEfGhIjKlMnOpQrStUvWxYz012345" in r.text
    assert "ZyXwVuTsRqPoNmLkJiHgFeDcBa543210" in r.text
    assert r.text.index("AbCdEf") < r.text.index("next line")


def test_the_diagnostic_bundle_redacts_a_key_split_by_the_tail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bundle's pod logs are a 500-line tail, which can start inside a key."""
    import io
    import zipfile
    from types import SimpleNamespace

    from app.services.appliance import diagnostics as diag_svc

    text = "\n".join((*KEY_BODY, "-----END PRIVATE KEY-----", "host=db password=bundlepw"))
    monkeypatch.setattr(diag_svc, "list_log_sources", lambda: [])
    monkeypatch.setattr(
        diag_svc, "list_containers", lambda: [SimpleNamespace(name="api-0", is_spatium=True)]
    )
    monkeypatch.setattr(diag_svc, "get_container_logs", lambda _n, tail=500: text)
    monkeypatch.setattr(diag_svc, "run_self_test", lambda: None)
    monkeypatch.setattr(diag_svc, "_format_self_test_report", lambda _r: "ok")
    blob = diag_svc.generate_diagnostic_bundle()
    pod_log = zipfile.ZipFile(io.BytesIO(blob)).read("pods/api-0.log").decode()
    for line in KEY_BODY:
        assert line not in pod_log
    assert "bundlepw" not in pod_log
