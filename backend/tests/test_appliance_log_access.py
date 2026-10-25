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


# ── One-shot windows that fall inside a key ─────────────────────────────
#
# A log that ends inside a private key (the process printed the BEGIN line
# and part of the body, no END yet). A short window then holds body lines
# and neither marker, so the one-shot views read back past the window.

OPEN_KEY_BODY = tuple(
    f"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAt{n:07d}" for n in range(10)
)
OPEN_KEY_LOG = "\n".join(
    (
        "starting",
        "listening on 8080",
        "worker ready",
        "before",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        *OPEN_KEY_BODY,
    )
)
ONE_SHOT = (
    ("/api/v1/appliance/diagnostics/logs/syslog", "lines"),
    ("/api/v1/appliance/containers/api-0/logs", "tail"),
)


def _stub_tail(monkeypatch: pytest.MonkeyPatch, text: str) -> None:
    """Sources that honour the requested line count, like the real ones."""
    log_lines = text.split("\n")

    def _last(n: int) -> str:
        return "\n".join(log_lines[-n:])

    monkeypatch.setattr(diagnostics_route, "read_log_tail", lambda _n, lines=500: _last(lines))
    monkeypatch.setattr(
        containers_route, "get_container_logs", lambda _n, tail=200: _last(tail) + "\n"
    )


@pytest.mark.parametrize("window", [5, 11, 14])
@pytest.mark.parametrize(("path", "param"), ONE_SHOT)
async def test_a_window_inside_an_unterminated_key_is_redacted(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    param: str,
    window: int,
) -> None:
    _stub_tail(monkeypatch, OPEN_KEY_LOG)
    headers = await _headers(db_session, "admin")
    r = await client.get(path, params={param: window}, headers=headers)
    assert r.status_code == 200, r.text
    for line in OPEN_KEY_BODY:
        assert line not in r.text, f"key body reached {path} with a {window}-line window"
    assert "[REDACTED]:pem" in r.text
    tail = r.json()["tail"]
    assert len(tail.splitlines()) <= window


@pytest.mark.parametrize(("path", "param"), ONE_SHOT)
async def test_base64_lines_that_are_not_a_key_are_still_shown(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    param: str,
) -> None:
    ordinary = (
        "image digest sha256 0123456789abcdef0123456789abcdef",
        "QWxhZGRpbjpvcGVuIHNlc2FtZQ0123456789abcdef",
        "token cache refreshed",
        "ZGlzdHJpYnV0ZWQgY29uZmlnIGJsb2I0123456789",
        "c2Vzc2lvbiByZXN1bWVkIGNsZWFubHk0123456789",
    )
    _stub_tail(monkeypatch, "\n".join(("boot", *ordinary)))
    headers = await _headers(db_session, "admin")
    r = await client.get(path, params={param: 5}, headers=headers)
    assert r.status_code == 200, r.text
    assert r.json()["tail"].splitlines() == list(ordinary)


def test_a_tail_whose_key_began_before_the_context_is_dropped() -> None:
    """When even the context starts inside a key, its leading body run goes."""
    from app.services.support_bundle.scrub import redact_log_tail

    text = "\n".join((*OPEN_KEY_BODY, "after the key"))
    assert redact_log_tail(text, 3, requested=len(OPEN_KEY_BODY) + 1) == "after the key"
    # The same text read whole (fewer lines than requested) is the start of
    # the log, so nothing is dropped on that ground.
    assert OPEN_KEY_BODY[-1] in redact_log_tail(text, 3, requested=100)


def test_the_bundle_pod_log_is_read_with_context(monkeypatch: pytest.MonkeyPatch) -> None:
    """The bundle's 500-line pod tail is read with context and trimmed after
    redacting, like the one-shot views."""
    import io
    import zipfile
    from types import SimpleNamespace

    from app.services.appliance import diagnostics as diag_svc

    # A log that ends inside a key, longer than the 500-line window.
    log_lines = [f"line {n}" for n in range(1000)] + OPEN_KEY_LOG.split("\n")
    requested: list[int] = []

    def _logs(_n: str, tail: int = 500) -> str:
        requested.append(tail)
        return "\n".join(log_lines[-tail:])

    monkeypatch.setattr(diag_svc, "list_log_sources", lambda: [])
    monkeypatch.setattr(
        diag_svc, "list_containers", lambda: [SimpleNamespace(name="api-0", is_spatium=True)]
    )
    monkeypatch.setattr(diag_svc, "get_container_logs", _logs)
    monkeypatch.setattr(diag_svc, "run_self_test", lambda: None)
    monkeypatch.setattr(diag_svc, "_format_self_test_report", lambda _r: "ok")
    blob = diag_svc.generate_diagnostic_bundle()
    pod_log = zipfile.ZipFile(io.BytesIO(blob)).read("pods/api-0.log").decode()
    assert requested and requested[0] > 500
    assert len(pod_log.splitlines()) <= 500
    for line in OPEN_KEY_BODY:
        assert line not in pod_log


# ── A key whose last body line is short ─────────────────────────────────
#
# A body line is recognised by a 16-character base64 token, and a key's
# last line is usually shorter. With no END after it, the BEGIN branch of
# the fragment pass has to take that line by its shape: a base64 token
# shorter than the full-width lines, with the same log prefix in front.

SHORT_LAST = "AAAAC3NzaC1l"  # 12 characters
SHORT_KEY_BODY = (*OPEN_KEY_BODY[:9], SHORT_LAST)
SHORT_KEY_LOG = "\n".join(
    (
        "starting",
        "listening on 8080",
        "worker ready",
        "before",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        *SHORT_KEY_BODY,
    )
)


@pytest.mark.parametrize("window", [5, 11, 12, 14])
@pytest.mark.parametrize(("path", "param"), ONE_SHOT)
async def test_a_short_last_key_line_is_not_shown_after_the_marker(
    client: AsyncClient,
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
    param: str,
    window: int,
) -> None:
    _stub_tail(monkeypatch, SHORT_KEY_LOG)
    headers = await _headers(db_session, "admin")
    r = await client.get(path, params={param: window}, headers=headers)
    assert r.status_code == 200, r.text
    for line in SHORT_KEY_BODY:
        assert line not in r.text, f"{line!r} reached {path} with a {window}-line window"
    tail = r.json()["tail"]
    assert tail.splitlines()[-1].endswith("[REDACTED]:pem")
    assert len(tail.splitlines()) <= window


def test_the_diagnostic_bundle_hides_a_short_last_key_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import io
    import zipfile
    from types import SimpleNamespace

    from app.services.appliance import diagnostics as diag_svc

    log_lines = SHORT_KEY_LOG.split("\n")
    monkeypatch.setattr(diag_svc, "list_log_sources", lambda: [])
    monkeypatch.setattr(
        diag_svc, "list_containers", lambda: [SimpleNamespace(name="api-0", is_spatium=True)]
    )
    monkeypatch.setattr(
        diag_svc, "get_container_logs", lambda _n, tail=500: "\n".join(log_lines[-tail:])
    )
    monkeypatch.setattr(diag_svc, "run_self_test", lambda: None)
    monkeypatch.setattr(diag_svc, "_format_self_test_report", lambda _r: "ok")
    blob = diag_svc.generate_diagnostic_bundle()
    pod_log = zipfile.ZipFile(io.BytesIO(blob)).read("pods/api-0.log").decode()
    for line in SHORT_KEY_BODY:
        assert line not in pod_log
    assert "[REDACTED]:pem" in pod_log


@pytest.mark.parametrize("trailing_newline", [False, True])
def test_a_short_last_key_line_that_ends_the_text_is_removed(trailing_newline: bool) -> None:
    from app.services.support_bundle.scrub import redact_secrets

    text = SHORT_KEY_LOG + ("\n" if trailing_newline else "")
    out = redact_secrets(text)[0]
    assert SHORT_LAST not in out
    assert out.rstrip("\n").endswith("[REDACTED]:pem")
    assert out.startswith("starting\nlistening on 8080\nworker ready\nbefore\n")


def test_a_log_line_after_a_short_last_key_line_is_kept() -> None:
    from app.services.support_bundle.scrub import redact_log_tail, redact_secrets

    text = SHORT_KEY_LOG + "\nserver started on port 8080\nready"
    out = redact_secrets(text)[0]
    assert SHORT_LAST not in out
    assert out.endswith("[REDACTED]:pem\nserver started on port 8080\nready")
    tail = redact_log_tail(text, 3, requested=100).split("\n")
    assert tail[0].endswith("[REDACTED]:pem")
    assert tail[1:] == ["server started on port 8080", "ready"]


def test_a_log_line_right_after_the_full_width_lines_is_kept() -> None:
    """No short last line: the ordinary line after the key is not taken
    for one, since it says more than one base64-shaped word."""
    from app.services.support_bundle.scrub import redact_secrets

    text = "\n".join(("-----BEGIN PRIVATE KEY-----", *OPEN_KEY_BODY[:3], "worker ready", "done"))
    out = redact_secrets(text)[0].split("\n")
    assert out[-2:] == ["worker ready", "done"]
    for line in OPEN_KEY_BODY[:3]:
        assert line not in "\n".join(out)


def test_a_prefixed_short_last_key_line_is_removed_and_the_next_line_kept() -> None:
    """Body lines behind a container-runtime prefix: the short last line has
    the same prefix and goes; a log line behind that prefix says more and
    stays."""
    from app.services.support_bundle.scrub import redact_secrets

    def stamp(n: int, msg: str) -> str:
        return f"2026-10-24T10:00:{n:02d}.123456789Z stdout F {msg}"

    lines = [stamp(0, "-----BEGIN OPENSSH PRIVATE KEY-----")]
    lines += [stamp(n + 1, body) for n, body in enumerate(SHORT_KEY_BODY)]
    lines.append(stamp(30, "listening on 8080"))
    out = redact_secrets("\n".join(lines))[0]
    for body in SHORT_KEY_BODY:
        assert body not in out
    assert out.endswith(stamp(30, "listening on 8080"))


def test_a_short_word_with_a_different_prefix_is_kept() -> None:
    from app.services.support_bundle.scrub import redact_secrets

    text = "\n".join(
        ("-----BEGIN PRIVATE KEY-----", *OPEN_KEY_BODY[:2], "INFO done", "kernel: eth0 up")
    )
    out = redact_secrets(text)[0].split("\n")
    assert out[-2:] == ["INFO done", "kernel: eth0 up"]


def test_a_short_last_key_line_before_an_end_is_still_removed() -> None:
    from app.services.support_bundle.scrub import redact_secrets

    text = "\n".join((*SHORT_KEY_BODY, "-----END OPENSSH PRIVATE KEY-----", "next"))
    out = redact_secrets(text)[0]
    for line in SHORT_KEY_BODY:
        assert line not in out
    assert out.endswith("[REDACTED]:pem\nnext")


def test_the_stream_hides_a_short_last_key_line() -> None:
    from app.services.support_bundle.scrub import LogStreamRedactor

    # BEGIN with no END: everything after the marker is withheld.
    r = LogStreamRedactor()
    sent = []
    for line in SHORT_KEY_LOG.split("\n"):
        sent += r.feed(line)
    sent += r.flush()
    joined = "\n".join(sent)
    for line in SHORT_KEY_BODY:
        assert line not in joined
    assert sent[-1].endswith("[REDACTED]:pem")

    # END with no BEGIN: the held body, short last line included, is dropped.
    r = LogStreamRedactor()
    sent = []
    for line in (*SHORT_KEY_BODY, "-----END OPENSSH PRIVATE KEY-----", "next"):
        sent += r.feed(line)
    sent += r.flush()
    joined = "\n".join(sent)
    for line in SHORT_KEY_BODY:
        assert line not in joined
    assert sent[-1] == "next"


def test_a_tail_starting_inside_a_key_drops_its_short_last_line() -> None:
    from app.services.support_bundle.scrub import redact_log_tail

    text = "\n".join((*SHORT_KEY_BODY, "after the key"))
    assert redact_log_tail(text, 3, requested=len(SHORT_KEY_BODY) + 1) == "after the key"
