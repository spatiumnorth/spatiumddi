"""Building a bundle never holds the API's event loop (#3310).

The api serves every request from one event loop, so a synchronous step
run on that loop holds every other request, ``/health/live`` included,
until it returns. A support bundle's host and runtime collectors (the
appliance self-test, pod logs through the kube API, host log files,
``/proc``, the environment), its safety-net sweep over the assembled
text, and the whole appliance diagnostics bundle are synchronous, so each
runs in a worker thread (non-negotiable #2). The DB-backed collectors
stay on the request's session.

Each contract test stubs a synchronous step to wait, briefly, for the
loop to do something else: a ticker coroutine to tick, or a
``GET /health/live`` to be answered. On the loop's own thread that cannot
happen, so the step times out and the test names it. In a worker thread
the loop answers at once. Two controls, which pass before and after the
change, hold the archive's files and a failed section's note to what
they were.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import threading
import time
import zipfile
from collections.abc import AsyncIterator, Callable, Coroutine
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services import support_bundle
from app.services.appliance import diagnostics as diag_svc
from app.services.support_bundle import collect, generate
from app.services.support_bundle import scrub as scrub_mod
from app.services.support_bundle.scrub import Scrubber, redact_secrets

# Long enough for a free loop to answer many times over, short enough
# that a held loop fails the test in about a second.
_WAIT_S = 0.5


class _LoopWatch:
    """Lets a synchronous step ask whether the event loop ran while it waited.

    Whatever runs on the loop (a ticker, or a poller after each answered
    request) sets ``beat``. A step clears it and waits: only a loop that is
    free while the step runs can set it again.
    """

    def __init__(self) -> None:
        self.beat = threading.Event()
        self.ran: list[str] = []
        self.held: list[str] = []
        self.bad_answers: list[str] = []
        self.most_at_once = 0
        self._running = 0
        self._lock = threading.Lock()

    def step(self, name: str) -> None:
        with self._lock:
            self.ran.append(name)
            self._running += 1
            self.most_at_once = max(self.most_at_once, self._running)
        try:
            self.beat.clear()
            if not self.beat.wait(_WAIT_S):
                self.held.append(name)
        finally:
            with self._lock:
                self._running -= 1

    async def tick(self) -> None:
        while True:
            self.beat.set()
            await asyncio.sleep(0.005)

    async def poll_live(self, client: AsyncClient) -> None:
        while True:
            resp = await client.get("/health/live")
            if resp.status_code == 200:
                self.beat.set()
            else:
                self.bad_answers.append(f"{resp.status_code} {resp.text[:200]}")
            await asyncio.sleep(0.005)


@contextlib.asynccontextmanager
async def _beside(coro: Coroutine[Any, Any, None]) -> AsyncIterator[None]:
    """Run ``coro`` on the loop for the duration of the block."""
    task = asyncio.create_task(coro)
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


def _stub(watch: _LoopWatch, name: str, value: Any) -> Callable[[Any], Any]:
    """A synchronous collector that takes ``scrub`` and returns ``value``."""

    def _collector(_scrub: Any) -> Any:
        watch.step(name)
        return value

    return _collector


async def _superadmin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="sb3310",
        email="sb3310@example.com",
        display_name="sb3310",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_active=True,
        is_superadmin=True,
        force_password_change=False,
        password_changed_at=datetime.now(UTC),
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


# The synchronous collectors generate() calls: attribute on ``collect``,
# the section name ``_safe`` records, and what the stub returns.
_SYNC_COLLECTORS: dict[str, tuple[str, Any]] = {
    "collect_self_test": ("self_test", "self-test stub"),
    "collect_environment": ("environment", "ENV_STUB=1"),
    "collect_proc": ("proc", {"proc/version": "proc stub"}),
    "collect_container_logs": ("pods", {"spatium-api-0.log": "pod log stub"}),
    "collect_host_logs": ("host_logs", {"syslog.log": "host log stub"}),
}


@pytest.mark.asyncio
async def test_no_synchronous_step_of_a_support_bundle_holds_the_loop(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    watch = _LoopWatch()
    for attr, (name, value) in _SYNC_COLLECTORS.items():
        monkeypatch.setattr(collect, attr, _stub(watch, name, value))

    # The safety net sweeps every section in turn; one call is enough to
    # show where the sweep runs.
    real_net = support_bundle.safety_net
    swept: list[str] = []

    def _net(path: str, value: str, report: Any) -> str:
        if not swept:
            watch.step("safety_net")
        swept.append(path)
        return real_net(path, value, report)

    monkeypatch.setattr(support_bundle, "safety_net", _net)

    async with _beside(watch.tick()):
        result = await generate(db_session, scrubbed=True)

    assert watch.held == [], f"these steps held the event loop while they ran: {watch.held}"
    assert watch.ran == [
        "self_test",
        "environment",
        "proc",
        "pods",
        "host_logs",
        "safety_net",
    ]
    # One Scrubber serves the whole build and it is not thread-safe, so
    # the steps still run one at a time, in the same order as before.
    assert watch.most_at_once == 1
    assert result.errors == []


def _returning(value: Any) -> Callable[[Any], Any]:
    """A synchronous collector that takes ``scrub`` and returns ``value`` at once."""

    def _collector(_scrub: Any) -> Any:
        return value

    return _collector


@pytest.mark.asyncio
async def test_a_support_bundle_holds_the_same_files_as_before(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    """The control: where the steps run changed, what the archive holds did not."""
    for attr, (_name, value) in _SYNC_COLLECTORS.items():
        monkeypatch.setattr(collect, attr, _returning(value))
    real_net = support_bundle.safety_net
    swept: list[str] = []

    def _net(path: str, value: str, report: Any) -> str:
        swept.append(path)
        return real_net(path, value, report)

    monkeypatch.setattr(support_bundle, "safety_net", _net)
    result = await generate(db_session, scrubbed=True)

    assert result.errors == []
    with zipfile.ZipFile(BytesIO(result.archive)) as zf:
        names = sorted(zf.namelist())
        assert zf.read("health/self-test.txt").decode() == "self-test stub"
        assert zf.read("system/env.txt").decode() == "ENV_STUB=1"
        assert zf.read("system/proc/version").decode() == "proc stub"
        assert zf.read("containers/spatium-api-0.log").decode() == "pod log stub"
        assert zf.read("logs/syslog.log").decode() == "host log stub"
        manifest = json.loads(zf.read("manifest.json"))
    assert names == [
        "activity/recent.log",
        "agents/servers.json",
        "alerts/events.json",
        "audit/recent.json",
        "config/feature-modules.json",
        "config/integrations.json",
        "config/platform-settings.json",
        "containers/spatium-api-0.log",
        "errors/internal-errors.json",
        "health/db-connections.json",
        "health/self-test.txt",
        "health/table-sizes.json",
        "logs/syslog.log",
        "manifest.json",
        "system/env.txt",
        "system/proc/version",
        "versions.json",
    ]
    # The safety net still sweeps every section once.
    assert sorted(swept) == [n for n in names if n != "manifest.json"]
    assert manifest["section_errors"] == []


@pytest.mark.asyncio
async def test_a_collector_that_raises_off_the_loop_is_recorded_as_before(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    """A section that fails is still a note in the bundle, never a 500."""

    def _unreachable(_scrub: Any) -> Any:
        raise RuntimeError("kubeapi unreachable")

    monkeypatch.setattr(collect, "collect_container_logs", _unreachable)
    result = await generate(db_session, scrubbed=True)

    assert result.errors == ["pods: RuntimeError: kubeapi unreachable"]
    with zipfile.ZipFile(BytesIO(result.archive)) as zf:
        note = zf.read("containers/_error.txt").decode()
        manifest = json.loads(zf.read("manifest.json"))
    assert note == "[section failed: RuntimeError: kubeapi unreachable]"
    assert manifest["section_errors"] == ["pods: RuntimeError: kubeapi unreachable"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/system/support-bundle/preview",
        "/api/v1/system/support-bundle",
        "/api/v1/system/support-bundle/decode-map",
    ],
)
async def test_the_api_answers_while_a_support_bundle_builds(
    path: str,
    monkeypatch: pytest.MonkeyPatch,
    db_session: AsyncSession,
    client: AsyncClient,
) -> None:
    watch = _LoopWatch()
    # Pod logs: one kube API read per pod, the longest part of a build on
    # an appliance.
    monkeypatch.setattr(
        collect,
        "collect_container_logs",
        _stub(watch, "pods", {"spatium-api-0.log": "pod log stub"}),
    )
    headers = await _superadmin_headers(db_session)

    async with _beside(watch.poll_live(client)):
        resp = await client.post(path, headers=headers, json={})

    assert resp.status_code == 200, resp.text
    assert watch.ran == ["pods"]
    assert watch.bad_answers == []
    assert watch.held == [], f"GET /health/live got no answer while {path} collected pod logs"


@pytest.mark.asyncio
async def test_the_api_answers_while_the_diagnostics_bundle_builds(
    monkeypatch: pytest.MonkeyPatch,
    db_session: AsyncSession,
    client: AsyncClient,
) -> None:
    watch = _LoopWatch()

    def _slow_self_test() -> diag_svc.SelfTestReport:
        # The issue's case: the host resolver does not answer.
        watch.step("self_test")
        return diag_svc.SelfTestReport(
            run_at=datetime.now(tz=UTC),
            overall_ok=False,
            checks=[
                diag_svc.CheckResult(
                    name="DNS resolution",
                    ok=False,
                    detail="registry-1.docker.io -> [Errno -3] Temporary failure in name resolution",
                )
            ],
        )

    monkeypatch.setattr(diag_svc, "run_self_test", _slow_self_test)
    monkeypatch.setattr(diag_svc, "list_log_sources", lambda: [])
    headers = await _superadmin_headers(db_session)

    async with _beside(watch.poll_live(client)):
        resp = await client.get("/api/v1/appliance/diagnostics/bundle", headers=headers)

    assert resp.status_code == 200, resp.text
    assert watch.ran == ["self_test"]
    assert watch.bad_answers == []
    assert (
        watch.held == []
    ), "GET /health/live got no answer while the diagnostics bundle ran its self-test"
    with zipfile.ZipFile(BytesIO(resp.content)) as zf:
        assert "Overall: FAIL" in zf.read("self-test.txt").decode()


# ── The second cause: a large host log scrubbed in one piece ──────────────
#
# Each scrub pattern is one regex pass, and one pass over a whole host log
# is one C call that holds the GIL until it returns, so even from a worker
# thread it stops the event loop for as long as that pass runs: about 85 ms
# per MB of log for the slowest pass, where this was measured (a 31.5 MB
# log held the loop 2.7 s). Over this 6 MB log the loop went about 550 ms
# without running when each pass took the whole log, and at most about
# 60 ms when the passes took it in pieces (that much is the thread switch
# on the machine it was measured on, not the passes).
_LARGE_LOG_BYTES = 6 * 1024 * 1024
_LONGEST_GAP_S = 0.25


def _write_large_log(path: Path, size: int = _LARGE_LOG_BYTES) -> None:
    """An appliance-shaped request log: an address and a name on every line."""
    lines: list[str] = []
    total = i = 0
    while total < size:
        line = (
            f"2026-11-02T08:{i % 60:02d}:{i % 60:02d}.123456Z INFO  [api] "
            f"request_id={i * 2654435761 % 2**64:016x} method=GET "
            f"path=/api/v1/ipam/subnets/{i} status=200 "
            f"client=10.{i % 250}.{i * 7 % 250}.{i * 13 % 250} "
            f"host=dns{i % 9}.corp.example.net duration_ms={i % 97}.{i % 10}\n"
        )
        lines.append(line)
        total += len(line)
        i += 1
    path.write_text("".join(lines), encoding="utf-8")


class _GapWatch:
    """The longest the event loop went without running, while a block runs."""

    def __init__(self) -> None:
        self.longest = 0.0

    async def tick(self) -> None:
        last = time.perf_counter()
        while True:
            await asyncio.sleep(0.001)
            now = time.perf_counter()
            self.longest = max(self.longest, now - last)
            last = now


def _passing_self_test() -> diag_svc.SelfTestReport:
    return diag_svc.SelfTestReport(run_at=datetime.now(tz=UTC), overall_ok=True, checks=[])


def _only_host_logs(monkeypatch: pytest.MonkeyPatch, log_dir: Path) -> None:
    """Point the host collectors at ``log_dir`` and stub every other synchronous one."""
    monkeypatch.setattr(diag_svc, "_log_dir", lambda: log_dir)
    for attr, (_name, value) in _SYNC_COLLECTORS.items():
        if attr != "collect_host_logs":
            monkeypatch.setattr(collect, attr, _returning(value))


@pytest.mark.asyncio
async def test_a_large_host_log_does_not_hold_the_loop_while_a_support_bundle_scrubs_it(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession, tmp_path: Path
) -> None:
    _write_large_log(tmp_path / "spatiumddi.log")
    _only_host_logs(monkeypatch, tmp_path)
    gaps = _GapWatch()

    async with _beside(gaps.tick()):
        result = await generate(db_session, scrubbed=True)

    assert result.errors == []
    assert "logs/spatiumddi.log" in {f.path for f in result.files}
    assert gaps.longest < _LONGEST_GAP_S, (
        f"the event loop went {gaps.longest * 1000:.0f} ms without running while a support "
        f"bundle scrubbed a {_LARGE_LOG_BYTES >> 20} MB host log"
    )


@pytest.mark.asyncio
async def test_a_large_host_log_does_not_hold_the_loop_while_the_diagnostics_bundle_redacts_it(
    monkeypatch: pytest.MonkeyPatch,
    db_session: AsyncSession,
    client: AsyncClient,
    tmp_path: Path,
) -> None:
    _write_large_log(tmp_path / "spatiumddi.log")
    monkeypatch.setattr(diag_svc, "_log_dir", lambda: tmp_path)
    monkeypatch.setattr(diag_svc, "run_self_test", _passing_self_test)
    monkeypatch.setattr(diag_svc, "list_containers", lambda: [])
    headers = await _superadmin_headers(db_session)
    gaps = _GapWatch()

    async with _beside(gaps.tick()):
        resp = await client.get("/api/v1/appliance/diagnostics/bundle", headers=headers)

    assert resp.status_code == 200, resp.text
    with zipfile.ZipFile(BytesIO(resp.content)) as zf:
        assert "logs/spatiumddi.log" in zf.namelist()
    assert gaps.longest < _LONGEST_GAP_S, (
        f"the event loop went {gaps.longest * 1000:.0f} ms without running while the "
        f"diagnostics bundle redacted a {_LARGE_LOG_BYTES >> 20} MB host log"
    )


# Every line-local shape the scrubber knows, each on lines of varied length,
# so that piece boundaries fall all over them.
_SHAPES = (
    "token=gAAAAABm" + "A" * 40,
    "hash $2b$12$" + "a" * 53,
    "hash $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$abcdefghijklmnopqrstuv",
    "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n",
    "dsn postgresql+asyncpg://spatium:hunter2@db.corp.example.com/spatiumddi",
    "cache redis://:s3cr3t@redis.corp.example.com:6379/0",
    "notify https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX",
    "notify https://discord.com/api/webhooks/123456/abcDEF_-xyz",
    "notify https://contoso.webhook.office.com/webhookb2/abc@xyz/IncomingWebhook/1/2",
    "flow https://x.logic.azure.com/workflows/1/invoke?api-version=1&sig=AbCdEf123",
    "get https://b.s3.amazonaws.com/k?X-Amz-Credential=AKIA2026&X-Amz-Signature=ab01",
    "store AccountName=acct;AccountKey=abc123+/==;EndpointSuffix=core.windows.net",
    'cfg PGPASSWORD=hunter2 password: "p@ss w" api_key=abcd1234 {"secret": "xyz"}',
    "lease 10.1.2.3 in 192.168.10.0/24 via 203.0.113.9 to 52:54:00:12:34:56",
    "v6 2001:db8:9::1 2600:1f18:abcd::42/64 fe80::1 mac AA-BB-CC-DD-EE-FF",
    "dns api.corp.example.com ns1.example.co.uk naïve façade ✓",
)


def _varied_log(lines: int = 6000, *, crlf: bool = False) -> str:
    out = []
    for i in range(lines):
        end = "\r" if crlf and i % 7 == 0 else ""
        pad = "x" * (i * 37 % 120)
        out.append(
            f"2026-11-02T08:00:{i % 60:02d}Z worker[{i}] {pad} {_SHAPES[i % len(_SHAPES)]}{end}"
        )
    return "\n".join(out) + "\n"


@pytest.mark.asyncio
async def test_a_support_bundle_keeps_the_same_host_log_as_before(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession, tmp_path: Path
) -> None:
    """The control: the archive's host log is what one scrub of the whole file gave."""
    path = tmp_path / "spatiumddi.log"
    path.write_text(_varied_log(), encoding="utf-8")
    raw = path.read_text(encoding="utf-8", errors="replace")
    _only_host_logs(monkeypatch, tmp_path)
    # Small pieces, for many boundaries (a no-op where nothing reads it).
    monkeypatch.setattr(scrub_mod, "_PIECE_CHARS", 4096, raising=False)

    result = await generate(db_session, scrubbed=True)

    with zipfile.ZipFile(BytesIO(result.archive)) as zf:
        kept = zf.read("logs/spatiumddi.log").decode()
    assert kept == redact_secrets(collect.cap(Scrubber().text(raw), collect.CAP_LOG_BYTES))[0]


def test_the_diagnostics_bundle_keeps_the_same_host_log_as_before(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The control: the archive's host log is what one redaction of the whole file gave."""
    path = tmp_path / "spatiumddi.log"
    path.write_text(_varied_log(), encoding="utf-8")
    raw = path.read_text(encoding="utf-8", errors="replace")
    monkeypatch.setattr(diag_svc, "_log_dir", lambda: tmp_path)
    monkeypatch.setattr(diag_svc, "run_self_test", _passing_self_test)
    monkeypatch.setattr(diag_svc, "list_containers", lambda: [])
    monkeypatch.setattr(scrub_mod, "_PIECE_CHARS", 4096, raising=False)

    blob = diag_svc.generate_diagnostic_bundle()

    with zipfile.ZipFile(BytesIO(blob)) as zf:
        assert zf.read("logs/spatiumddi.log").decode() == redact_secrets(raw)[0]


def test_a_text_scrubbed_in_pieces_comes_out_as_it_does_whole(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same text, the same report and the same decode map, whole or in pieces."""
    monkeypatch.setattr(scrub_mod, "_PIECE_CHARS", 4096)
    text = _varied_log(crlf=True)
    assert len(scrub_mod._line_pieces(text)) > 100

    whole, pieces = Scrubber(seed="s"), Scrubber(seed="s")
    assert pieces.text(text, in_pieces=True) == whole.text(text)
    assert pieces.report == whole.report
    assert pieces.decode_map() == whole.decode_map()
    assert redact_secrets(text, in_pieces=True) == redact_secrets(text)

    # A private key spans lines, so a text that holds one is never cut.
    key = "-----BEGIN PRIVATE KEY-----\n" + "MIIEv" * 12 + "\n" + "Qk0" * 20 + "\n"
    key += "-----END PRIVATE KEY-----\n"
    mid = text.index("\n", len(text) // 2) + 1
    keyed = text[:mid] + key + text[mid:]
    assert scrub_mod._line_pieces(keyed) == [keyed]
    assert redact_secrets(keyed, in_pieces=True) == redact_secrets(keyed)
    assert "MIIEv" not in redact_secrets(keyed, in_pieces=True)[0]
