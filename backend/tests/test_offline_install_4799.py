"""An install with no internet reads as healthy-but-unreachable (#4799).

Three messages used to read as faults on an air-gapped install: the
self-test resolved a public name, the release check stored a bare error
the UI painted amber, and the Releases tab blamed rate limiting while
logging a warning on every page view.
"""

from __future__ import annotations

import socket

import httpx
import pytest
from structlog.testing import capture_logs

from app.core.exc_text import check_error_kind
from app.services.appliance import diagnostics as diag
from app.services.appliance import releases as rel


def test_self_test_dns_check_passes_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the install's own name resolves; every external name fails."""

    def fake(name: str) -> str:
        if name == "cp.example.internal":
            return "10.0.0.5"
        raise socket.gaierror(-3, "Temporary failure in name resolution")

    monkeypatch.setattr(diag.settings, "appliance_hostname", "cp.example.internal")
    monkeypatch.setattr(socket, "gethostbyname", fake)
    check = diag._check_dns_resolves()
    assert check.ok is True
    assert "cp.example.internal" in check.detail
    assert "external DNS is not tested" in check.detail


def test_self_test_dns_check_fails_when_own_name_does_not_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake(name: str) -> str:
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(diag.settings, "appliance_hostname", "cp.example.internal")
    monkeypatch.setattr(socket, "gethostbyname", fake)
    check = diag._check_dns_resolves()
    assert check.ok is False


@pytest.mark.parametrize(
    ("error", "kind"),
    [
        (None, None),
        ("", None),
        ("HTTP 403", "http"),
        ("HTTP 500", "http"),
        ("Unreadable response: Expecting value", "http"),
        ("Could not connect to api.github.com:443: [Errno -3] Temporary failure", "unreachable"),
        ("ReadTimeout (the destination timed out)", "unreachable"),
    ],
)
def test_update_check_error_kind(error: str | None, kind: str | None) -> None:
    assert check_error_kind(error) == kind


class _Client:
    """``httpx.AsyncClient`` stand-in whose ``get`` raises or answers."""

    def __init__(self, behaviour: object) -> None:
        self.behaviour = behaviour
        self.calls = 0

    def __call__(self, *a: object, **k: object) -> _Client:
        return self

    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(self, *a: object) -> None:
        return None

    async def get(self, url: str, **k: object) -> httpx.Response:
        self.calls += 1
        if isinstance(self.behaviour, Exception):
            raise self.behaviour
        assert isinstance(self.behaviour, httpx.Response)
        self.behaviour.request = httpx.Request("GET", url)
        return self.behaviour


@pytest.fixture(autouse=True)
def _clean_caches():
    rel._RAW_CACHE.clear()
    rel._FAIL_CACHE.clear()
    yield
    rel._RAW_CACHE.clear()
    rel._FAIL_CACHE.clear()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("behaviour", "kind"),
    [
        (httpx.ConnectError("[Errno -3] Temporary failure in name resolution"), "unreachable"),
        (httpx.ConnectTimeout(""), "unreachable"),
        (httpx.Response(403), "rate_limited"),
        (httpx.Response(429), "rate_limited"),
        (httpx.Response(500), "error"),
    ],
)
async def test_releases_fetch_failure_kind(
    monkeypatch: pytest.MonkeyPatch, behaviour: object, kind: str
) -> None:
    monkeypatch.setattr(rel.httpx, "AsyncClient", _Client(behaviour))
    assert await rel.list_releases() == []
    assert rel.last_fetch_failure() == kind


@pytest.mark.asyncio
async def test_releases_failure_is_logged_and_fetched_once_per_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _Client(httpx.ConnectError("no route"))
    monkeypatch.setattr(rel.httpx, "AsyncClient", client)
    with capture_logs() as logs:
        for _ in range(5):
            assert await rel.list_releases() == []
    assert client.calls == 1
    failures = [e for e in logs if e["event"] == "appliance_releases_fetch_failed"]
    assert len(failures) == 1
    assert failures[0]["kind"] == "unreachable"
