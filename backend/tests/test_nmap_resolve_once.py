"""A hostname target is resolved once, and nmap is handed the checked address."""

from __future__ import annotations

import asyncio
import socket
from typing import Any

import pytest

from app.services.nmap import runner
from app.services.nmap.runner import NmapArgError, resolve_target


def _fake_getaddrinfo(answers: list[list[str]], calls: list[str]) -> Any:
    async def fake(self: Any, host: str, port: Any, **kw: Any) -> list[tuple]:
        calls.append(host)
        addrs = answers[min(len(calls) - 1, len(answers) - 1)]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addrs]

    return fake


@pytest.mark.asyncio
async def test_hostname_resolved_once_and_checked_address_returned(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        asyncio.get_running_loop().__class__,
        "getaddrinfo",
        _fake_getaddrinfo([["10.1.2.3"], ["127.0.0.1"]], calls),
    )
    assert await resolve_target("router1.lan") == "10.1.2.3"
    assert calls == ["router1.lan"]


@pytest.mark.asyncio
async def test_hostname_with_a_blocked_answer_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(
        asyncio.get_running_loop().__class__,
        "getaddrinfo",
        _fake_getaddrinfo([["10.1.2.3", "169.254.169.254"]], []),
    )
    with pytest.raises(NmapArgError):
        await resolve_target("mixed.example.com")


@pytest.mark.asyncio
async def test_literals_and_cidrs_pass_through() -> None:
    assert await resolve_target("10.0.0.5") == "10.0.0.5"
    assert await resolve_target("10.0.0.0/24") == "10.0.0.0/24"


def test_validate_target_does_not_resolve(monkeypatch) -> None:
    def boom(*a: Any, **k: Any) -> None:
        raise AssertionError("synchronous lookup")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    assert runner._validate_target("router1.lan") == "router1.lan"  # noqa: SLF001
