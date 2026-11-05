"""#3607: an HTML or empty answer must not empty a blocklist."""

from __future__ import annotations

import contextlib

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import safe_fetch
from app.models.dns import DNSBlockList, DNSBlockListEntry
from app.services.dns_blocklist import looks_like_html
from app.tasks import dns as dns_tasks

PUBLIC_IP = "93.184.216.34"
HTML = "<!DOCTYPE html>\n<html><body>Please log in</body></html>"


class _NullEngine:
    async def dispose(self) -> None:
        return None


async def _noop_publish(_channel: str) -> None:
    return None


def _wire(monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession, response) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        safe_fetch, "GuardedTransport", lambda **kw: httpx.MockTransport(lambda r: response)
    )
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)


async def _list(db: AsyncSession, *, with_entry: bool) -> DNSBlockList:
    bl = DNSBlockList(
        name="l", source_type="url", feed_url=f"https://{PUBLIC_IP}/l.txt", feed_format="domains"
    )
    db.add(bl)
    await db.flush()
    if with_entry:
        db.add(
            DNSBlockListEntry(
                list_id=bl.id, domain="keep.example.com", entry_type="block", source="feed"
            )
        )
    await db.commit()
    return bl


async def _domains(db: AsyncSession, bl: DNSBlockList) -> list[str]:
    rows = await db.execute(
        select(DNSBlockListEntry.domain).where(DNSBlockListEntry.list_id == bl.id)
    )
    return list(rows.scalars().all())


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="ads.example.com\n", headers={"content-type": "text/html"}),
        httpx.Response(200, text=HTML, headers={"content-type": "text/plain; charset=utf-8"}),
        httpx.Response(200, text="  \n" + HTML.lower(), headers={"content-type": "text/plain"}),
    ],
)
async def test_html_response_is_refused_and_entries_kept(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, response: httpx.Response
) -> None:
    _wire(monkeypatch, db_session, response)
    bl = await _list(db_session, with_entry=True)

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out["status"] == "error"
    await db_session.refresh(bl)
    assert bl.last_sync_status == "error"
    assert "web page" in (bl.last_sync_error or "")
    assert await _domains(db_session, bl) == ["keep.example.com"]


@pytest.mark.parametrize("body", ["", "   \n\n", "# nothing here\n! comment\n"])
async def test_empty_feed_on_populated_list_is_refused(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, body: str
) -> None:
    _wire(monkeypatch, db_session, httpx.Response(200, text=body))
    bl = await _list(db_session, with_entry=True)

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out["status"] == "error"
    await db_session.refresh(bl)
    assert bl.last_sync_status == "error"
    assert "no rules" in (bl.last_sync_error or "")
    assert await _domains(db_session, bl) == ["keep.example.com"]


async def test_empty_first_refresh_is_allowed_and_reported(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _wire(monkeypatch, db_session, httpx.Response(200, text="# empty\n"))
    bl = await _list(db_session, with_entry=False)

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out["status"] == "success"
    await db_session.refresh(bl)
    assert bl.last_sync_status == "success"
    assert "no rules" in (bl.last_sync_error or "")
    assert await _domains(db_session, bl) == []


async def test_normal_feed_is_unaffected(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _wire(
        monkeypatch,
        db_session,
        httpx.Response(200, text="new.example.com\n", headers={"content-type": "text/plain"}),
    )
    bl = await _list(db_session, with_entry=True)

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out["status"] == "success"
    await db_session.refresh(bl)
    assert bl.last_sync_error is None
    assert await _domains(db_session, bl) == ["new.example.com"]


def test_looks_like_html() -> None:
    assert looks_like_html("﻿  <HTML><head>")
    assert looks_like_html("<!doctype html>")
    assert not looks_like_html("<!-- c -->\nexample.com")
    assert not looks_like_html("example.com\n")
