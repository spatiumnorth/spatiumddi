"""A hosts / domains list fed an adblock file stores junk (#3531).

Every ``||name^`` rule used to be stored verbatim as a "name", so nothing was
blocked and the refresh reported success. The parser now validates each token,
reports a wrong-format feed, and the refresh refuses it, keeping the entries
the list already had.
"""

from __future__ import annotations

import contextlib

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import safe_fetch
from app.models.dns import DNSBlockList, DNSBlockListEntry
from app.services.dns_blocklist import parse_feed_detailed
from app.tasks import dns as dns_tasks

PUBLIC_IP = "93.184.216.34"

ADBLOCK = "! Title: x\n||ads.example.com^\n||tracker.example.net^$important\n@@||ok.example.org^\n"


@pytest.mark.parametrize("fmt", ["hosts", "domains"])
def test_adblock_content_is_reported_not_stored(fmt: str) -> None:
    parsed = parse_feed_detailed(ADBLOCK, fmt)
    assert parsed.format_mismatch == "adblock"
    assert parsed.domains == []


def test_invalid_tokens_are_skipped_and_counted() -> None:
    hosts = "0.0.0.0 good.example.com\n0.0.0.0 0.0.0.0\n0.0.0.0 bad/path.example.com\n"
    parsed = parse_feed_detailed(hosts, "hosts")
    assert parsed.format_mismatch is None
    assert parsed.domains == ["good.example.com"]
    assert parsed.skipped is not None and parsed.skipped.invalid_name == 2
    assert parsed.skipped.total == 2

    domains = "a.example.com\n*.b.example.com\n1.2.3.4\nwith space.example.com\n"
    parsed = parse_feed_detailed(domains, "domains")
    # "with space.example.com" reads as the token "with", which has no dot.
    assert parsed.domains == ["a.example.com", "b.example.com"]
    assert parsed.skipped is not None and parsed.skipped.invalid_name == 1


def test_valid_feeds_parse_as_before() -> None:
    hosts = "# c\n127.0.0.1 localhost\n0.0.0.0 ads.example.com # x\n0.0.0.0 t.example.net\n"
    p = parse_feed_detailed(hosts, "hosts")
    assert p.domains == ["ads.example.com", "t.example.net"]
    assert p.format_mismatch is None
    assert p.skipped is None
    d = parse_feed_detailed("a.example.com\n*.b.example.com\n", "domains")
    assert d.domains == ["a.example.com", "b.example.com"]
    assert d.wildcard_count == 1


class _NullEngine:
    async def dispose(self) -> None:
        return None


async def _noop_publish(_channel: str) -> None:
    return None


@pytest.mark.parametrize("fmt", ["hosts", "domains"])
async def test_refresh_refuses_wrong_format_and_keeps_entries(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, fmt: str
) -> None:
    url = f"https://{PUBLIC_IP}/list.txt"
    monkeypatch.setattr(
        safe_fetch,
        "GuardedTransport",
        lambda **kw: httpx.MockTransport(lambda r: httpx.Response(200, text=ADBLOCK)),
    )
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)

    bl = DNSBlockList(name="mm", source_type="url", feed_url=url, feed_format=fmt)
    db_session.add(bl)
    await db_session.flush()
    db_session.add(
        DNSBlockListEntry(
            list_id=bl.id, domain="keep.example.com", entry_type="block", source="feed"
        )
    )
    await db_session.commit()

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out["status"] == "error"
    await db_session.refresh(bl)
    assert bl.last_sync_status == "error"
    assert "adblock" in (bl.last_sync_error or "")
    domains = (
        (
            await db_session.execute(
                select(DNSBlockListEntry.domain).where(DNSBlockListEntry.list_id == bl.id)
            )
        )
        .scalars()
        .all()
    )
    assert domains == ["keep.example.com"]
