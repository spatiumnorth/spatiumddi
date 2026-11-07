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
from app.core.dns_names import validate_fqdn
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
    hosts = "0.0.0.0 good.example.com\n0.0.0.0 bad/path.example.com\n0.0.0.0 a\\b.example.com\n"
    parsed = parse_feed_detailed(hosts, "hosts")
    assert parsed.format_mismatch is None
    assert parsed.domains == ["good.example.com"]
    assert parsed.skipped is not None and parsed.skipped.invalid_name == 2
    assert parsed.skipped.total == 2
    assert parsed.skipped.as_dict()["invalid_name"] == 2

    domains = "a.example.com\n*.b.example.com\n-lead.example.com\nwith space.example.com\n"
    parsed = parse_feed_detailed(domains, "domains")
    # "with space.example.com" reads as the token "with", which has no dot.
    assert parsed.domains == ["a.example.com", "b.example.com"]
    assert parsed.skipped is not None and parsed.skipped.invalid_name == 1


def test_ip_literals_are_boilerplate_not_skipped_rules() -> None:
    # StevenBlack's header carries ``0.0.0.0 0.0.0.0``; counting it would put
    # a permanent "1 skipped" banner on every StevenBlack list.
    hosts = "0.0.0.0 0.0.0.0\n127.0.0.1 localhost\n::1 ip6-localhost\n0.0.0.0 ads.example.com\n"
    parsed = parse_feed_detailed(hosts, "hosts")
    assert parsed.domains == ["ads.example.com"]
    assert parsed.skipped is None
    parsed = parse_feed_detailed("1.2.3.4\nads.example.com\n", "domains")
    assert parsed.domains == ["ads.example.com"]
    assert parsed.skipped is None


def test_names_validate_fqdn_accepts_are_kept() -> None:
    # Shapes real catalog feeds carry; each was stored before #3531 and is a
    # name ``validate_fqdn`` accepts, so the new check must keep it.
    feed = (
        "anitokyo.t\n"  # single-character last label (StevenBlack adult)
        "_dmarc.example.com\n"
        "xn--bcher-kva.example\n"
        "Upper.Example.COM.\n"
        "a_b-c.example.net\n"
    )
    parsed = parse_feed_detailed(feed, "domains")
    assert parsed.domains == [
        "anitokyo.t",
        "_dmarc.example.com",
        "xn--bcher-kva.example",
        "upper.example.com",
        "a_b-c.example.net",
    ]
    assert parsed.skipped is None
    for name in parsed.domains:
        assert validate_fqdn(name) == name


def test_hosts_content_in_a_domains_list_is_reported() -> None:
    # Read as domains, each line's first token is the address, so every line
    # would be dropped and the refresh would empty the list.
    hosts = "# StevenBlack\n0.0.0.0 0.0.0.0\n0.0.0.0 ads.example.com\n0.0.0.0 t.example.net\n"
    parsed = parse_feed_detailed(hosts, "domains")
    assert parsed.format_mismatch == "hosts"
    assert parsed.domains == []
    # The other way round is fine: a hosts list reads a bare name per line.
    assert parse_feed_detailed("ads.example.com\nt.example.net\n", "hosts").domains == [
        "ads.example.com",
        "t.example.net",
    ]


def test_comment_heavy_hosts_file_is_not_a_mismatch() -> None:
    header = "".join(f"# line {i}\n\n! note\n[section]\n" for i in range(500))
    hosts = header + "0.0.0.0 ads.example.com\n"
    parsed = parse_feed_detailed(hosts, "hosts")
    assert parsed.format_mismatch is None
    assert parsed.domains == ["ads.example.com"]
    # A minority of adblock lines is counted, not refused.
    mixed = "0.0.0.0 a.example.com\n0.0.0.0 b.example.com\n||c.example.com^\n"
    parsed = parse_feed_detailed(mixed, "hosts")
    assert parsed.format_mismatch is None
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


async def test_first_refresh_of_a_wrong_format_list_says_why(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A brand-new list with no entries: the operator sees an error naming the
    format to switch to, not a successful sync of zero entries."""
    hosts = "0.0.0.0 ads.example.com\n0.0.0.0 t.example.net\n"
    monkeypatch.setattr(
        safe_fetch,
        "GuardedTransport",
        lambda **kw: httpx.MockTransport(lambda r: httpx.Response(200, text=hosts)),
    )
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)

    bl = DNSBlockList(
        name="new", source_type="url", feed_url=f"https://{PUBLIC_IP}/h", feed_format="domains"
    )
    db_session.add(bl)
    await db_session.commit()

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out["status"] == "error"
    await db_session.refresh(bl)
    assert bl.last_sync_status == "error"
    assert "hosts format" in (bl.last_sync_error or "")
    assert "Change the list's feed format to hosts" in (bl.last_sync_error or "")


# --- #3597: the reverse direction, an adblock-format list fed hosts / domains ---

HOSTS = "# hosts\n127.0.0.1 localhost\n0.0.0.0 ads.example.com\n0.0.0.0 t.example.net\n"
DOMAINS = "# domains\nads.example.com\n*.t.example.net\nx.example.org # c\n"


@pytest.mark.parametrize(("content", "detected"), [(HOSTS, "hosts"), (DOMAINS, "domains")])
def test_hosts_or_domains_content_in_an_adblock_list_is_reported(
    content: str, detected: str
) -> None:
    parsed = parse_feed_detailed(content, "adblock")
    assert parsed.format_mismatch == detected
    assert parsed.domains == []


def test_adblock_feed_with_some_plain_lines_is_not_a_mismatch() -> None:
    content = "! t\n||a.example.com^\n||b.example.com^\n||c.example.com^\nplain.example.com\n"
    parsed = parse_feed_detailed(content, "adblock")
    assert parsed.format_mismatch is None
    assert parsed.domains == ["a.example.com", "b.example.com", "c.example.com"]


@pytest.mark.parametrize(("content", "detected"), [(HOSTS, "hosts"), (DOMAINS, "domains")])
async def test_refresh_of_adblock_list_refuses_hosts_or_domains_and_keeps_entries(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, content: str, detected: str
) -> None:
    monkeypatch.setattr(
        safe_fetch,
        "GuardedTransport",
        lambda **kw: httpx.MockTransport(lambda r: httpx.Response(200, text=content)),
    )
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)

    bl = DNSBlockList(
        name="rev", source_type="url", feed_url=f"https://{PUBLIC_IP}/l", feed_format="adblock"
    )
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
    assert f"Change the list's feed format to {detected}" in (bl.last_sync_error or "")
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
