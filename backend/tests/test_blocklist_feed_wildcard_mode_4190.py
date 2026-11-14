"""Feed entries decide subdomain blocking from their own syntax (#4190).

A hosts line names one host; an adblock ``||name^`` rule means "name and
every subdomain". ``feed_wildcard_mode`` is ``by_syntax`` (default),
``always`` or ``never``.
"""

from __future__ import annotations

import contextlib
import importlib.util
from pathlib import Path

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSBlockList, DNSBlockListEntry
from app.services.dns_blocklist_parse import parse_feed_detailed
from app.tasks import dns as dns_tasks

HOSTS = "127.0.0.1 localhost\n0.0.0.0 ads.example.com\n127.0.0.1 track.example.net # c\n"
ADBLOCK = "! t\n||ads.example.com^\n||track.example.net^$important\n"


# ── parser ──────────────────────────────────────────────────────────────────


def test_hosts_feed_declares_no_wildcards() -> None:
    p = parse_feed_detailed(HOSTS, "hosts")
    assert p.domains == ["ads.example.com", "track.example.net"]
    assert p.wildcard_domains == set()


def test_adblock_feed_declares_every_entry_wildcard() -> None:
    p = parse_feed_detailed(ADBLOCK, "adblock")
    assert p.domains == ["ads.example.com", "track.example.net"]
    assert p.wildcard_domains == set(p.domains)


def test_domains_feed_mixed_bare_and_star_lines() -> None:
    p = parse_feed_detailed("bare.example.com\n*.wild.example.com\n", "domains")
    assert p.domains == ["bare.example.com", "wild.example.com"]
    assert p.wildcard_domains == {"wild.example.com"}


def test_a_star_line_after_a_bare_duplicate_still_marks_the_name_wildcard() -> None:
    p = parse_feed_detailed("a.example.com\n*.a.example.com\n", "domains")
    assert p.domains == ["a.example.com"]
    assert p.wildcard_domains == {"a.example.com"}


# ── refresh ─────────────────────────────────────────────────────────────────


class _NullEngine:
    async def dispose(self) -> None:
        return None


async def _refresh(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, bl: DNSBlockList, feed: str
) -> None:
    from app.core import safe_fetch

    monkeypatch.setattr(
        safe_fetch,
        "GuardedTransport",
        lambda **kw: httpx.MockTransport(lambda r: httpx.Response(200, text=feed)),
    )
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _cm():  # type: ignore[no-untyped-def]
        yield db_session

    async def _noop(_c: str) -> None:
        return None

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop)
    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
    assert out["status"] == "success"


async def _flags(db_session: AsyncSession, bl: DNSBlockList) -> dict[str, bool]:
    rows = (
        await db_session.execute(
            select(DNSBlockListEntry.domain, DNSBlockListEntry.is_wildcard).where(
                DNSBlockListEntry.list_id == bl.id
            )
        )
    ).all()
    return {d: w for d, w in rows}


@pytest.mark.parametrize(
    ("fmt", "feed", "mode", "expect"),
    [
        ("hosts", HOSTS, "by_syntax", False),
        ("adblock", ADBLOCK, "by_syntax", True),
        ("hosts", HOSTS, "always", True),
        ("adblock", ADBLOCK, "never", False),
        ("hosts", HOSTS, "never", False),
        ("adblock", ADBLOCK, "always", True),
    ],
)
async def test_refresh_stamps_entries_by_mode(
    db_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    fmt: str,
    feed: str,
    mode: str,
    expect: bool,
) -> None:
    bl = DNSBlockList(
        name=f"l-{fmt}-{mode}",
        source_type="url",
        feed_url="https://93.184.216.34/f.txt",
        feed_format=fmt,
        feed_wildcard_mode=mode,
    )
    db_session.add(bl)
    await db_session.commit()
    await _refresh(db_session, monkeypatch, bl, feed)
    flags = await _flags(db_session, bl)
    assert flags == {"ads.example.com": expect, "track.example.net": expect}


async def test_mixed_domains_feed_by_syntax(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    bl = DNSBlockList(
        name="mixed",
        source_type="url",
        feed_url="https://93.184.216.34/f.txt",
        feed_format="domains",
    )
    db_session.add(bl)
    await db_session.commit()
    assert bl.feed_wildcard_mode == "by_syntax"
    await _refresh(db_session, monkeypatch, bl, "bare.example.com\n*.wild.example.com\n")
    assert await _flags(db_session, bl) == {"bare.example.com": False, "wild.example.com": True}


async def test_refresh_restamps_rows_stored_wildcard_by_an_older_version(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An upgraded hosts list keeps its rows; the next refresh makes them exact,
    and a manual row is left alone."""
    bl = DNSBlockList(
        name="upgraded",
        source_type="url",
        feed_url="https://93.184.216.34/f.txt",
        feed_format="hosts",
    )
    db_session.add(bl)
    await db_session.flush()
    db_session.add_all(
        [
            DNSBlockListEntry(
                list_id=bl.id, domain="ads.example.com", source="feed", is_wildcard=True
            ),
            DNSBlockListEntry(
                list_id=bl.id, domain="mine.example.com", source="manual", is_wildcard=True
            ),
        ]
    )
    await db_session.commit()
    await _refresh(db_session, monkeypatch, bl, "0.0.0.0 ads.example.com\n")
    assert await _flags(db_session, bl) == {"ads.example.com": False, "mine.example.com": True}


# ── API ─────────────────────────────────────────────────────────────────────


async def _admin_headers(db_session: AsyncSession) -> dict[str, str]:
    from app.core.security import create_access_token, hash_password
    from app.models.auth import User

    user = User(
        username="wm4190",
        email="wm4190@example.com",
        display_name="wm4190",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def test_api_tri_state_and_legacy_boolean(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    h = await _admin_headers(db_session)
    r = await client.post("/api/v1/dns/blocklists", headers=h, json={"name": "api1"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["feed_wildcard_mode"] == "by_syntax"
    assert body["feed_entries_are_wildcard"] is True
    lid = body["id"]

    r = await client.put(
        f"/api/v1/dns/blocklists/{lid}", headers=h, json={"feed_wildcard_mode": "never"}
    )
    assert r.status_code == 200, r.text
    assert (r.json()["feed_wildcard_mode"], r.json()["feed_entries_are_wildcard"]) == (
        "never",
        False,
    )

    # The deprecated boolean still works: true is the explicit "always".
    r = await client.put(
        f"/api/v1/dns/blocklists/{lid}", headers=h, json={"feed_entries_are_wildcard": True}
    )
    assert r.status_code == 200, r.text
    assert r.json()["feed_wildcard_mode"] == "always"

    r = await client.put(
        f"/api/v1/dns/blocklists/{lid}", headers=h, json={"feed_wildcard_mode": "bogus"}
    )
    assert r.status_code == 422

    r = await client.post(
        "/api/v1/dns/blocklists",
        headers=h,
        json={"name": "api2", "feed_entries_are_wildcard": False},
    )
    assert r.status_code == 201, r.text
    assert r.json()["feed_wildcard_mode"] == "never"


async def test_switching_to_always_restamps_stored_feed_rows(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    h = await _admin_headers(db_session)
    bl = DNSBlockList(name="flip4190", source_type="url", feed_url="http://x/f")
    db_session.add(bl)
    await db_session.flush()
    db_session.add_all(
        [
            DNSBlockListEntry(list_id=bl.id, domain="f.example", source="feed", is_wildcard=False),
            DNSBlockListEntry(
                list_id=bl.id, domain="m.example", source="manual", is_wildcard=False
            ),
        ]
    )
    await db_session.commit()
    r = await client.put(
        f"/api/v1/dns/blocklists/{bl.id}", headers=h, json={"feed_wildcard_mode": "always"}
    )
    assert r.status_code == 200, r.text
    assert await _flags(db_session, bl) == {"f.example": True, "m.example": False}


# ── migration ───────────────────────────────────────────────────────────────


async def test_migration_maps_the_old_boolean(db_session: AsyncSession) -> None:
    path = next(Path(__file__).resolve().parents[1].glob("alembic/versions/b6d2e9f41a07_*.py"))
    spec = importlib.util.spec_from_file_location("mig4190", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    await db_session.execute(text("DROP SCHEMA IF EXISTS mig4190 CASCADE"))
    await db_session.execute(text("CREATE SCHEMA mig4190"))
    await db_session.execute(text("SET LOCAL search_path TO mig4190"))
    await db_session.execute(
        text(
            "CREATE TABLE dns_blocklist (name text, feed_url text, "
            "feed_entries_are_wildcard boolean, "
            "feed_wildcard_mode varchar(16) NOT NULL DEFAULT 'by_syntax')"
        )
    )
    rows = [
        ("hosts", "https://example.org/hosts", True),
        ("exact", "https://example.org/c2.txt", False),
        ("manual", None, True),
        (
            "hagezi",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro-onlydomains.txt",
            True,
        ),
        ("oisd", "https://big.oisd.nl/domainswild", True),
        (
            "hagezi-off",
            "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/x",
            False,
        ),
    ]
    for name, url, flag in rows:
        await db_session.execute(
            text(
                "INSERT INTO dns_blocklist (name, feed_url, feed_entries_are_wildcard) VALUES (:n, :u, :f)"
            ),
            {"n": name, "u": url, "f": flag},
        )
    for stmt in mod.MAPPING_SQL:
        await db_session.execute(text(stmt))
    got = dict(
        (await db_session.execute(text("SELECT name, feed_wildcard_mode FROM dns_blocklist"))).all()
    )
    await db_session.execute(text("SET LOCAL search_path TO public"))
    await db_session.execute(text("DROP SCHEMA mig4190 CASCADE"))
    assert got == {
        "hosts": "by_syntax",
        "exact": "never",
        "manual": "by_syntax",
        "hagezi": "always",
        "oisd": "always",
        "hagezi-off": "never",
    }


async def test_legacy_boolean_column_follows_the_mode(db_session: AsyncSession) -> None:
    """Kept for a rolling upgrade (expand/contract): true unless ``never``."""
    bl = DNSBlockList(name="legacy-sync", feed_wildcard_mode="never")
    db_session.add(bl)
    await db_session.commit()
    assert bl.feed_entries_are_wildcard is False
    bl.feed_wildcard_mode = "always"
    await db_session.commit()
    assert bl.feed_entries_are_wildcard is True
    assert (
        await db_session.scalar(
            text("SELECT feed_entries_are_wildcard FROM dns_blocklist WHERE id = :i"),
            {"i": bl.id},
        )
        is True
    )
