"""Tests for DNS blocking lists: model, CRUD, bulk-add dedupe, feed sync."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSBlockList, DNSBlockListEntry
from app.services.dns_blocklist import (
    build_effective_for_group,
    dedupe_domains,
    parse_feed,
)


async def _make_user(
    db: AsyncSession, superadmin: bool = True, username: str = "bladmin"
) -> tuple[User, str]:
    user = User(
        username=username,
        email=f"{username}@example.com",
        display_name=username,
        hashed_password=hash_password("password123"),
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.flush()
    token = create_access_token(str(user.id))
    return user, token


# ── Model smoke ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_blocklist_model_roundtrip(db_session: AsyncSession) -> None:
    bl = DNSBlockList(
        name="ads", description="Ads list", feed_url="http://x/y", feed_format="hosts"
    )
    db_session.add(bl)
    await db_session.flush()

    e = DNSBlockListEntry(list_id=bl.id, domain="ads.example.com", source="manual")
    db_session.add(e)
    await db_session.commit()

    result = await db_session.execute(
        select(DNSBlockListEntry).where(DNSBlockListEntry.list_id == bl.id)
    )
    assert len(list(result.scalars().all())) == 1


# ── Feed parser ────────────────────────────────────────────────────────────


def test_parse_feed_hosts() -> None:
    text = """
# comment
0.0.0.0 ads.example.com
0.0.0.0   tracker.example.net   # inline
127.0.0.1 dup.example.com
127.0.0.1 dup.example.com
just.a.domain
"""
    domains = parse_feed(text, "hosts")
    assert "ads.example.com" in domains
    assert "tracker.example.net" in domains
    assert "just.a.domain" in domains
    assert domains.count("dup.example.com") == 1


def test_parse_feed_adblock() -> None:
    text = """
! comment
||ads.example.com^
||tracker.example.net$third-party
||bad.example.org/
"""
    domains = parse_feed(text, "adblock")
    # #2123 — a ``$third-party`` rule narrows the block, and ``||host/`` is a
    # path rule: neither is widened into an unconditional block any more.
    assert domains == ["ads.example.com"]


def test_parse_feed_domains() -> None:
    text = "foo.example.com\nbar.example.com\n# skip me\nbaz.example.com\n"
    assert parse_feed(text, "domains") == [
        "foo.example.com",
        "bar.example.com",
        "baz.example.com",
    ]


def test_dedupe_domains() -> None:
    assert dedupe_domains(["Foo.com", "foo.com", "bad", "bar.com"]) == ["foo.com", "bar.com"]


# ── CRUD ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_blocklist_crud_flow(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session, superadmin=True, username="blcrud")
    headers = {"Authorization": f"Bearer {token}"}

    # Create
    resp = await client.post(
        "/api/v1/dns/blocklists",
        json={"name": "ads", "category": "ads", "block_mode": "nxdomain"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    bl_id = resp.json()["id"]

    # List
    resp = await client.get("/api/v1/dns/blocklists", headers=headers)
    assert resp.status_code == 200
    assert any(b["id"] == bl_id for b in resp.json())

    # Update
    resp = await client.put(
        f"/api/v1/dns/blocklists/{bl_id}",
        json={"description": "Updated"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["description"] == "Updated"

    # Delete
    resp = await client.delete(f"/api/v1/dns/blocklists/{bl_id}", headers=headers)
    assert resp.status_code == 204


@pytest.mark.asyncio
async def test_bulk_add_entries_dedupes(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session, superadmin=True, username="blbulk")
    headers = {"Authorization": f"Bearer {token}"}

    # Create list
    resp = await client.post(
        "/api/v1/dns/blocklists",
        json={"name": "bulk-test"},
        headers=headers,
    )
    bl_id = resp.json()["id"]

    # Bulk-add with duplicates + invalid entries
    resp = await client.post(
        f"/api/v1/dns/blocklists/{bl_id}/entries/bulk",
        json={
            "domains": [
                "a.example.com",
                "A.example.com",  # case-dup
                "a.example.com",  # dup
                "b.example.com",
                "invalid",  # no dot → skipped
                "",  # empty → skipped
            ]
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["added"] == 2
    # Second bulk-add: same domains → all skipped
    resp = await client.post(
        f"/api/v1/dns/blocklists/{bl_id}/entries/bulk",
        json={"domains": ["a.example.com", "b.example.com", "c.example.com"]},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["added"] == 1  # only c.example.com
    assert resp.json()["skipped"] >= 2

    # Verify paginated list
    resp = await client.get(f"/api/v1/dns/blocklists/{bl_id}/entries", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 3


@pytest.mark.asyncio
async def test_exception_crud(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session, superadmin=True, username="blexc")
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post("/api/v1/dns/blocklists", json={"name": "exc-test"}, headers=headers)
    bl_id = resp.json()["id"]

    resp = await client.post(
        f"/api/v1/dns/blocklists/{bl_id}/exceptions",
        json={"domain": "good.example.com", "reason": "false positive"},
        headers=headers,
    )
    assert resp.status_code == 201
    ex_id = resp.json()["id"]

    resp = await client.get(f"/api/v1/dns/blocklists/{bl_id}/exceptions", headers=headers)
    assert resp.status_code == 200
    assert any(x["id"] == ex_id for x in resp.json())

    resp = await client.delete(
        f"/api/v1/dns/blocklists/{bl_id}/exceptions/{ex_id}", headers=headers
    )
    assert resp.status_code == 204


# ── Feed sync (mocked httpx) ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_feed_sync_adds_and_prunes(
    db_session: AsyncSession,
) -> None:
    """Feed sync must add new feed entries and remove ones no longer in the feed."""
    from app.tasks.dns import _refresh_blocklist_feed_async

    bl = DNSBlockList(
        name="feedtest",
        source_type="url",
        feed_url="http://example.com/list.txt",
        feed_format="hosts",
    )
    db_session.add(bl)
    await db_session.flush()
    # Pre-existing feed entry that will no longer be in the feed
    db_session.add(DNSBlockListEntry(list_id=bl.id, domain="stale.example.com", source="feed"))
    # Manual entry: must NOT be touched
    db_session.add(DNSBlockListEntry(list_id=bl.id, domain="manual.example.com", source="manual"))
    await db_session.commit()

    fake_body = "0.0.0.0 new.example.com\n0.0.0.0 another.example.com\n"

    async def fake_run() -> dict[str, int | str]:
        # Inline a simplified version running against the test session instead
        # of spinning up a new engine with real DB URL.
        from datetime import UTC, datetime

        from app.services.dns_blocklist import parse_feed as _pf

        result = await db_session.execute(select(DNSBlockList).where(DNSBlockList.id == bl.id))
        current = result.scalar_one()
        domains = set(_pf(fake_body, current.feed_format))
        existing_res = await db_session.execute(
            select(DNSBlockListEntry).where(
                DNSBlockListEntry.list_id == current.id,
                DNSBlockListEntry.source == "feed",
            )
        )
        existing = {e.domain: e for e in existing_res.scalars().all()}
        to_add = domains - set(existing.keys())
        to_remove = set(existing.keys()) - domains
        for d in to_add:
            db_session.add(
                DNSBlockListEntry(list_id=current.id, domain=d, entry_type="block", source="feed")
            )
        for d in to_remove:
            await db_session.delete(existing[d])
        current.last_synced_at = datetime.now(UTC)
        current.last_sync_status = "success"
        await db_session.commit()
        return {"status": "success", "added": len(to_add), "removed": len(to_remove)}

    out = await fake_run()
    assert out["status"] == "success"
    assert out["added"] == 2
    assert out["removed"] == 1

    # Manual entry preserved
    res = await db_session.execute(
        select(DNSBlockListEntry).where(DNSBlockListEntry.list_id == bl.id)
    )
    domains_now = {e.domain for e in res.scalars().all()}
    assert "manual.example.com" in domains_now
    assert "stale.example.com" not in domains_now
    assert "new.example.com" in domains_now
    assert "another.example.com" in domains_now

    # Keep helper symbols referenced to avoid unused-import lints
    assert callable(_refresh_blocklist_feed_async)


# ── Effective blocklist ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_effective_blocklist_for_group(db_session: AsyncSession) -> None:
    from app.models.dns import DNSBlockListException, DNSServerGroup

    group = DNSServerGroup(name="effective-grp")
    bl = DNSBlockList(name="eff", block_mode="nxdomain", enabled=True)
    bl.server_groups = [group]
    db_session.add_all([group, bl])
    await db_session.flush()

    db_session.add(DNSBlockListEntry(list_id=bl.id, domain="bad.example.com", source="manual"))
    db_session.add(DNSBlockListException(list_id=bl.id, domain="good.example.com"))
    await db_session.commit()

    eff = await build_effective_for_group(db_session, group.id)
    assert eff.scope == "group"
    assert any(e.domain == "bad.example.com" for e in eff.entries)
    # Equality, not membership: the group has one list carrying one exception,
    # so pinning the whole set also catches an exception leaking in from a list
    # that is not in scope. (It additionally keeps CodeQL's
    # py/incomplete-url-substring-sanitization off a `"host" in <set[str]>`
    # test it mistakes for a substring check on an unparsed URL.)
    assert eff.exceptions == {"good.example.com"}
    assert bl.id in eff.lists


# ── Feed sync against the real task (issue #878) ───────────────────────────


@pytest.mark.asyncio
async def test_feed_sync_counts_and_wildcards(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drive the actual refresh coroutine, not a reimplementation of it.

    ``test_feed_sync_adds_and_prunes`` above inlines a simplified copy of
    the logic, which is why neither of the two bugs this pins was ever
    caught: the copy did not run the code that had them.

      * ``entry_count`` double-counted on a first sync, because the
        recount query autoflushes the pending inserts and the old code
        then added ``len(to_add)`` on top again. A 16k-domain feed
        reported 33k.
      * feed rows never set ``is_wildcard``, so a list naming
        ``tracker.example`` left ``cdn.tracker.example`` resolving.
    """
    import contextlib

    from app.tasks import dns as dns_tasks

    bl = DNSBlockList(
        name="countcheck",
        source_type="url",
        feed_url="http://example.com/list.txt",
        feed_format="domains",
        # Deliberately wrong to start with, so a task that never writes
        # the field would fail rather than coincidentally match.
        entry_count=999,
    )
    db_session.add(bl)
    await db_session.flush()
    db_session.add(DNSBlockListEntry(list_id=bl.id, domain="stale.example.com", source="feed"))
    await db_session.commit()

    body = "a.example.com\nb.example.com\n*.wild.example.com\n"

    class _Resp:
        is_redirect = False  # the guarded fetch follows redirects by hand
        text = body

        def raise_for_status(self) -> None:
            return None

    class _Client:
        def __init__(self, *a: object, **kw: object) -> None:
            pass

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *a: object) -> None:
            return None

        async def get(self, _url: str) -> _Resp:
            return _Resp()

    monkeypatch.setattr(dns_tasks.httpx, "AsyncClient", _Client)
    # The task builds its own engine + session factory; hand it the test
    # session so it writes where the assertions can see it.
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _factory_cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _factory_cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
    assert out["status"] == "success"
    assert out["added"] == 3
    assert out["removed"] == 1

    rows = (
        (
            await db_session.execute(
                select(DNSBlockListEntry).where(DNSBlockListEntry.list_id == bl.id)
            )
        )
        .scalars()
        .all()
    )
    assert {r.domain for r in rows} == {
        "a.example.com",
        "b.example.com",
        # `*.` is feed syntax for "and subdomains", not part of the name.
        "wild.example.com",
    }
    assert all(r.is_wildcard for r in rows), "feed rows must block subdomains"

    await db_session.refresh(bl)
    assert bl.entry_count == len(rows) == 3


class _NullEngine:
    """Stand-in for the engine the task disposes in its ``finally``."""

    async def dispose(self) -> None:
        return None


async def _noop_publish(_channel: str) -> None:
    return None


# ── Per-list feed wildcard control (issue #894) ────────────────────────────


def test_parse_feed_reports_wildcard_syntax() -> None:
    """The `*.` prefix is the feed DECLARING it means "and subdomains".

    Stripping it is right — kept literally it produces an RPZ rule
    matching subdomains only — but the caller needs to know the feed
    said it, so an apex-only list can flag that it is overriding the
    feed's stated intent rather than doing so silently.
    """
    from app.services.dns_blocklist import parse_feed_detailed

    out = parse_feed_detailed("*.a.example\n*.b.example\nc.example\n", "domains")
    assert out.domains == ["a.example", "b.example", "c.example"]
    assert out.wildcard_count == 2

    plain = parse_feed_detailed("a.example\nb.example\n", "domains")
    assert plain.wildcard_count == 0


@pytest.mark.asyncio
async def test_feed_wildcard_flag_defaults_on_and_drives_new_rows(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Default on preserves #878; off is what a host-specific feed needs."""
    import contextlib

    from app.tasks import dns as dns_tasks

    async def _run(bl_id: str, body: str) -> None:
        class _Resp:
            is_redirect = False  # the guarded fetch follows redirects by hand
            text = body

            def raise_for_status(self) -> None:
                return None

        class _Client:
            def __init__(self, *a: object, **kw: object) -> None:
                pass

            async def __aenter__(self) -> _Client:
                return self

            async def __aexit__(self, *a: object) -> None:
                return None

            async def get(self, _url: str) -> _Resp:
                return _Resp()

        monkeypatch.setattr(dns_tasks.httpx, "AsyncClient", _Client)
        monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

        @contextlib.asynccontextmanager
        async def _factory_cm():  # type: ignore[no-untyped-def]
            yield db_session

        monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _factory_cm)
        monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)
        await dns_tasks._refresh_blocklist_feed_async(bl_id)

    wide = DNSBlockList(
        name="wide", source_type="url", feed_url="http://x/1", feed_format="domains"
    )
    narrow = DNSBlockList(
        name="narrow",
        source_type="url",
        feed_url="http://x/2",
        feed_format="domains",
        feed_entries_are_wildcard=False,
    )
    db_session.add_all([wide, narrow])
    await db_session.commit()
    # The column default applies without the caller passing anything.
    assert wide.feed_entries_are_wildcard is True

    await _run(str(wide.id), "a.example.com\n")
    await _run(str(narrow.id), "b.example.com\n")

    rows = (await db_session.execute(select(DNSBlockListEntry))).scalars().all()
    by_domain = {r.domain: r for r in rows}
    assert by_domain["a.example.com"].is_wildcard is True
    assert by_domain["b.example.com"].is_wildcard is False


@pytest.mark.asyncio
async def test_toggling_the_flag_restamps_existing_feed_rows(
    db_session: AsyncSession, client: AsyncClient
) -> None:
    """Without this the toggle silently does nothing until the feed churns.

    The refresh task diffs by domain and never revisits an unchanged
    one, so a flag flip would only reach rows added afterwards — the
    operator's stated intent deferred for days with no sign of it.

    Manual rows are deliberately untouched: ``is_wildcard`` there is that
    row's own setting, and someone who unchecked "include subdomains" on
    one domain did not ask for a list-wide switch to overwrite it.
    """
    from app.core.security import create_access_token, hash_password
    from app.models.auth import User

    user = User(
        username="wcadmin",
        email="wcadmin@example.com",
        display_name="wcadmin",
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db_session.add(user)
    await db_session.flush()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    bl = DNSBlockList(name="flip", source_type="url", feed_url="http://x/f")
    db_session.add(bl)
    await db_session.flush()
    db_session.add_all(
        [
            DNSBlockListEntry(
                list_id=bl.id, domain="feed-a.example", source="feed", is_wildcard=True
            ),
            DNSBlockListEntry(
                list_id=bl.id, domain="feed-b.example", source="feed", is_wildcard=True
            ),
            DNSBlockListEntry(
                list_id=bl.id, domain="manual.example", source="manual", is_wildcard=False
            ),
        ]
    )
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dns/blocklists/{bl.id}",
        headers=headers,
        json={"feed_entries_are_wildcard": False},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["feed_entries_are_wildcard"] is False

    rows = (
        (
            await db_session.execute(
                select(DNSBlockListEntry).where(DNSBlockListEntry.list_id == bl.id)
            )
        )
        .scalars()
        .all()
    )
    by_domain = {r.domain: r for r in rows}
    assert by_domain["feed-a.example"].is_wildcard is False
    assert by_domain["feed-b.example"].is_wildcard is False
    # Untouched — the operator's per-row choice survives.
    assert by_domain["manual.example"].is_wildcard is False

    # …and flipping back restamps the feed rows again.
    back = await client.put(
        f"/api/v1/dns/blocklists/{bl.id}",
        headers=headers,
        json={"feed_entries_are_wildcard": True},
    )
    assert back.status_code == 200
    rows2 = (
        (
            await db_session.execute(
                select(DNSBlockListEntry).where(
                    DNSBlockListEntry.list_id == bl.id,
                    DNSBlockListEntry.source == "feed",
                )
            )
        )
        .scalars()
        .all()
    )
    assert all(r.is_wildcard for r in rows2)
