"""DNS blocklists: sinkhole answers with an address (#2124), and the
adblock parser honours ``@@`` / ``$badfilter`` / modifiers (#2123).

#2124 — the agent rendered ``sinkhole`` as ``CNAME rpz-drop.``, which sends
no response, so every blocked lookup hung for the client's resolver timeout;
the list's ``sinkhole_ip`` never reached it. The control-plane renderer
emitted ``A <ip>`` only when an address was set and rendered ``refused`` as
``rpz-drop``. ``refused`` has no RPZ action at all, so it is now a 422.

#2123 — the adblock branch read only ``||`` lines and cut each rule at the
first ``^`` / ``$`` / ``/``: exceptions vanished, ``$badfilter`` became a
block, and narrowing modifiers became unconditional blocks.
"""

from __future__ import annotations

import contextlib
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns.base import BlocklistEntry, EffectiveBlocklistData
from app.drivers.dns.bind9 import BIND9Driver
from app.models.auth import User
from app.models.dns import (
    DNSBlockList,
    DNSBlockListEntry,
    DNSBlockListException,
    DNSServerGroup,
)
from app.services.dns.agent_config import _entry_dict
from app.services.dns_blocklist import (
    build_effective_for_group,
    effective_lists_for_group,
    exception_domains,
    parse_feed_detailed,
)
from app.tasks import dns as dns_tasks

# ── #2124: the control-plane renderer ───────────────────────────────────────


def _entry(domain: str, mode: str, ip: str | None = None, wild: bool = False) -> BlocklistEntry:
    return BlocklistEntry(
        domain=domain,
        action="block",
        block_mode=mode,
        sinkhole_ip=ip,
        target=None,
        is_wildcard=wild,
    )


def _rendered(*entries: BlocklistEntry) -> list[str]:
    out = BIND9Driver().render_rpz_zone(
        EffectiveBlocklistData(
            rpz_zone_name="spatium-blocklist.rpz.",
            entries=entries,
            exceptions=frozenset(),
        )
    )
    return [
        ln.strip()
        for ln in out.splitlines()
        if " IN " in ln and not ln.startswith("spatium-blocklist.rpz.")
    ]


def test_sinkhole_without_an_address_answers_both_unspecified_addresses() -> None:
    """Used to fall through to NXDOMAIN when ``sinkhole_ip`` was unset."""
    assert _rendered(_entry("ads.example", "sinkhole", wild=True)) == [
        "ads.example IN A 0.0.0.0",
        "ads.example IN AAAA ::",
        "*.ads.example IN A 0.0.0.0",
        "*.ads.example IN AAAA ::",
    ]


def test_sinkhole_ipv4_address_keeps_the_ipv6_unspecified_address() -> None:
    assert _rendered(_entry("ads.example", "sinkhole", "192.0.2.53")) == [
        "ads.example IN A 192.0.2.53",
        "ads.example IN AAAA ::",
    ]


def test_sinkhole_ipv6_address_keeps_the_ipv4_unspecified_address() -> None:
    assert _rendered(_entry("ads.example", "sinkhole", "2001:db8::53")) == [
        "ads.example IN A 0.0.0.0",
        "ads.example IN AAAA 2001:db8::53",
    ]


def test_an_unusable_sinkhole_address_never_reaches_the_rdata() -> None:
    assert _rendered(_entry("ads.example", "sinkhole", "not an ip")) == [
        "ads.example IN A 0.0.0.0",
        "ads.example IN AAAA ::",
    ]


def test_a_legacy_refused_mode_renders_nxdomain_not_drop() -> None:
    """The agent always served it as NXDOMAIN; this renderer used ``rpz-drop``."""
    assert _rendered(_entry("r.example", "refused")) == ["r.example IN CNAME ."]


# ── #2124: the bundle carries the sinkhole address ──────────────────────────


def test_bundle_entry_carries_sinkhole_ip_only_where_it_means_something() -> None:
    assert _entry_dict("a.example", "block", "sinkhole", None, True, "192.0.2.1") == {
        "domain": "a.example",
        "action": "block",
        "block_mode": "sinkhole",
        "target": None,
        "is_wildcard": True,
        "sinkhole_ip": "192.0.2.1",
    }
    # Not on another mode, and not when the list names no address: those
    # bundles stay byte-identical.
    assert "sinkhole_ip" not in _entry_dict("a.example", "block", "nxdomain", None, True, "1.2.3.4")
    assert "sinkhole_ip" not in _entry_dict("a.example", "block", "sinkhole", None, True, None)
    assert "sinkhole_ip" not in _entry_dict("a.example", "block", "nxdomain", None, True)


# ── #2124: the API ──────────────────────────────────────────────────────────


async def _token(db: AsyncSession) -> dict[str, str]:
    user = User(
        username="bl2124",
        email="bl2124@example.com",
        display_name="bl2124",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.mark.asyncio
async def test_refused_is_a_422_that_says_why(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _token(db_session)
    resp = await client.post(
        "/api/v1/dns/blocklists",
        json={"name": "r", "block_mode": "refused"},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text
    assert "no action that answers REFUSED" in resp.text

    resp = await client.post("/api/v1/dns/blocklists", json={"name": "ok"}, headers=headers)
    assert resp.status_code == 201, resp.text
    resp = await client.put(
        f"/api/v1/dns/blocklists/{resp.json()['id']}",
        json={"block_mode": "refused"},
        headers=headers,
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_sinkhole_ip_must_be_an_address(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _token(db_session)
    bad = await client.post(
        "/api/v1/dns/blocklists",
        json={"name": "s", "block_mode": "sinkhole", "sinkhole_ip": "sinkhole.example"},
        headers=headers,
    )
    assert bad.status_code == 422, bad.text

    good = await client.post(
        "/api/v1/dns/blocklists",
        json={"name": "s", "block_mode": "sinkhole", "sinkhole_ip": " 2001:DB8::0:53 "},
        headers=headers,
    )
    assert good.status_code == 201, good.text
    assert good.json()["sinkhole_ip"] == "2001:db8::53"
    assert good.json()["feed_parse_skipped"] is None

    cleared = await client.put(
        f"/api/v1/dns/blocklists/{good.json()['id']}",
        json={"sinkhole_ip": ""},
        headers=headers,
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["sinkhole_ip"] is None


# ── #2123: the adblock parser ───────────────────────────────────────────────

# Shapes taken from the AdGuard DNS filter
# (adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt).
_ADGUARD_EXCERPT = """\
! Title: AdGuard DNS filter
! Homepage: https://github.com/AdguardTeam/AdGuardSDNSFilter
[Adblock Plus 2.0]
||ads.example.com^
||Tracker.Example.NET^
||metrics.example.org^$important
||doubled.example.com^
||doubled.example.com^
||covered.example.com^
||sub.covered.example.com^
@@||sub.covered.example.com^
@@||allowed.example.net^|
@@||allowed-important.example.net^$important
||cancelled.example.com^
||cancelled.example.com^$badfilter
@@||cancelled-exception.example.com^
@@||cancelled-exception.example.com^$badfilter
||only-important-cancelled.example.com^$important
||only-important-cancelled.example.com^$badfilter
||narrow.example.com^$domain=site.example
||thirdparty.example.com^$third-party
||doc.example.com^$document
||stealth.example.com^$stealth
||client.example.com^$client=192.168.1.1
@@||narrow-exception.example.com^$domain=site.example
/^ad[0-9]+\\.example\\.com$/
@@/^ok[0-9]+\\.example\\.com$/
||path.example.com/banner.js
||ad*.example.com^
|anchor.example.com^
plain.example.com
example.com##.banner
*.wild.example.com
||*.star.example.com^
"""


def test_adblock_parses_every_rule_shape_for_what_it_says() -> None:
    p = parse_feed_detailed(_ADGUARD_EXCERPT, "adblock")
    assert p.domains == [
        "ads.example.com",
        "tracker.example.net",
        "metrics.example.org",  # $important is a plain block
        "doubled.example.com",
        "covered.example.com",
        # sub.covered is excepted by the feed itself, so not stored
        # cancelled.example.com: disabled by its $badfilter twin
        "only-important-cancelled.example.com",  # the badfilter names a different rule
        "star.example.com",
    ]
    assert p.exceptions == [
        "sub.covered.example.com",
        "allowed.example.net",
        "allowed-important.example.net",
    ]
    assert p.skipped is not None
    assert p.skipped.as_dict() == {
        # ``/…/`` and ``@@/…/``
        "regex": 2,
        # $domain= / $third-party / $document / $stealth / $client= and the
        # $domain= exception: each narrows a rule DNS cannot narrow
        "modifier": 6,
        # three $badfilter rules
        "badfilter": 3,
        # a path, a ``*`` inside a name, a ``|`` anchor, a bare word, and
        # ``*.wild…`` (not ``||`` syntax)
        "malformed": 5,
    }


def test_an_important_block_overrules_a_plain_exception_for_its_name() -> None:
    """``$important`` exists to beat ``@@``: kept as a plain block, it must
    still not lose to an exception the feed lists for the same name, or the
    exception (applied group-wide) would unblock what the feed insists on."""
    p = parse_feed_detailed(
        "||forced.example.com^$important\n"
        "@@||forced.example.com^\n"
        "||both.example.com^$important\n"
        "@@||both.example.com^$important\n",
        "adblock",
    )
    assert p.domains == ["forced.example.com"]
    assert p.exceptions == ["both.example.com"]


def test_adblock_rules_count_as_subdomain_intent_894() -> None:
    """``||name^`` means "and every subdomain"; an apex-only list against an
    adblock feed must log the #894 override as a ``*.`` feed does."""
    p = parse_feed_detailed("||a.example^\n||b.example^\n@@||c.example^\n", "adblock")
    assert p.wildcard_count == 2


def test_other_formats_report_no_skip_counts() -> None:
    p = parse_feed_detailed("0.0.0.0 a.example\n", "hosts")
    assert p.skipped is None and p.exceptions == []


# ── #2123: the refresh stores exceptions and counts ─────────────────────────


class _NullEngine:
    async def dispose(self) -> None:
        return None


def _wire(monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession, holder: dict) -> None:
    class _Resp:
        is_redirect = False  # the guarded fetch follows redirects by hand

        def __init__(self) -> None:
            self.text = holder["body"]

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

    async def _noop(_c: str) -> None:
        return None

    monkeypatch.setattr(dns_tasks.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _factory_cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _factory_cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop)


@pytest.mark.asyncio
async def test_refresh_stores_feed_exceptions_and_skip_counts(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    bl = DNSBlockList(
        name="adguard",
        source_type="url",
        feed_url="http://example.com/filter.txt",
        feed_format="adblock",
    )
    db_session.add(bl)
    await db_session.flush()
    # An operator's own exception, which a refresh must never remove — even
    # when the feed lists the same name.
    db_session.add(DNSBlockListException(list_id=bl.id, domain="mine.example", reason="ours"))
    db_session.add(DNSBlockListException(list_id=bl.id, domain="both.example", reason="ours"))
    await db_session.commit()

    holder = {
        "body": "||ads.example^\n@@||ok.example^\n@@||both.example^\n"
        "||x.example^$third-party\n/re/\n"
    }
    _wire(monkeypatch, db_session, holder)
    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
    assert out["status"] == "success"

    async def _exceptions() -> dict[str, str]:
        rows = await db_session.execute(
            select(DNSBlockListException.domain, DNSBlockListException.source).where(
                DNSBlockListException.list_id == bl.id
            )
        )
        return {d: src for d, src in rows.tuples()}

    assert await _exceptions() == {
        "mine.example": "manual",
        "both.example": "manual",
        "ok.example": "feed",
    }
    entries = (
        (
            await db_session.execute(
                select(DNSBlockListEntry.domain).where(DNSBlockListEntry.list_id == bl.id)
            )
        )
        .scalars()
        .all()
    )
    assert list(entries) == ["ads.example"]
    await db_session.refresh(bl)
    assert bl.entry_count == 1
    assert bl.feed_parse_skipped == {"regex": 1, "modifier": 1, "badfilter": 0, "malformed": 0}

    # The feed drops its exceptions: the feed row goes, the operator's stay.
    holder["body"] = "||ads.example^\n"
    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))
    assert out["status"] == "success"
    assert await _exceptions() == {"mine.example": "manual", "both.example": "manual"}
    await db_session.refresh(bl)
    assert bl.feed_parse_skipped == {"regex": 0, "modifier": 0, "badfilter": 0, "malformed": 0}


@pytest.mark.asyncio
async def test_adding_a_feed_exception_by_hand_makes_it_the_operators(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A manual add of a name the feed already excepts adopts the feed row
    instead of 409ing: otherwise the next refresh that stops listing it
    deletes the exception the operator just asked for."""
    headers = await _token(db_session)
    bl = DNSBlockList(name="adguard-adopt", source_type="url", feed_format="adblock")
    db_session.add(bl)
    await db_session.flush()
    db_session.add(
        DNSBlockListException(list_id=bl.id, domain="ok.example", reason="feed", source="feed")
    )
    db_session.add(DNSBlockListException(list_id=bl.id, domain="mine.example", reason="ours"))
    await db_session.commit()

    resp = await client.post(
        f"/api/v1/dns/blocklists/{bl.id}/exceptions",
        json={"domain": "OK.example", "reason": "keep it"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["source"] == "manual"
    assert resp.json()["reason"] == "keep it"

    dup = await client.post(
        f"/api/v1/dns/blocklists/{bl.id}/exceptions",
        json={"domain": "mine.example", "reason": "again"},
        headers=headers,
    )
    assert dup.status_code == 409, dup.text


# ── Feed exceptions apply to the feed's own list only (decided on #2124) ────


async def _group_with_feed_and_manual(db: AsyncSession) -> DNSServerGroup:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    manual = DNSBlockList(name="a-manual", block_mode="nxdomain")
    feed = DNSBlockList(
        name="z-adguard", source_type="url", feed_format="adblock", block_mode="nxdomain"
    )
    manual.server_groups = [group]
    feed.server_groups = [group]
    db.add_all([group, manual, feed])
    await db.flush()

    def entry(bl: DNSBlockList, domain: str, wild: bool) -> DNSBlockListEntry:
        return DNSBlockListEntry(
            list_id=bl.id, domain=domain, entry_type="block", source="manual", is_wildcard=wild
        )

    db.add_all(
        [
            # The operator's own blocks.
            entry(manual, "x.example", False),
            entry(manual, "p.example", True),
            entry(manual, "deep.d.feed.example", False),
            entry(manual, "m.example", False),
            # The feed's own wildcard block it carves exceptions out of.
            entry(feed, "feed.example", True),
        ]
    )
    for domain in (
        "x.example",  # the operator blocks it exactly
        "sub.p.example",  # the operator blocks it through a wildcard
        "c.feed.example",  # a carve-out from the feed's own block: honoured
        "d.feed.example",  # a carve-out, but the operator blocks a name under it
        "lone.example",  # the feed blocks nothing above it
    ):
        db.add(DNSBlockListException(list_id=feed.id, domain=domain, reason="feed", source="feed"))
    # An exception the operator added (or adopted) on the feed's list is
    # group-wide, as every manual exception is.
    db.add(DNSBlockListException(list_id=feed.id, domain="m.example", reason="mine"))
    await db.commit()
    return group


@pytest.mark.asyncio
async def test_a_feed_exception_never_unblocks_another_lists_block(
    db_session: AsyncSession,
) -> None:
    group = await _group_with_feed_and_manual(db_session)
    eff = await build_effective_for_group(db_session, group.id)
    assert eff.exceptions == {"c.feed.example", "m.example"}

    # The streamed bundle (#1662) reads exceptions through the same helper.
    lists = await effective_lists_for_group(db_session, group.id)
    assert lists is not None
    assert await exception_domains(db_session, lists) == eff.exceptions

    # Rendered by the control-plane driver (which skips exceptions rather
    # than emitting passthru): the operator's blocks all survive, and the
    # operator's own exception still unblocks m.example across lists.
    zone = BIND9Driver().render_rpz_zone(
        EffectiveBlocklistData(
            rpz_zone_name="spatium-blocklist.rpz.",
            entries=[
                BlocklistEntry(
                    domain=e.domain,
                    action=e.action,
                    block_mode=e.block_mode,
                    sinkhole_ip=e.sinkhole_ip,
                    target=e.target,
                    is_wildcard=e.is_wildcard,
                )
                for e in eff.entries
            ],
            exceptions=frozenset(eff.exceptions),
        )
    )
    assert "x.example IN CNAME ." in zone
    assert "*.p.example IN CNAME ." in zone
    assert "deep.d.feed.example IN CNAME ." in zone
    assert "\nm.example IN CNAME ." not in zone


@pytest.mark.asyncio
async def test_without_another_list_a_feed_carve_out_still_applies(
    db_session: AsyncSession,
) -> None:
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}")
    feed = DNSBlockList(name="only-feed", source_type="url", feed_format="adblock")
    feed.server_groups = [group]
    db_session.add_all([group, feed])
    await db_session.flush()
    db_session.add(
        DNSBlockListEntry(
            list_id=feed.id,
            domain="feed.example",
            entry_type="block",
            source="manual",
            is_wildcard=True,
        )
    )
    db_session.add_all(
        [
            DNSBlockListException(list_id=feed.id, domain="ok.feed.example", source="feed"),
            DNSBlockListException(list_id=feed.id, domain="lone.example", source="feed"),
        ]
    )
    await db_session.commit()
    eff = await build_effective_for_group(db_session, group.id)
    assert eff.exceptions == {"ok.feed.example"}


def test_a_name_the_feed_blocks_and_excepts_is_not_an_entry() -> None:
    p = parse_feed_detailed("||both.example^\n@@||both.example^\n||ads.example^\n", "adblock")
    assert p.domains == ["ads.example"]
    assert p.exceptions == ["both.example"]
