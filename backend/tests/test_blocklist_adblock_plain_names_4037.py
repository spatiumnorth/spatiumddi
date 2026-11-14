"""AdGuard DNS Filter rules a DNS server can express were skipped (#4037).

``.name^`` (the name's subdomains) and ``|name^`` (exactly that name) are
complete names, so they are enforced; filename fragments that look like them
(``.n.2.1.js^``) and rules with no ``^`` are not.
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

# Verbatim lines (original order) from the AdGuard DNS Filter,
# https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt,
# fetched 13 Nov 2026 (192,622 lines). Source line numbers are in the order of
# the file; the three unrelated plain ``||`` rules are kept so the excerpt also
# exercises the enforced path.
ADGUARD_EXCERPT = """\
.bbelements.com^
.doublepimp.com^
.n.2.1.js^
.1.1.1.l80.js^
.3.n.2.1.l50.js
.infox.sg^
.is.traff-numerical.info^
.tpm.pw^
|piwik.
.prod.pr.analytics.console.aws.a2z.com
|c.blue.*.com^|
|a.klaviyo.com^
.tvp.tv^
.ay.delivery^
.stape.net
|load.gtm.
.1080.x.90.
||ads.livetv*.me^
||admulti.
-adx-*.rayjump.com^
||countly-
||taboola.com^
||doubleclick.net^
@@|api.taboola.com^|
@@|cdn.taboola.com^|
@@|ezodn.com^|
||ezodn.com^
||crazyegg.com^
"""


def _parse(text: str = ADGUARD_EXCERPT):
    return parse_feed_detailed(text, "adblock")


def test_dot_led_name_blocks_subdomains_only() -> None:
    p = _parse()
    # Stored as ``*.name`` with the list flag NOT applied: the apex stays out.
    assert "*.bbelements.com" in p.literal_domains
    assert "*.is.traff-numerical.info" in p.literal_domains
    assert "*.tpm.pw" in p.literal_domains
    assert "bbelements.com" not in p.domains
    assert "bbelements.com" not in p.literal_domains


def test_start_anchor_full_name_is_an_exact_block() -> None:
    p = _parse()
    assert "a.klaviyo.com" in p.literal_domains
    assert "*.a.klaviyo.com" not in p.literal_domains


def test_filename_fragments_and_unterminated_rules_stay_skipped() -> None:
    p = _parse()
    for junk in (".n.2.1.js", ".1.1.1.l80.js", ".3.n.2.1.l50.js", ".stape.net"):
        assert not any(junk.lstrip(".") in d for d in p.literal_domains + p.domains), junk
    assert not any("piwik" in d or "gtm" in d or "1080" in d for d in p.literal_domains)
    s = p.skipped
    assert s is not None
    # ``.n.2.1.js^``, ``.1.1.1.l80.js^`` (numeric labels), ``.3.n.2.1.l50.js``,
    # ``.stape.net``, ``.prod.pr...com`` and ``.1080.x.90.`` (no ``^``).
    assert s.no_anchor == 6
    # ``|piwik.``, ``|load.gtm.`` and ``|c.blue.*.com^|`` (start anchor wins).
    assert s.start_anchor == 3
    assert s.bare_star == 1  # ``-adx-*.rayjump.com^``
    assert s.star_in_name == 1
    assert s.trailing_dot == 1
    assert s.dotless == 1
    assert s.total == s.malformed


def test_plain_rules_still_enforced_with_the_list_flag() -> None:
    p = _parse()
    assert "doubleclick.net" in p.domains
    assert "crazyegg.com" in p.domains
    assert "taboola.com" in p.domains
    assert p.wildcard_count == len(p.domains) + 1  # + the one removed by an exception


def test_exact_exception_maps_and_carves_out_its_block() -> None:
    p = _parse()
    assert {"api.taboola.com", "cdn.taboola.com", "ezodn.com"} <= set(p.exceptions)
    # ``||ezodn.com^`` is excepted by ``@@|ezodn.com^|``, so it is not stored.
    assert "ezodn.com" not in p.domains


def test_dot_led_exception_has_nothing_to_map_to() -> None:
    p = _parse("||x.example.com^\n@@.y.example.com^\n")
    assert p.exceptions == []
    assert p.skipped is not None and p.skipped.no_anchor == 1


def test_subdomain_rule_is_dropped_when_its_name_is_excepted() -> None:
    # The exception renders ``*.N`` as passthru; a ``*.N`` block would be a
    # second CNAME on that owner and BIND refuses the whole zone.
    p = _parse(".n.example.com^\n@@|n.example.com^\n")
    assert p.literal_domains == []
    assert p.exceptions == ["n.example.com"]


def test_badfilter_cancels_the_new_shapes() -> None:
    p = _parse("|a.example.com^\n|a.example.com^$badfilter\n.b.example.com^\n")
    assert p.literal_domains == ["*.b.example.com"]


def test_exact_rule_covered_by_a_double_pipe_rule_is_not_duplicated() -> None:
    p = _parse("||a.example.com^\n|a.example.com^\n")
    assert p.domains == ["a.example.com"]
    assert p.literal_domains == []


def test_name_sanity_rule() -> None:
    p = _parse(
        ".good.example.com^\n.1.example.com^\n.app.js^\n.a.b.php^\n"
        "|x.xn--p1ai^\n|nodots^\n.-bad.example.com^\n"
    )
    assert p.literal_domains == ["*.good.example.com", "x.xn--p1ai"]


class _NullEngine:
    async def dispose(self) -> None:
        return None


async def _noop_publish(_channel: str) -> None:
    return None


@pytest.mark.parametrize("list_wildcard", [True, False])
async def test_refresh_stores_literal_entries_with_their_own_flag(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch, list_wildcard: bool
) -> None:
    feed = "||plain.example.com^\n.sub.example.org^\n|exact.example.net^\n"
    monkeypatch.setattr(
        safe_fetch,
        "GuardedTransport",
        lambda **kw: httpx.MockTransport(lambda r: httpx.Response(200, text=feed)),
    )
    monkeypatch.setattr(dns_tasks, "create_async_engine", lambda *a, **kw: _NullEngine())

    @contextlib.asynccontextmanager
    async def _cm():  # type: ignore[no-untyped-def]
        yield db_session

    monkeypatch.setattr(dns_tasks, "async_sessionmaker", lambda *a, **kw: _cm)
    monkeypatch.setattr(dns_tasks, "publish_wake", _noop_publish)

    bl = DNSBlockList(
        name="ag",
        source_type="url",
        feed_url="https://93.184.216.34/f.txt",
        feed_format="adblock",
        feed_entries_are_wildcard=list_wildcard,
    )
    db_session.add(bl)
    await db_session.flush()
    # A previous refresh stored ``exact.example.net`` as a plain wildcard row.
    db_session.add(
        DNSBlockListEntry(
            list_id=bl.id,
            domain="exact.example.net",
            entry_type="block",
            source="feed",
            is_wildcard=True,
        )
    )
    await db_session.commit()

    out = await dns_tasks._refresh_blocklist_feed_async(str(bl.id))

    assert out["status"] == "success"
    rows = (
        await db_session.execute(
            select(DNSBlockListEntry.domain, DNSBlockListEntry.is_wildcard).where(
                DNSBlockListEntry.list_id == bl.id
            )
        )
    ).all()
    assert {d: w for d, w in rows} == {
        "plain.example.com": list_wildcard,
        "*.sub.example.org": False,
        "exact.example.net": False,
    }
    await db_session.refresh(bl)
    assert bl.entry_count == 3
