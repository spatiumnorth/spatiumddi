"""RPZ zone-file rendering on the agent (issue #878).

The agent is the live RPZ renderer: the control plane ships an
effective blocklist in the config bundle and the agent writes the zone
file BIND loads. These tests pin the rdata it emits per entry shape,
because a malformed line does not degrade to "that one entry does not
work" — BIND refuses to load the zone, and the whole blocklist stops
being enforced.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from spatium_dns_agent.drivers.bind9 import Bind9Driver, sinkhole_rdatas


def _render(tmp_path: Path, entries: list[dict], exceptions: list[str] | None = None) -> list[str]:
    driver = Bind9Driver(state_dir=tmp_path)
    out = tmp_path / "rpz.zone"
    driver._write_rpz_zone_file(
        out,
        {
            "rpz_zone_name": "spatium-blocklist.rpz.",
            "entries": entries,
            "exceptions": exceptions or [],
        },
    )
    return [
        line
        for line in out.read_text().splitlines()
        if line and not line.startswith(("$TTL", "@"))
    ]


def test_block_and_sinkhole_rdata(tmp_path: Path) -> None:
    lines = _render(
        tmp_path,
        [
            {"domain": "ads.example.test", "action": "block", "block_mode": "nxdomain"},
            {"domain": "drop.example.test", "action": "block", "block_mode": "sinkhole"},
        ],
    )
    assert "ads.example.test CNAME ." in lines
    # #2124 — local data, never ``rpz-drop`` (which answers nothing).
    assert "drop.example.test A 0.0.0.0" in lines
    assert "drop.example.test AAAA ::" in lines
    assert not any("rpz-drop" in line for line in lines)


def test_redirect_to_hostname_is_a_cname(tmp_path: Path) -> None:
    """SafeSearch rewrites point at a name, not an address.

    Before #878 this path emitted ``CNAME`` unconditionally, which is
    right here — the regression risk is the opposite direction, so both
    are pinned.
    """
    lines = _render(
        tmp_path,
        [
            {
                "domain": "www.google.com",
                "action": "redirect",
                "block_mode": "nxdomain",
                "target": "forcesafesearch.google.com",
            }
        ],
    )
    assert lines == ["www.google.com CNAME forcesafesearch.google.com."]


def test_redirect_to_an_ip_is_an_address_record(tmp_path: Path) -> None:
    """``CNAME 1.2.3.4.`` is a CNAME to a name that does not exist, so
    the redirect silently resolves to nothing. The model documents the
    target as "the IP/hostname to return instead", so both must work."""
    lines = _render(
        tmp_path,
        [
            {
                "domain": "v4.example.test",
                "action": "redirect",
                "block_mode": "nxdomain",
                "target": "192.0.2.10",
            },
            {
                "domain": "v6.example.test",
                "action": "redirect",
                "block_mode": "nxdomain",
                "target": "2001:db8::1",
            },
        ],
    )
    assert "v4.example.test A 192.0.2.10" in lines
    assert "v6.example.test AAAA 2001:db8::1" in lines


def test_wildcard_covers_the_apex_as_well_as_subdomains(tmp_path: Path) -> None:
    """An RPZ wildcard matches subdomains only, so a `*.x`-only rule
    leaves `x` itself resolving — both lines are required."""
    lines = _render(
        tmp_path,
        [{"domain": "bad.example.test", "action": "block", "block_mode": "nxdomain",
          "is_wildcard": True}],
    )
    assert lines == ["bad.example.test CNAME .", "*.bad.example.test CNAME ."]


def test_wildcard_redirect_keeps_one_rdata_for_both_lines(tmp_path: Path) -> None:
    lines = _render(
        tmp_path,
        [{"domain": "search.example.test", "action": "redirect",
          "block_mode": "nxdomain", "target": "safe.example.test",
          "is_wildcard": True}],
    )
    assert lines == [
        "search.example.test CNAME safe.example.test.",
        "*.search.example.test CNAME safe.example.test.",
    ]


def test_exceptions_render_as_passthru(tmp_path: Path) -> None:
    lines = _render(tmp_path, [], ["allow.example.test"])
    assert lines == [
        "allow.example.test CNAME rpz-passthru.",
        "*.allow.example.test CNAME rpz-passthru.",
    ]


def test_an_excepted_entry_is_not_also_emitted_as_a_block(tmp_path: Path) -> None:
    """Un-blocking a domain a feed lists is what exceptions are FOR.

    Emitting the block line and the passthru line puts two CNAMEs on one
    owner name; BIND rejects the zone outright ("multiple RRs of
    singleton type") and every other entry stops being enforced with it.
    ``validate()`` runs named-checkconf, which does not read zone files,
    so nothing catches it before the reload.
    """
    lines = _render(
        tmp_path,
        [
            {"domain": "ads.example.test", "action": "block",
             "block_mode": "nxdomain", "is_wildcard": True},
            {"domain": "keep.example.test", "action": "block",
             "block_mode": "nxdomain"},
        ],
        ["ADS.example.test"],
    )
    # Matched case-insensitively — DNS names are, so `ADS` and `ads` are
    # the same owner and would collide just the same.
    assert lines == [
        "keep.example.test CNAME .",
        "ADS.example.test CNAME rpz-passthru.",
        "*.ADS.example.test CNAME rpz-passthru.",
    ]
    # No owner name carries two different rdata.
    owners = [line.split(" ", 1)[0].lower() for line in lines]
    assert len(owners) == len(set(owners))


def test_redirect_target_trailing_dot_is_not_doubled(tmp_path: Path) -> None:
    lines = _render(
        tmp_path,
        [{"domain": "a.example.test", "action": "redirect",
          "block_mode": "nxdomain", "target": "safe.example.test."}],
    )
    assert lines == ["a.example.test CNAME safe.example.test."]


def test_one_domain_in_two_lists_emits_one_owner(tmp_path: Path) -> None:
    """Overlapping feeds with different block modes must not kill the zone.

    The effective blocklist concatenates every assigned list without
    deduping, so a domain in two of them arrives twice. If their block
    modes differ the two lines carry different rdata, and BIND answers
    "multiple RRs of singleton type" by refusing the WHOLE zone — every
    other entry stops being enforced with it. Verified against
    named-checkzone: identical duplicates load fine, differing ones do
    not.

    The Family filter (#878) subscribes to four overlapping Hagezi feeds
    in one click, so this went from something you had to assemble by
    hand to one `block_mode` change away.
    """
    lines = _render(
        tmp_path,
        [
            {"domain": "both.example.test", "action": "block",
             "block_mode": "nxdomain"},
            {"domain": "both.example.test", "action": "block",
             "block_mode": "sinkhole"},
            {"domain": "only.example.test", "action": "block",
             "block_mode": "nxdomain"},
        ],
    )
    # First writer wins; the later, differing one is dropped.
    assert lines == [
        "both.example.test CNAME .",
        "only.example.test CNAME .",
    ]


def test_duplicate_owner_check_is_case_insensitive(tmp_path: Path) -> None:
    """DNS names are case-insensitive, so `ADS.x` and `ads.x` are one
    owner and would collide exactly as a same-case pair would."""
    lines = _render(
        tmp_path,
        [
            {"domain": "Dup.example.test", "action": "block",
             "block_mode": "nxdomain"},
            {"domain": "dup.EXAMPLE.test", "action": "block",
             "block_mode": "sinkhole"},
        ],
    )
    assert lines == ["Dup.example.test CNAME ."]


def test_no_owner_name_is_ever_emitted_twice(tmp_path: Path) -> None:
    """The invariant the two tests above are instances of."""
    lines = _render(
        tmp_path,
        [
            {"domain": "a.example.test", "action": "block",
             "block_mode": "nxdomain", "is_wildcard": True},
            {"domain": "A.example.test", "action": "block",
             "block_mode": "sinkhole"},
            {"domain": "b.example.test", "action": "block",
             "block_mode": "nxdomain"},
            {"domain": "exc.example.test", "action": "block",
             "block_mode": "nxdomain"},
        ],
        ["exc.example.test", "EXC.example.test"],
    )
    owners = [line.split(" ", 1)[0].lower() for line in lines]
    assert len(owners) == len(set(owners)), owners


def test_a_redirect_target_that_cannot_be_a_name_is_dropped(tmp_path: Path) -> None:
    """``target`` is free-form on the API and reaches the renderer raw.

    Whitespace splits the rdata into extra fields and an empty label is
    malformed; either makes BIND reject the whole zone, so the entry is
    dropped instead. Confirmed against named-checkzone — note that
    odd-but-parseable targets (a pasted URL, ``host:8080``) DO load, so
    they are deliberately left alone rather than second-guessed.
    """
    lines = _render(
        tmp_path,
        [
            {"domain": "space.example.test", "action": "redirect",
             "block_mode": "nxdomain", "target": "a b.example.test"},
            {"domain": "empty.example.test", "action": "redirect",
             "block_mode": "nxdomain", "target": "..."},
            {"domain": "url.example.test", "action": "redirect",
             "block_mode": "nxdomain", "target": "http://sink.example.test/"},
            {"domain": "ok.example.test", "action": "redirect",
             "block_mode": "nxdomain", "target": "safe.example.test"},
        ],
    )
    assert lines == [
        "url.example.test CNAME http://sink.example.test/.",
        "ok.example.test CNAME safe.example.test.",
    ]


def test_a_dropped_redirect_leaves_the_owner_free(tmp_path: Path) -> None:
    """Dropping the unusable entry must not also suppress a later, valid
    entry for the same domain — the owner name was never emitted."""
    lines = _render(
        tmp_path,
        [
            {"domain": "dup.example.test", "action": "redirect",
             "block_mode": "nxdomain", "target": "a b.example.test"},
            {"domain": "dup.example.test", "action": "block",
             "block_mode": "nxdomain"},
        ],
    )
    assert lines == ["dup.example.test CNAME ."]


def test_streamed_file_is_byte_identical_to_the_joined_render(tmp_path: Path) -> None:
    """#1109 Part 3 — the renderer streams to disk instead of building
    ``"\\n".join(lines) + "\\n"``. The bytes must not change: this pins the
    exact file the old implementation produced for an input covering
    wildcards, both redirect shapes, a dropped redirect, a case-variant
    duplicate across lists, an excepted entry and exceptions."""
    entries = [
        {"domain": "Ads.Example.test.", "action": "block", "is_wildcard": True},
        {"domain": "ads.example.test", "action": "block", "block_mode": "sinkhole"},
        {"domain": "sink.test", "block_mode": "sinkhole"},
        {
            "domain": "redir.test",
            "action": "redirect",
            "target": "safe.example.",
            "is_wildcard": True,
        },
        {"domain": "redir-ip.test", "action": "redirect", "target": "192.0.2.7"},
        {"domain": "bad.test", "action": "redirect", "target": "has space"},
        {"domain": "excepted.test", "action": "block"},
    ]
    out = tmp_path / "sub" / "rpz.zone"
    Bind9Driver(state_dir=tmp_path)._write_rpz_zone_file(
        out,
        {
            "rpz_zone_name": "z.rpz.",
            "entries": entries,
            "exceptions": ["excepted.test", "Excepted.test.", "ok.test"],
        },
    )
    expected = (
        "$TTL 60\n"
        "@ IN SOA localhost. root.localhost. ( 1 3600 600 86400 60 )\n"
        "@ IN NS localhost.\n"
        "Ads.Example.test CNAME .\n"
        "*.Ads.Example.test CNAME .\n"
        "sink.test A 0.0.0.0\n"
        "sink.test AAAA ::\n"
        "redir.test CNAME safe.example.\n"
        "*.redir.test CNAME safe.example.\n"
        "redir-ip.test A 192.0.2.7\n"
        "excepted.test CNAME rpz-passthru.\n"
        "*.excepted.test CNAME rpz-passthru.\n"
        "ok.test CNAME rpz-passthru.\n"
        "*.ok.test CNAME rpz-passthru.\n"
    )
    assert out.read_bytes() == expected.encode()


# ── #2124: sinkhole answers with an address, never by dropping the query ─────


def test_sinkhole_without_an_address_answers_the_unspecified_addresses(
    tmp_path: Path,
) -> None:
    """``rpz-drop`` sent no response, so every blocked lookup hung for the
    client's resolver timeout. A sinkhole answers at once, in both
    families, with 0.0.0.0 / :: when the list names no address."""
    lines = _render(
        tmp_path,
        [
            {
                "domain": "ads.example.test",
                "action": "block",
                "block_mode": "sinkhole",
                "is_wildcard": True,
            }
        ],
    )
    assert lines == [
        "ads.example.test A 0.0.0.0",
        "ads.example.test AAAA ::",
        "*.ads.example.test A 0.0.0.0",
        "*.ads.example.test AAAA ::",
    ]


def test_sinkhole_reads_the_lists_ipv4_address(tmp_path: Path) -> None:
    """The bundle's ``sinkhole_ip`` used to be ignored by this renderer."""
    lines = _render(
        tmp_path,
        [
            {
                "domain": "ads.example.test",
                "action": "block",
                "block_mode": "sinkhole",
                "sinkhole_ip": "192.0.2.53",
            }
        ],
    )
    assert lines == ["ads.example.test A 192.0.2.53", "ads.example.test AAAA ::"]


def test_sinkhole_reads_the_lists_ipv6_address(tmp_path: Path) -> None:
    lines = _render(
        tmp_path,
        [
            {
                "domain": "ads.example.test",
                "action": "block",
                "block_mode": "sinkhole",
                "sinkhole_ip": "2001:DB8::0:53",
            }
        ],
    )
    assert lines == ["ads.example.test A 0.0.0.0", "ads.example.test AAAA 2001:db8::53"]


def test_an_unusable_sinkhole_address_falls_back_rather_than_breaking_the_zone(
    tmp_path: Path,
) -> None:
    """A legacy row the API never validated must not reach the rdata: BIND
    would refuse the whole zone (#878)."""
    lines = _render(
        tmp_path,
        [
            {
                "domain": "ads.example.test",
                "action": "block",
                "block_mode": "sinkhole",
                "sinkhole_ip": "not an ip",
            }
        ],
    )
    assert lines == ["ads.example.test A 0.0.0.0", "ads.example.test AAAA ::"]
    assert sinkhole_rdatas("not an ip")[1] is False
    assert sinkhole_rdatas(None) == (("A 0.0.0.0", "AAAA ::"), True)


def test_a_legacy_refused_mode_renders_nxdomain(tmp_path: Path) -> None:
    """``refused`` has no RPZ action; it always rendered NXDOMAIN here."""
    lines = _render(
        tmp_path,
        [{"domain": "r.example.test", "action": "block", "block_mode": "refused"}],
    )
    assert lines == ["r.example.test CNAME ."]


def test_two_sinkhole_lists_with_different_addresses_keep_one_owner(
    tmp_path: Path,
) -> None:
    """An A beside a different A is a second RRset member, not a collision
    BIND rejects — but it would answer two addresses for one name. First
    writer wins, as for any other differing pair."""
    lines = _render(
        tmp_path,
        [
            {
                "domain": "d.example.test",
                "action": "block",
                "block_mode": "sinkhole",
                "sinkhole_ip": "192.0.2.1",
            },
            {
                "domain": "d.example.test",
                "action": "block",
                "block_mode": "sinkhole",
                "sinkhole_ip": "192.0.2.2",
            },
            {"domain": "d.example.test", "action": "block", "block_mode": "nxdomain"},
        ],
    )
    assert lines == ["d.example.test A 192.0.2.1", "d.example.test AAAA ::"]


_CHECKZONE = shutil.which("named-checkzone")


@pytest.mark.skipif(_CHECKZONE is None, reason="named-checkzone is not installed")
def test_every_block_mode_renders_a_zone_bind_loads(tmp_path: Path) -> None:
    """The rendered zone must load: one bad line takes the whole list down."""
    out = tmp_path / "rpz.zone"
    Bind9Driver(state_dir=tmp_path)._write_rpz_zone_file(
        out,
        {
            "rpz_zone_name": "spatium-blocklist.rpz.",
            "entries": [
                {
                    "domain": "nx.example.test",
                    "action": "block",
                    "block_mode": "nxdomain",
                    "is_wildcard": True,
                },
                {
                    "domain": "sink.example.test",
                    "action": "block",
                    "block_mode": "sinkhole",
                    "is_wildcard": True,
                },
                {
                    "domain": "sink4.example.test",
                    "action": "block",
                    "block_mode": "sinkhole",
                    "sinkhole_ip": "192.0.2.53",
                },
                {
                    "domain": "sink6.example.test",
                    "action": "block",
                    "block_mode": "sinkhole",
                    "sinkhole_ip": "2001:db8::53",
                    "is_wildcard": True,
                },
                {
                    "domain": "bad.example.test",
                    "action": "block",
                    "block_mode": "sinkhole",
                    "sinkhole_ip": "nope",
                },
                {
                    "domain": "old.example.test",
                    "action": "block",
                    "block_mode": "refused",
                },
            ],
            "exceptions": ["ok.example.test"],
        },
    )
    res = subprocess.run(
        [_CHECKZONE, "spatium-blocklist.rpz", str(out)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stdout + res.stderr


def test_feed_exception_shipped_only_as_its_own_carve_out(tmp_path: Path) -> None:
    """#2123 / #2124: an AdGuard-style feed ``@@``-excepts ``x.example.test``,
    which the operator's manual list blocks. The control plane leaves it out
    of the exceptions, so the agent still blocks it; the feed's own
    carve-out ``c.feed.test`` renders as a passthru."""
    out = tmp_path / "rpz.zone"
    Bind9Driver(state_dir=tmp_path)._write_rpz_zone_file(
        out,
        {
            "rpz_zone_name": "z.rpz.",
            "entries": [
                {"domain": "x.example.test", "action": "block"},
                {"domain": "feed.test", "action": "block", "is_wildcard": True},
            ],
            "exceptions": ["c.feed.test"],
        },
    )
    text = out.read_text()
    assert "x.example.test CNAME .\n" in text
    assert "c.feed.test CNAME rpz-passthru.\n" in text
    assert "x.example.test CNAME rpz-passthru." not in text
