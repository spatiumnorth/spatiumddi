"""RPZ zone-file rendering on the agent (issue #878).

The agent is the live RPZ renderer: the control plane ships an
effective blocklist in the config bundle and the agent writes the zone
file BIND loads. These tests pin the rdata it emits per entry shape,
because a malformed line does not degrade to "that one entry does not
work" — BIND refuses to load the zone, and the whole blocklist stops
being enforced.
"""

from __future__ import annotations

from pathlib import Path

from spatium_dns_agent.drivers.bind9 import Bind9Driver


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
    assert "drop.example.test CNAME rpz-drop." in lines


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
        "sink.test CNAME rpz-drop.\n"
        "redir.test CNAME safe.example.\n"
        "*.redir.test CNAME safe.example.\n"
        "redir-ip.test A 192.0.2.7\n"
        "excepted.test CNAME rpz-passthru.\n"
        "*.excepted.test CNAME rpz-passthru.\n"
        "ok.test CNAME rpz-passthru.\n"
        "*.ok.test CNAME rpz-passthru.\n"
    )
    assert out.read_bytes() == expected.encode()
