"""Unit tests for the DNS driver abstraction layer and the BIND9 driver."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from app.drivers.dns import get_driver, register_driver
from app.drivers.dns.base import (
    AclData,
    BlocklistEntry,
    ConfigBundle,
    DNSDriver,
    EffectiveBlocklistData,
    RecordData,
    ServerOptions,
    TrustAnchorData,
    TsigKey,
    ViewData,
    ZoneData,
)
from app.drivers.dns.bind9 import BIND9Driver
from app.services.dns.serial import bump_zone_serial, compute_next_serial

# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def zone() -> ZoneData:
    return ZoneData(
        name="example.com.",
        zone_type="primary",
        kind="forward",
        ttl=3600,
        refresh=86400,
        retry=7200,
        expire=3600000,
        minimum=3600,
        primary_ns="ns1.example.com.",
        admin_email="hostmaster.example.com.",
        serial=2026041401,
        records=(),
    )


@pytest.fixture
def records() -> list[RecordData]:
    return [
        RecordData(name="@", record_type="NS", value="ns1.example.com.", ttl=3600),
        RecordData(name="www", record_type="A", value="10.0.0.1", ttl=300),
        RecordData(name="ipv6", record_type="AAAA", value="2001:db8::1", ttl=300),
        RecordData(name="alias", record_type="CNAME", value="www.example.com.", ttl=300),
        RecordData(name="@", record_type="MX", value="mail.example.com.", ttl=3600, priority=10),
        RecordData(name="@", record_type="TXT", value="v=spf1 -all", ttl=3600),
        RecordData(
            name="_sip._tcp",
            record_type="SRV",
            value="sip.example.com.",
            ttl=3600,
            priority=10,
            weight=20,
            port=5060,
        ),
    ]


@pytest.fixture
def bundle(zone: ZoneData) -> ConfigBundle:
    opts = ServerOptions(
        forwarders=("1.1.1.1", "9.9.9.9"),
        trust_anchors=(
            TrustAnchorData(
                zone_name=".",
                algorithm=8,
                key_tag=20326,
                public_key="AAAA...",
                is_initial_key=True,
            ),
        ),
    )
    return ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="ns1",
        driver="bind9",
        roles=("authoritative",),
        options=opts,
        acls=(AclData(name="trusted", entries=(("10.0.0.0/8", False), ("1.2.3.4", True))),),
        views=(),
        zones=(zone,),
        tsig_keys=(
            TsigKey(
                name="ddns-key.",
                algorithm="hmac-sha256",
                secret="c3VwZXJzZWNyZXRiYXNlNjQ=",
            ),
        ),
        blocklists=(),
        generated_at=datetime(2026, 4, 14, 12, 0, tzinfo=UTC),
    )


# ── Driver registry ──────────────────────────────────────────────────────


def test_registry_returns_bind9() -> None:
    drv = get_driver("bind9")
    assert isinstance(drv, BIND9Driver)
    assert drv.capabilities()["name"] == "bind9"


def test_registry_unknown_driver_raises() -> None:
    with pytest.raises(ValueError):
        get_driver("djbdns")


def test_registry_register_driver_override() -> None:
    class FakeDriver(BIND9Driver):
        name = "fake"

    register_driver("fake-bind", FakeDriver)
    assert isinstance(get_driver("fake-bind"), FakeDriver)


# ── BIND9 rendering ──────────────────────────────────────────────────────


def test_render_zone_config_primary(zone: ZoneData) -> None:
    out = BIND9Driver().render_zone_config(zone)
    assert 'zone "example.com."' in out
    assert "type master;" in out
    assert 'file "/var/cache/bind/zones/example.com.db"' in out


def test_render_zone_config_secondary_with_masters() -> None:
    # Issue #336 — a secondary zone must render ``type slave;`` + a
    # ``masters { ... };`` clause, otherwise named refuses to load it.
    z = ZoneData(
        name="example.com.",
        zone_type="secondary",
        kind="forward",
        ttl=3600,
        refresh=86400,
        retry=7200,
        expire=3600000,
        minimum=3600,
        primary_ns="",
        admin_email="",
        serial=0,
        masters=("192.0.2.1", "192.0.2.2@5353"),
    )
    out = BIND9Driver().render_zone_config(z)
    assert 'zone "example.com."' in out
    assert "type slave;" in out
    assert "192.0.2.1;" in out
    assert "192.0.2.2 port 5353;" in out
    assert "masters {" in out


def test_render_zone_config_stub_with_masters() -> None:
    z = ZoneData(
        name="stub.example.com.",
        zone_type="stub",
        kind="forward",
        ttl=3600,
        refresh=86400,
        retry=7200,
        expire=3600000,
        minimum=3600,
        primary_ns="",
        admin_email="",
        serial=0,
        masters=("198.51.100.5",),
    )
    out = BIND9Driver().render_zone_config(z)
    assert "type stub;" in out
    assert "198.51.100.5;" in out
    assert "masters {" in out


def test_render_zone_file_mixed_records(zone: ZoneData, records: list[RecordData]) -> None:
    out = BIND9Driver().render_zone_file(zone, records)
    assert "$TTL 3600" in out
    assert "example.com. IN SOA ns1.example.com." in out
    assert "2026041401 ; serial" in out
    # Individual record types survive rendering
    assert "www 300 IN A 10.0.0.1" in out
    assert "ipv6 300 IN AAAA 2001:db8::1" in out
    assert "alias 300 IN CNAME www.example.com." in out
    assert "@ 3600 IN MX 10 mail.example.com." in out
    assert '@ 3600 IN TXT "v=spf1 -all"' in out
    assert "_sip._tcp 3600 IN SRV 10 20 5060 sip.example.com." in out


def test_render_zone_file_is_idempotent(zone: ZoneData, records: list[RecordData]) -> None:
    drv = BIND9Driver()
    assert drv.render_zone_file(zone, records) == drv.render_zone_file(zone, records)


def test_render_server_config_includes_acl_and_forwarders(bundle: ConfigBundle) -> None:
    out = BIND9Driver().render_server_config(
        SimpleNamespace(id=bundle.server_id, name=bundle.server_name),
        bundle.options,
        bundle=bundle,
    )
    assert 'acl "trusted"' in out
    assert "10.0.0.0/8;" in out
    assert "!1.2.3.4;" in out
    assert "forwarders { 1.1.1.1; 9.9.9.9; };" in out
    assert "forward first;" in out
    assert 'key "ddns-key."' in out
    assert "algorithm hmac-sha256;" in out
    assert 'zone "example.com."' in out
    # No view wrapping when views=()
    assert 'view "' not in out


def _bundle_with_opts(zone: ZoneData, opts: ServerOptions) -> ConfigBundle:
    return ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="ns1",
        driver="bind9",
        roles=("authoritative",),
        options=opts,
        acls=(),
        views=(),
        zones=(zone,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 4, 14, 12, 0, tzinfo=UTC),
    )


def test_render_server_config_rrl_enabled(zone: ZoneData) -> None:
    """#146 — RRL + amplification directives render into options{}."""
    opts = ServerOptions(
        rrl_enabled=True,
        rrl_responses_per_second=20,
        rrl_window=10,
        rrl_slip=3,
        rrl_qps_scale=250,
        rrl_exempt_clients=("10.0.0.0/8",),
        rrl_log_only=True,
        minimal_responses=True,
        tcp_clients=200,
        clients_per_query=12,
        max_clients_per_query=120,
    )
    out = BIND9Driver().render_server_config(
        SimpleNamespace(id="x", name="ns1"), opts, bundle=_bundle_with_opts(zone, opts)
    )
    assert "rate-limit {" in out
    assert "responses-per-second 20;" in out
    assert "window 10;" in out
    assert "slip 3;" in out
    assert "qps-scale 250;" in out
    assert "exempt-clients { 10.0.0.0/8; };" in out
    assert "log-only yes;" in out
    assert "minimal-responses yes;" in out
    assert "tcp-clients 200;" in out
    assert "clients-per-query 12;" in out
    assert "max-clients-per-query 120;" in out


def test_rrl_exempt_clients_normalized() -> None:
    """#146 review — the schema strips + drops blanks + dedups so neither
    renderer emits an invalid ``exempt-clients { ; };`` stanza."""
    from app.api.v1.dns.router import ServerOptionsUpdate

    body = ServerOptionsUpdate(rrl_exempt_clients=[" 10.0.0.0/8 ", "", "   ", "10.0.0.0/8", "any"])
    assert body.rrl_exempt_clients == ["10.0.0.0/8", "any"]
    # None (field absent) passes through untouched — means "not provided".
    assert ServerOptionsUpdate().rrl_exempt_clients is None


def test_rrl_nullable_clear_precondition() -> None:
    """#146 review — the update handler re-injects explicit nulls because
    exclude_none drops them. Verify the precondition the fix relies on: an
    explicitly-set None is in model_fields_set but NOT in the exclude_none
    dump (so without re-injection the clear would be silently lost)."""
    from app.api.v1.dns.router import ServerOptionsUpdate

    body = ServerOptionsUpdate(rrl_qps_scale=None, tcp_clients=None)
    assert "rrl_qps_scale" in body.model_fields_set
    assert "tcp_clients" in body.model_fields_set
    dumped = body.model_dump(exclude_none=True)
    assert "rrl_qps_scale" not in dumped
    assert "tcp_clients" not in dumped


def test_render_server_config_rrl_default_noop(zone: ZoneData) -> None:
    """Default options render NO rate-limit / amplification config — adding
    the feature is a no-op for groups that haven't opted in."""
    out = BIND9Driver().render_server_config(
        SimpleNamespace(id="x", name="ns1"),
        ServerOptions(),
        bundle=_bundle_with_opts(zone, ServerOptions()),
    )
    assert "rate-limit {" not in out
    assert "minimal-responses" not in out
    assert "tcp-clients" not in out


def test_render_server_config_query_log_switch(zone: ZoneData) -> None:
    """#2249 — an explicit ``querylog yes;`` with query logging on, mirroring
    the agent renderer, and nothing with it off so an existing group's
    preview is unchanged."""
    on = ServerOptions(query_log_enabled=True, response_log_enabled=True)
    out = BIND9Driver().render_server_config(
        SimpleNamespace(id="x", name="ns1"), on, bundle=_bundle_with_opts(zone, on)
    )
    assert "querylog yes;" in out
    assert "responselog yes;" in out
    off = ServerOptions()
    out = BIND9Driver().render_server_config(
        SimpleNamespace(id="x", name="ns1"), off, bundle=_bundle_with_opts(zone, off)
    )
    assert "querylog" not in out


def test_render_server_config_split_horizon_views() -> None:
    """Issue #24: the same zone name materialises once per view (with
    each view's filtered records pre-expanded by the bundle builder),
    and the driver wraps each copy in its own ``view { … }`` block —
    the stanza dict is keyed by (view_name, name) so the copies don't
    collapse."""

    def _z(view_name: str) -> ZoneData:
        return ZoneData(
            name="example.com.",
            zone_type="primary",
            kind="forward",
            ttl=3600,
            refresh=86400,
            retry=7200,
            expire=3600000,
            minimum=3600,
            primary_ns="ns1.example.com.",
            admin_email="hostmaster.example.com.",
            serial=2026041401,
            records=(),
            view_name=view_name,
        )

    b = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="ns1",
        driver="bind9",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(
            ViewData(
                name="internal",
                match_clients=("10.0.0.0/8",),
                match_destinations=(),
                recursion=True,
                order=0,
            ),
            ViewData(
                name="external",
                match_clients=("any",),
                match_destinations=(),
                recursion=False,
                order=1,
            ),
        ),
        zones=(_z("internal"), _z("external")),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 4, 14, 12, 0, tzinfo=UTC),
    )
    out = BIND9Driver().render_server_config(
        SimpleNamespace(id=b.server_id, name=b.server_name), b.options, bundle=b
    )
    assert 'view "internal" {' in out
    assert 'view "external" {' in out
    assert "match-clients { 10.0.0.0/8; };" in out
    # The zone stanza appears inside BOTH view blocks (keyed by
    # (view_name, name), so neither copy is dropped).
    assert out.count('zone "example.com."') == 2


def test_render_server_config_views_put_rpz_inside_view() -> None:
    """Issue #24 (review): with views present, RPZ zones + the
    response-policy directive must render INSIDE the owning view block,
    never at the top level — BIND9 rejects top-level ``zone {}``
    alongside ``view {}``. A ``view_name=None`` blocklist is group-level
    and lands only in a view with no zone of its own (#1706)."""
    b = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="ns1",
        driver="bind9",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(
            ViewData(
                name="internal",
                match_clients=("10.0.0.0/8",),
                match_destinations=(),
                recursion=True,
                order=0,
            ),
        ),
        zones=(),
        tsig_keys=(),
        blocklists=(
            EffectiveBlocklistData(
                rpz_zone_name="spatium-blocklist-internal.rpz.",
                entries=(
                    BlocklistEntry(
                        domain="ads.example.com",
                        action="block",
                        block_mode="nxdomain",
                        sinkhole_ip=None,
                        target=None,
                        is_wildcard=False,
                    ),
                ),
                exceptions=frozenset(),
                view_name="internal",
            ),
        ),
        generated_at=datetime(2026, 4, 14, 12, 0, tzinfo=UTC),
    )
    out = BIND9Driver().render_server_config(
        SimpleNamespace(id=b.server_id, name=b.server_name), b.options, bundle=b
    )
    # The RPZ zone declaration + response-policy live inside the view
    # block, not at top level. Slice from the view header onward.
    view_block = out.split('view "internal" {', 1)[1]
    assert "response-policy {" in view_block
    assert 'zone "spatium-blocklist-internal.rpz.";' in view_block
    # And the RPZ zone is NOT declared before the view block opens.
    preamble = out.split('view "internal" {', 1)[0]
    assert 'zone "spatium-blocklist-internal.rpz." {' not in preamble


def test_render_server_config_group_rpz_only_in_a_view_without_its_own_1706() -> None:
    """#1706: a view's own RPZ zone already folds in the group's lists, so the
    group zone is not loaded beside it; a view with no zone of its own still
    falls back to it. Mirrors the agent's BIND9 renderer."""

    def _bl(zone: str, view: str | None) -> EffectiveBlocklistData:
        return EffectiveBlocklistData(
            rpz_zone_name=zone,
            entries=(
                BlocklistEntry(
                    domain="ads.example.com",
                    action="block",
                    block_mode="nxdomain",
                    sinkhole_ip=None,
                    target=None,
                    is_wildcard=False,
                ),
            ),
            exceptions=frozenset(),
            view_name=view,
        )

    def _view(name: str, clients: str, order: int) -> ViewData:
        return ViewData(
            name=name,
            match_clients=(clients,),
            match_destinations=(),
            recursion=True,
            order=order,
        )

    b = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="ns1",
        driver="bind9",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(_view("internal", "10.0.0.0/8", 0), _view("external", "any", 1)),
        zones=(),
        tsig_keys=(),
        blocklists=(
            _bl("spatium-blocklist-internal.rpz.", "internal"),
            _bl("spatium-blocklist.rpz.", None),
        ),
        generated_at=datetime(2026, 4, 14, 12, 0, tzinfo=UTC),
    )
    out = BIND9Driver().render_server_config(
        SimpleNamespace(id=b.server_id, name=b.server_name), b.options, bundle=b
    )
    internal = out.split('view "internal" {', 1)[1].split('view "external" {', 1)[0]
    external = out.split('view "external" {', 1)[1]
    assert 'zone "spatium-blocklist-internal.rpz.";' in internal
    assert 'zone "spatium-blocklist.rpz."' not in internal
    assert 'zone "spatium-blocklist.rpz.";' in external
    assert "spatium-blocklist-internal" not in external


# ── RPZ rendering ─────────────────────────────────────────────────────────


def test_render_rpz_zone_nxdomain_and_sinkhole_and_exception() -> None:
    bl = EffectiveBlocklistData(
        rpz_zone_name="spatium-blocklist.rpz.",
        entries=(
            BlocklistEntry(
                domain="ads.example.com",
                action="block",
                block_mode="nxdomain",
                sinkhole_ip=None,
                target=None,
                is_wildcard=False,
            ),
            BlocklistEntry(
                domain="tracker.example.net",
                action="block",
                block_mode="sinkhole",
                sinkhole_ip="10.0.0.250",
                target=None,
                is_wildcard=True,
            ),
            BlocklistEntry(
                domain="redirect.example.org",
                action="redirect",
                block_mode="nxdomain",
                sinkhole_ip=None,
                target="1.2.3.4",
                is_wildcard=False,
            ),
            BlocklistEntry(
                domain="allowed.example.com",
                action="block",
                block_mode="nxdomain",
                sinkhole_ip=None,
                target=None,
                is_wildcard=False,
            ),
        ),
        exceptions=frozenset({"allowed.example.com"}),
    )
    out = BIND9Driver().render_rpz_zone(bl)
    assert "spatium-blocklist.rpz. IN SOA" in out
    assert "ads.example.com IN CNAME ." in out
    assert "*.tracker.example.net IN A 10.0.0.250" in out
    assert "*.tracker.example.net IN AAAA ::" in out  # #2124
    assert "redirect.example.org IN A 1.2.3.4" in out
    assert "allowed.example.com" not in out  # exception excluded


def test_render_rpz_redirect_to_hostname_is_a_cname() -> None:
    """A redirect target is "the IP or hostname to return instead", and
    the two need different record types. Emitting ``IN A
    forcesafesearch.google.com`` is not merely wrong for that entry —
    BIND rejects the malformed rdata and refuses to load the zone, which
    takes the whole blocklist offline. Issue #878.
    """
    bl = EffectiveBlocklistData(
        rpz_zone_name="spatium-blocklist.rpz.",
        entries=(
            BlocklistEntry(
                domain="www.google.com",
                action="redirect",
                block_mode="nxdomain",
                sinkhole_ip=None,
                target="forcesafesearch.google.com",
                is_wildcard=False,
            ),
            BlocklistEntry(
                domain="v6.example.com",
                action="redirect",
                block_mode="nxdomain",
                sinkhole_ip=None,
                target="2001:db8::1",
                is_wildcard=False,
            ),
        ),
        exceptions=frozenset(),
    )
    out = BIND9Driver().render_rpz_zone(bl)
    assert "www.google.com IN CNAME forcesafesearch.google.com." in out
    assert "v6.example.com IN AAAA 2001:db8::1" in out


def test_render_rpz_wildcard_covers_the_apex_too() -> None:
    """An RPZ wildcard matches subdomains ONLY.

    Since #878 every feed-sourced row carries ``is_wildcard=True``, so
    emitting just ``*.ads.example.com`` would stop blocking the very
    domain the feed names. Both lines are required, and the agent-side
    renderer emits exactly the same pair — the two must not diverge.
    """
    bl = EffectiveBlocklistData(
        rpz_zone_name="spatium-blocklist.rpz.",
        entries=(
            BlocklistEntry(
                domain="ads.example.com",
                action="block",
                block_mode="nxdomain",
                sinkhole_ip=None,
                target=None,
                is_wildcard=True,
            ),
        ),
        exceptions=frozenset(),
    )
    out = BIND9Driver().render_rpz_zone(bl)
    assert "ads.example.com IN CNAME ." in out
    assert "*.ads.example.com IN CNAME ." in out


def test_render_rpz_emits_each_owner_name_once() -> None:
    """Overlapping lists must not produce two CNAMEs at one owner.

    BIND answers that with "multiple RRs of singleton type" and refuses
    the ENTIRE zone, so one collision stops every other entry being
    enforced. The effective blocklist concatenates assigned lists
    without deduping, so a domain in two of them — with different block
    modes, e.g. one list switched to sinkhole — arrives here as two
    entries carrying different rdata. Verified against named-checkzone:
    identical duplicates load, differing ones do not.
    """

    def _entry(domain: str, mode: str) -> BlocklistEntry:
        return BlocklistEntry(
            domain=domain,
            action="block",
            block_mode=mode,
            sinkhole_ip="10.0.0.250" if mode == "sinkhole" else None,
            target=None,
            is_wildcard=True,
        )

    bl = EffectiveBlocklistData(
        rpz_zone_name="spatium-blocklist.rpz.",
        entries=(
            _entry("both.example.com", "nxdomain"),
            _entry("both.example.com", "sinkhole"),
            # Case difference is not a different owner — DNS names are
            # case-insensitive, so this would collide just the same.
            _entry("BOTH.example.com", "refused"),
            _entry("only.example.com", "nxdomain"),
        ),
        exceptions=frozenset(),
    )
    out = BIND9Driver().render_rpz_zone(bl)
    # Exact list, not a uniqueness check over a filtered slice: this also
    # pins that BOTH forms of each surviving wildcard entry are emitted,
    # and that the later sinkhole/refused duplicates contributed nothing.
    # The apex SOA/NS records are the zone's own, not blocklist entries.
    apex = "spatium-blocklist.rpz."
    rendered = [ln.strip() for ln in out.splitlines() if " IN " in ln and not ln.startswith(apex)]
    assert rendered == [
        "both.example.com IN CNAME .",
        "*.both.example.com IN CNAME .",
        "only.example.com IN CNAME .",
        "*.only.example.com IN CNAME .",
    ]


# ── Serial bumping ────────────────────────────────────────────────────────


def test_serial_bump_rfc1912_same_day() -> None:
    now = datetime(2026, 4, 14, tzinfo=UTC)
    assert compute_next_serial(2026041400, now=now) == 2026041401
    assert compute_next_serial(2026041499, now=now) == 2026041500  # monotonic overflow


def test_serial_bump_rfc1912_new_day() -> None:
    now = datetime(2026, 4, 14, tzinfo=UTC)
    # previous day's serial rolls to today base
    assert compute_next_serial(2026041305, now=now) == 2026041400


def test_serial_bump_future_serial_stays_monotonic() -> None:
    now = datetime(2026, 4, 14, tzinfo=UTC)
    # A serial ahead of today (e.g. admin set the clock wrong once) must not decrease
    assert compute_next_serial(2030010100, now=now) == 2030010101


def test_serial_bump_non_rfc_serial_falls_back() -> None:
    now = datetime(2026, 4, 14, tzinfo=UTC)
    assert compute_next_serial(0, now=now) == 2026041400
    assert compute_next_serial(42, now=now) == 2026041400
    assert compute_next_serial(2026041400 + 5, now=now) == 2026041400 + 6


def test_bump_zone_serial_mutates_and_returns() -> None:
    z = SimpleNamespace(last_serial=2026041400)
    now = datetime(2026, 4, 14, tzinfo=UTC)
    nxt = bump_zone_serial(z, now=now)
    assert nxt == 2026041401
    assert z.last_serial == 2026041401


# ── Validation ───────────────────────────────────────────────────────────


def test_validate_config_ok(bundle: ConfigBundle) -> None:
    ok, errs = BIND9Driver().validate_config(bundle)
    assert ok is True
    assert errs == []


def test_validate_config_catches_missing_trailing_dot(bundle: ConfigBundle) -> None:
    bad_zone = ZoneData(
        name="no-dot",
        zone_type="primary",
        kind="forward",
        ttl=60,
        refresh=60,
        retry=60,
        expire=60,
        minimum=60,
        primary_ns="",
        admin_email="",
        serial=1,
    )
    broken = ConfigBundle(
        server_id=bundle.server_id,
        server_name=bundle.server_name,
        driver="bind9",
        roles=bundle.roles,
        options=bundle.options,
        acls=bundle.acls,
        views=bundle.views,
        zones=(bad_zone,),
        tsig_keys=bundle.tsig_keys,
        blocklists=bundle.blocklists,
        generated_at=bundle.generated_at,
    )
    ok, errs = BIND9Driver().validate_config(broken)
    assert ok is False
    assert any("must end with '.'" in e for e in errs)


def test_config_bundle_etag_is_deterministic(bundle: ConfigBundle) -> None:
    e1 = bundle.compute_etag()
    e2 = bundle.compute_etag()
    assert e1 == e2
    assert e1.startswith("sha256:")


def test_driver_is_dnsdriver_subclass() -> None:
    assert issubclass(BIND9Driver, DNSDriver)


# ── Query-log channel settings (#2265) ───────────────────────────────────


def _logging_stanza(zone: ZoneData, **opts: object) -> str:
    base = {"forwarders": ("1.1.1.1",), "query_log_enabled": True}
    b = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="ns1",
        driver="bind9",
        roles=("authoritative",),
        options=ServerOptions(**{**base, **opts}),  # type: ignore[arg-type]
        acls=(),
        views=(),
        zones=(zone,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 4, 14, 12, 0, tzinfo=UTC),
    )
    out = BIND9Driver().render_server_config(
        SimpleNamespace(id=b.server_id, name=b.server_name), b.options, bundle=b
    )
    start = out.index("channel queries_channel")
    return out[start : out.index("};", start) + 2]


def test_query_log_defaults_render_the_historical_channel(zone: ZoneData) -> None:
    assert _logging_stanza(zone) == (
        "channel queries_channel {\n"
        '        file "/var/log/named/queries.log" versions 5 size 50m;\n'
        "        severity info;\n"
        "        print-category yes;\n"
        "        print-severity yes;\n"
        "        print-time yes;\n"
        "    };"
    )


def test_query_log_severity_and_print_flags_reach_named_conf(zone: ZoneData) -> None:
    out = _logging_stanza(
        zone,
        query_log_severity="debug 3",
        query_log_print_category=False,
        query_log_print_severity=False,
    )
    assert "severity debug 3;" in out
    assert "print-category no;" in out
    assert "print-severity no;" in out


def test_query_log_channel_and_file_stay_on_the_shipper_file(zone: ZoneData) -> None:
    # A stored syslog / odd-path / too-quiet row must not starve the
    # DNS Queries tab: the render ignores channel + file and floors severity.
    out = _logging_stanza(
        zone,
        query_log_channel="syslog",
        query_log_file="/var/log/named/x.log",
        query_log_severity="error",
        query_log_print_time=False,
    )
    assert 'file "/var/log/named/queries.log" versions 5 size 50m;' in out
    assert "syslog" not in out
    assert "severity info;" in out
    assert "print-time yes;" in out
