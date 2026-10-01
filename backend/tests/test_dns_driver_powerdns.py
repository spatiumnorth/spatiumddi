"""Unit tests for the PowerDNS authoritative driver (issue #127)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from app.drivers.dns import get_driver
from app.drivers.dns.base import (
    AclData,
    BlocklistEntry,
    ConfigBundle,
    EffectiveBlocklistData,
    RecordData,
    ServerOptions,
    TsigKey,
    ViewData,
    ZoneData,
)
from app.drivers.dns.powerdns import (
    PowerDNSDriver,
    render_pdns_conf,
)


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
        serial=2026050701,
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
    return ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="pdns1",
        driver="powerdns",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=(zone,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
    )


# ── Registry ──────────────────────────────────────────────────────────────


def test_registry_returns_powerdns() -> None:
    drv = get_driver("powerdns")
    assert isinstance(drv, PowerDNSDriver)
    assert drv.capabilities()["name"] == "powerdns"


# ── Rendering ─────────────────────────────────────────────────────────────


def test_render_pdns_conf_lmdb_defaults() -> None:
    out = render_pdns_conf(api_key="test-key-12345")
    assert "launch=lmdb" in out
    assert "lmdb-filename=/var/lib/powerdns/pdns.lmdb" in out
    assert "api=yes" in out
    assert "api-key=test-key-12345" in out
    # API webserver bound to loopback only — agent loopback only.
    assert "webserver-address=127.0.0.1" in out
    assert "webserver-allow-from=127.0.0.1,::1" in out


def test_render_pdns_conf_turns_off_security_polling() -> None:
    # The agent's renderer does the same (#1353); an absent line would leave
    # PowerDNS's default secpoll ON, phoning secpoll.powerdns.com.
    assert "security-poll-suffix=" in render_pdns_conf(api_key="k").splitlines()


def test_render_pdns_conf_rejects_unsupported_backend() -> None:
    with pytest.raises(ValueError, match="Phase 1 only supports backend='lmdb'"):
        render_pdns_conf(api_key="x", backend="gpgsql")


def test_render_zone_config_returns_empty_for_lmdb_storage(zone: ZoneData) -> None:
    # PowerDNS LMDB stores zones in the database, not in per-zone
    # config stanzas. The driver returns an empty string by design.
    assert PowerDNSDriver().render_zone_config(zone) == ""


def test_render_zone_file_emits_pdns_api_payload(zone: ZoneData, records: list[RecordData]) -> None:
    out = PowerDNSDriver().render_zone_file(zone, records)
    payload = json.loads(out)

    assert payload["name"] == "example.com."
    assert payload["kind"] == "Native"
    assert payload["serial"] == zone.serial

    rrsets = {(r["name"], r["type"]): r for r in payload["rrsets"]}

    # Apex MX with stitched-in priority on content
    mx = rrsets[("example.com.", "MX")]
    assert mx["records"][0]["content"] == "10 mail.example.com."

    # SRV with priority/weight/port stitched into content
    srv = rrsets[("_sip._tcp.example.com.", "SRV")]
    assert srv["records"][0]["content"] == "10 20 5060 sip.example.com."

    # TXT quoted per RFC 1035
    txt = rrsets[("example.com.", "TXT")]
    assert txt["records"][0]["content"] == '"v=spf1 -all"'

    # Apex NS resolves to the zone FQDN
    ns = rrsets[("example.com.", "NS")]
    assert ns["records"][0]["content"] == "ns1.example.com."

    # Sub-record names get qualified
    a = rrsets[("www.example.com.", "A")]
    assert a["records"][0]["content"] == "10.0.0.1"


def test_render_zone_file_is_deterministic(zone: ZoneData, records: list[RecordData]) -> None:
    out1 = PowerDNSDriver().render_zone_file(zone, records)
    out2 = PowerDNSDriver().render_zone_file(zone, records)
    assert out1 == out2


def test_render_rpz_zone_returns_empty_string() -> None:
    # PowerDNS-Authoritative does not consume RPZ — that's a recursor
    # feature. Driver returns "" so the bundle hashes deterministically.
    bl = EffectiveBlocklistData(
        rpz_zone_name="spatium-blocklist.rpz.",
        entries=(
            BlocklistEntry(
                domain="ads.example.org",
                action="block",
                block_mode="nxdomain",
                sinkhole_ip=None,
                target=None,
                is_wildcard=False,
            ),
        ),
        exceptions=frozenset(),
    )
    assert PowerDNSDriver().render_rpz_zone(bl) == ""


# ── Validation ────────────────────────────────────────────────────────────


def test_validate_config_ok(bundle: ConfigBundle) -> None:
    ok, errors = PowerDNSDriver().validate_config(bundle)
    assert ok is True
    assert errors == []


def test_validate_config_rejects_views(bundle: ConfigBundle) -> None:
    bundle.views = (
        ViewData(
            name="internal",
            match_clients=("10.0.0.0/8",),
            match_destinations=(),
            recursion=False,
            order=1,
        ),
    )
    ok, errors = PowerDNSDriver().validate_config(bundle)
    assert ok is False
    assert any("does not support views" in e for e in errors)


def test_validate_config_rejects_unsupported_record_types(zone: ZoneData) -> None:
    bad = ZoneData(
        name="example.com.",
        zone_type="primary",
        kind="forward",
        ttl=zone.ttl,
        refresh=zone.refresh,
        retry=zone.retry,
        expire=zone.expire,
        minimum=zone.minimum,
        primary_ns=zone.primary_ns,
        admin_email=zone.admin_email,
        serial=zone.serial,
        records=(
            # DNSKEY is a real DNSSEC record type pdns serves natively
            # but SpatiumDDI deliberately doesn't expose to operators —
            # keys are auto-managed once Phase 3c online DNSSEC lands.
            # Stand-in for "valid pdns type, intentionally not in our
            # operator-facing supported set".
            RecordData(
                name="@",
                record_type="DNSKEY",
                value="257 3 8 AwEAAa...",
                ttl=300,
            ),
        ),
    )
    bundle = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="pdns1",
        driver="powerdns",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=(bad,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
    )
    ok, errors = PowerDNSDriver().validate_config(bundle)
    assert ok is False
    assert any("DNSKEY" in e for e in errors)


def test_validate_config_accepts_alias_record(zone: ZoneData) -> None:
    # Phase 3a — ALIAS lands as a first-class record type.
    aliased = ZoneData(
        name="example.com.",
        zone_type="primary",
        kind="forward",
        ttl=zone.ttl,
        refresh=zone.refresh,
        retry=zone.retry,
        expire=zone.expire,
        minimum=zone.minimum,
        primary_ns=zone.primary_ns,
        admin_email=zone.admin_email,
        serial=zone.serial,
        records=(
            RecordData(
                name="@",
                record_type="ALIAS",
                value="lb.elsewhere.example.net.",
                ttl=300,
            ),
        ),
    )
    bundle = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="pdns1",
        driver="powerdns",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=(aliased,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
    )
    ok, errors = PowerDNSDriver().validate_config(bundle)
    assert ok is True
    assert errors == []


def test_render_zone_file_emits_alias_apex(zone: ZoneData) -> None:
    # ALIAS at apex is the canonical reason to use it — CNAME-at-apex
    # is illegal per RFC 1034 §3.6.2 and PowerDNS's ALIAS resolves the
    # target at query time and serves the resulting A / AAAA. The
    # rendered API payload is identical in shape to a CNAME — the
    # type discriminator is enough.
    records = [
        RecordData(name="@", record_type="ALIAS", value="lb.example.net.", ttl=60),
    ]
    out = PowerDNSDriver().render_zone_file(zone, records)
    payload = json.loads(out)
    rrsets = {(r["name"], r["type"]): r for r in payload["rrsets"]}
    alias = rrsets[("example.com.", "ALIAS")]
    assert alias["records"][0]["content"] == "lb.example.net."
    assert alias["ttl"] == 60


def test_validate_config_accepts_lua_record(zone: ZoneData) -> None:
    # Phase 3b — LUA records are first-class. Snippet text is
    # opaque to the driver; pdns evaluates it at query time when
    # ``ENABLE-LUA-RECORDS`` zone metadata is set.
    luaful = ZoneData(
        name="example.com.",
        zone_type="primary",
        kind="forward",
        ttl=zone.ttl,
        refresh=zone.refresh,
        retry=zone.retry,
        expire=zone.expire,
        minimum=zone.minimum,
        primary_ns=zone.primary_ns,
        admin_email=zone.admin_email,
        serial=zone.serial,
        records=(
            RecordData(
                name="weighted",
                record_type="LUA",
                value="A \"pickrandom({'10.0.0.1', '10.0.0.2'})\"",
                ttl=60,
            ),
        ),
    )
    bundle = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="pdns1",
        driver="powerdns",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=(luaful,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
    )
    ok, errors = PowerDNSDriver().validate_config(bundle)
    assert ok is True
    assert errors == []


def test_render_zone_file_emits_lua_snippet_verbatim(zone: ZoneData) -> None:
    # The LUA value carries the whole RTYPE + snippet payload; the
    # driver passes it through unmodified (no TXT-quote, no MX-prio
    # stitching). PowerDNS parses it server-side.
    snippet = 'A \'pickrandom({"10.0.0.1","10.0.0.2"})\''
    records = [RecordData(name="weighted", record_type="LUA", value=snippet, ttl=60)]
    out = PowerDNSDriver().render_zone_file(zone, records)
    payload = json.loads(out)
    rrsets = {(r["name"], r["type"]): r for r in payload["rrsets"]}
    lua = rrsets[("weighted.example.com.", "LUA")]
    assert lua["records"][0]["content"] == snippet
    assert lua["ttl"] == 60


def test_validate_config_blocklists_are_warned_not_errored(
    zone: ZoneData,
) -> None:
    # Blocklists are valid bundle state; the agent just skips applying
    # them on PowerDNS hosts. The validator allows them through.
    bl = EffectiveBlocklistData(
        rpz_zone_name="spatium-blocklist.rpz.",
        entries=(),
        exceptions=frozenset(),
    )
    bundle = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="pdns1",
        driver="powerdns",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(AclData(name="any", entries=()),),
        views=(),
        zones=(zone,),
        tsig_keys=(TsigKey(name="k.", algorithm="hmac-sha256", secret="c3VwZXJzZWNyZXQ="),),
        blocklists=(bl,),
        generated_at=datetime(2026, 5, 7, 12, 0, tzinfo=UTC),
    )
    ok, errors = PowerDNSDriver().validate_config(bundle)
    assert ok is True
    assert errors == []


# ── Capabilities ──────────────────────────────────────────────────────────


def test_capabilities_alias_lua_dnssec_catalog_landed() -> None:
    caps = PowerDNSDriver().capabilities()
    # Phase 3a — ALIAS landed.
    assert caps["alias_records"] is True
    assert "ALIAS" in caps["record_types"]
    # Phase 3b — LUA landed.
    assert caps["lua_records"] is True
    assert "LUA" in caps["record_types"]
    # Phase 3c — online DNSSEC landed (agent-side sign/unsign + REST
    # gate via _DRIVER_GATED_OPERATIONS).
    assert caps["dnssec_inline_signing"] is True
    # Phase 3d — catalog zones (producer-only — PowerDNS 4.9 doesn't
    # auto-consume; pdns 4.10+ would unlock full producer/consumer).
    assert caps["catalog_zones"] == "producer-only"
    # Still pending: views (#24 cross-design), RPZ (recursor-only).
    assert caps["views"] is False
    assert caps["rpz"] is False
    assert caps["incremental_updates"] == "rest_api"
    assert "A" in caps["record_types"]
    assert "AAAA" in caps["record_types"]
