"""Unit tests for the Technitium DNS Server driver (v1 — primary zones +
standard record CRUD)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest

from app.drivers.dns import get_driver
from app.drivers.dns.base import (
    BlocklistEntry,
    ConfigBundle,
    EffectiveBlocklistData,
    RecordData,
    ServerOptions,
    ViewData,
    ZoneData,
)
from app.drivers.dns.technitium import TechnitiumDriver


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
        serial=2026072701,
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
        server_name="technitium1",
        driver="technitium",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=(zone,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
    )


# ── Registry ──────────────────────────────────────────────────────────────


def test_registry_returns_technitium() -> None:
    drv = get_driver("technitium")
    assert isinstance(drv, TechnitiumDriver)
    assert drv.capabilities()["name"] == "technitium"


# ── Rendering ─────────────────────────────────────────────────────────────


def test_render_server_config_redacts_token() -> None:
    out = TechnitiumDriver().render_server_config(None, ServerOptions())
    payload = json.loads(out)
    assert payload["api_token"] == "<agent-generated>"


def test_render_zone_config_returns_empty_string(zone: ZoneData) -> None:
    # Technitium stores zones in its own internal store, not in per-zone
    # config stanzas. The driver returns an empty string by design.
    assert TechnitiumDriver().render_zone_config(zone) == ""


def test_render_zone_file_emits_technitium_api_payload(
    zone: ZoneData, records: list[RecordData]
) -> None:
    out = TechnitiumDriver().render_zone_file(zone, records)
    payload = json.loads(out)

    assert payload["zone"] == "example.com"
    assert payload["type"] == "Primary"

    by_domain_type = {(r["domain"], r["type"]): r for r in payload["records"]}

    mx = by_domain_type[("example.com", "MX")]
    assert mx["exchange"] == "mail.example.com"
    assert mx["preference"] == 10

    srv = by_domain_type[("_sip._tcp.example.com", "SRV")]
    assert srv["target"] == "sip.example.com"
    assert srv["priority"] == 10
    assert srv["weight"] == 20
    assert srv["port"] == 5060

    txt = by_domain_type[("example.com", "TXT")]
    assert txt["text"] == "v=spf1 -all"

    a = by_domain_type[("www.example.com", "A")]
    assert a["ipAddress"] == "10.0.0.1"

    cname = by_domain_type[("alias.example.com", "CNAME")]
    assert cname["cname"] == "www.example.com"


def test_render_zone_file_is_deterministic(zone: ZoneData, records: list[RecordData]) -> None:
    out1 = TechnitiumDriver().render_zone_file(zone, records)
    out2 = TechnitiumDriver().render_zone_file(zone, records)
    assert out1 == out2


def test_render_zone_file_preserves_ttl_zero_and_mx_preference_zero(
    zone: ZoneData,
) -> None:
    # #1518: TTL 0 ("never cache") and MX preference 0 (highest
    # priority) are real values, not "unset" — the preview payload must
    # not rewrite either to a default.
    records = [
        RecordData(name="www", record_type="A", value="10.0.0.1", ttl=0),
        RecordData(name="@", record_type="MX", value="mail.example.com.", ttl=3600, priority=0),
    ]
    payload = json.loads(TechnitiumDriver().render_zone_file(zone, records))
    by_domain_type = {(r["domain"], r["type"]): r for r in payload["records"]}
    assert by_domain_type[("www.example.com", "A")]["ttl"] == 0
    assert by_domain_type[("example.com", "MX")]["preference"] == 0


def test_render_rpz_zone_returns_empty_string() -> None:
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
    assert TechnitiumDriver().render_rpz_zone(bl) == ""


# ── Validation ────────────────────────────────────────────────────────────


def test_validate_config_ok(bundle: ConfigBundle) -> None:
    ok, errors = TechnitiumDriver().validate_config(bundle)
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
    ok, errors = TechnitiumDriver().validate_config(bundle)
    assert ok is False
    assert any("does not support views" in e for e in errors)


def test_validate_config_accepts_secondary_with_masters(zone: ZoneData) -> None:
    """Superseded issue #743: a secondary used to be rejected outright.
    It is now valid as long as it carries somewhere to transfer from —
    see test_validate_rejects_secondary_without_masters for the other half.
    """
    secondary = ZoneData(
        name=zone.name,
        zone_type="secondary",
        kind=zone.kind,
        ttl=zone.ttl,
        refresh=zone.refresh,
        retry=zone.retry,
        expire=zone.expire,
        minimum=zone.minimum,
        primary_ns=zone.primary_ns,
        admin_email=zone.admin_email,
        serial=zone.serial,
        masters=("10.0.0.1",),
    )
    bundle = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="technitium1",
        driver="technitium",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=(secondary,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
    )
    ok, errors = TechnitiumDriver().validate_config(bundle)
    assert ok is True, errors


def test_validate_config_rejects_unsupported_record_types(zone: ZoneData) -> None:
    bad = ZoneData(
        name=zone.name,
        zone_type="primary",
        kind=zone.kind,
        ttl=zone.ttl,
        refresh=zone.refresh,
        retry=zone.retry,
        expire=zone.expire,
        minimum=zone.minimum,
        primary_ns=zone.primary_ns,
        admin_email=zone.admin_email,
        serial=zone.serial,
        records=(
            # ALIAS is a PowerDNS-only record type; Technitium has no
            # equivalent (it has ANAME, a different shape) — stand-in for
            # "not in our v1 supported set".
            RecordData(name="@", record_type="ALIAS", value="lb.example.net.", ttl=60),
        ),
    )
    bundle = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="technitium1",
        driver="technitium",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=(bad,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
    )
    ok, errors = TechnitiumDriver().validate_config(bundle)
    assert ok is False
    assert any("ALIAS" in e for e in errors)


def test_validate_config_accepts_modern_record_types(zone: ZoneData) -> None:
    modern = ZoneData(
        name=zone.name,
        zone_type="primary",
        kind=zone.kind,
        ttl=zone.ttl,
        refresh=zone.refresh,
        retry=zone.retry,
        expire=zone.expire,
        minimum=zone.minimum,
        primary_ns=zone.primary_ns,
        admin_email=zone.admin_email,
        serial=zone.serial,
        records=(
            RecordData(name="_443._tcp", record_type="TLSA", value="3 1 1 abcd", ttl=300),
            RecordData(name="@", record_type="HTTPS", value="1 . alpn=h2", ttl=300),
            RecordData(name="@", record_type="SVCB", value="1 target.example.com.", ttl=300),
        ),
    )
    bundle = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="technitium1",
        driver="technitium",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=(modern,),
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
    )
    ok, errors = TechnitiumDriver().validate_config(bundle)
    assert ok is True
    assert errors == []


def test_validate_config_blocklists_are_warned_not_errored(zone: ZoneData) -> None:
    bl = EffectiveBlocklistData(
        rpz_zone_name="spatium-blocklist.rpz.",
        entries=(),
        exceptions=frozenset(),
    )
    bundle = ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="technitium1",
        driver="technitium",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=(zone,),
        tsig_keys=(),
        blocklists=(bl,),
        generated_at=datetime(2026, 7, 27, 12, 0, tzinfo=UTC),
    )
    ok, errors = TechnitiumDriver().validate_config(bundle)
    assert ok is True
    assert errors == []


# ── Capabilities ──────────────────────────────────────────────────────────


def test_capabilities_scope() -> None:
    caps = TechnitiumDriver().capabilities()
    assert set(caps["zone_types"]) == {"primary", "secondary", "stub", "forward"}
    # Online signing landed in #740.
    assert caps["dnssec_inline_signing"] is True
    # ALIAS/LUA stay unsupported: Technitium's ANAME/APP are a different
    # shape, not a drop-in equivalent.
    assert caps["alias_records"] is False
    assert caps["lua_records"] is False
    assert caps["catalog_zones"] is True
    assert "SVCB" in caps["record_types"]
    assert "HTTPS" in caps["record_types"]
    assert "DNAME" in caps["record_types"]


def test_dynamic_update_caps_unsupported() -> None:
    caps = TechnitiumDriver().dynamic_update_caps
    assert caps.supports_ip_acl is False
    assert caps.supports_tsig_acl is False


# ── Zone types + capabilities (issue #743) ──────────────────────────────


def _zone(name: str, zone_type: str, **over: object) -> ZoneData:
    base = dict(
        name=name,
        zone_type=zone_type,
        kind="forward",
        ttl=3600,
        refresh=86400,
        retry=7200,
        expire=3600000,
        minimum=3600,
        primary_ns="ns1.example.com.",
        admin_email="hostmaster.example.com.",
        serial=1,
        records=(),
    )
    base.update(over)
    return ZoneData(**base)  # type: ignore[arg-type]


def _bundle_with(*zones: ZoneData) -> ConfigBundle:
    return ConfigBundle(
        server_id=str(uuid.uuid4()),
        server_name="technitium1",
        driver="technitium",
        roles=("authoritative",),
        options=ServerOptions(),
        acls=(),
        views=(),
        zones=zones,
        tsig_keys=(),
        blocklists=(),
        generated_at=datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
    )


def test_validate_accepts_every_supported_zone_type() -> None:
    d = TechnitiumDriver()
    ok, errors = d.validate_config(
        _bundle_with(
            _zone("p.example.com.", "primary"),
            _zone("s.example.com.", "secondary", masters=("192.0.2.1",)),
            _zone("st.example.com.", "stub", masters=("192.0.2.1",)),
            _zone("f.example.com.", "forward", forwarders=("8.8.8.8",)),
        )
    )
    assert ok, errors


def test_validate_rejects_secondary_without_masters() -> None:
    """Technitium resolves SOA against the primaries at create time, so a
    secondary with nowhere to transfer from can never be created. Better a
    422 on save than a zone that silently never appears."""
    d = TechnitiumDriver()
    ok, errors = d.validate_config(_bundle_with(_zone("s.example.com.", "secondary")))
    assert not ok
    assert any("primary name-server address" in e for e in errors)


def test_validate_rejects_forward_without_forwarders() -> None:
    d = TechnitiumDriver()
    ok, errors = d.validate_config(_bundle_with(_zone("f.example.com.", "forward")))
    assert not ok
    assert any("forwarder" in e for e in errors)


def test_validate_rejects_unknown_zone_type() -> None:
    d = TechnitiumDriver()
    ok, errors = d.validate_config(_bundle_with(_zone("x.example.com.", "mirror")))
    assert not ok
    assert any("not supported" in e for e in errors)


def test_capabilities_report_zone_types_and_catalog() -> None:
    caps = TechnitiumDriver().capabilities()
    assert set(caps["zone_types"]) == {"primary", "secondary", "stub", "forward"}
    assert caps["catalog_zones"] is True


def test_capabilities_report_dnssec_online_signing() -> None:
    """Issue #740 — Technitium signs online via /api/zones/dnssec/*, so it
    joins PowerDNS and BIND9 on the sign/unsign gate."""
    assert TechnitiumDriver().capabilities()["dnssec_inline_signing"] is True


def test_dnssec_operations_are_gated_to_technitium() -> None:
    from app.api.v1.dns.router import _DRIVER_GATED_OPERATIONS

    assert "technitium" in _DRIVER_GATED_OPERATIONS["dnssec_sign"]
    assert "technitium" in _DRIVER_GATED_OPERATIONS["dnssec_unsign"]
    # Manual rollover stays BIND9-only: Technitium rolls on its own
    # schedule (dnssecPrivateKeys carries rolloverDays), like PowerDNS.
    assert "technitium" not in _DRIVER_GATED_OPERATIONS["dnssec_rollover"]


def test_forward_transports_are_driver_gated() -> None:
    """BIND 9.20 forwards over DoT but has no client-side HTTP or QUIC
    transport, so https/quic are Technitium-only (issue #741)."""
    from app.api.v1.dns.router import (
        _TRANSPORT_DRIVER_GATE,
        VALID_FORWARD_TRANSPORTS,
    )

    assert VALID_FORWARD_TRANSPORTS == {"do53", "tls", "https", "quic"}
    assert _TRANSPORT_DRIVER_GATE["https"] == frozenset({"technitium"})
    assert _TRANSPORT_DRIVER_GATE["quic"] == frozenset({"technitium"})
    # do53 + tls stay ungated — every agent-managed driver can do both.
    assert "do53" not in _TRANSPORT_DRIVER_GATE
    assert "tls" not in _TRANSPORT_DRIVER_GATE


def test_doq_is_exposed_on_the_options_api() -> None:
    """Regression: doq_enabled/doq_port existed on the model and in
    validation but on neither API schema, so DoQ could not be set or read
    at all and the validation was unreachable."""
    from app.api.v1.dns.router import ServerOptionsResponse, ServerOptionsUpdate

    assert "doq_enabled" in ServerOptionsUpdate.model_fields
    assert "doq_port" in ServerOptionsUpdate.model_fields
    assert "doq_enabled" in ServerOptionsResponse.model_fields
    assert "doq_port" in ServerOptionsResponse.model_fields


def test_encrypted_transport_ports_reach_the_firewall_for_technitium() -> None:
    """Regression: all three firewall renderers gated the operator-chosen
    DoT/DoH ports on bind9/powerdns, so a Technitium listener came up
    behind a closed nftables port. DoQ additionally needs the UDP list."""
    import inspect

    from app.services.appliance import firewall, firewall_merge

    for mod in (firewall, firewall_merge):
        src = inspect.getsource(mod)
        assert "dns-technitium" in src, mod.__name__
        assert "dns_encrypted_udp_ports" in src, mod.__name__


def test_forward_zone_gate_is_driver_scoped() -> None:
    """Found by end-to-end testing: a forward zone with no forwarders was
    accepted (201) and then silently skipped by the agent, because
    Technitium's zones/create requires a forwarder while BIND9 legally
    falls back to the global list. The gate has to be driver-scoped, not
    global, or it would break valid BIND9 configs."""
    import inspect

    from app.api.v1.dns import router

    src = inspect.getsource(router._assert_forward_zone_serviceable)
    assert "technitium" in src
    # BIND9 must remain able to omit forwarders.
    assert "BIND9 groups may omit it" in src


def test_technitium_supports_drift_pull() -> None:
    """#61 drift needs a ``pull_zone_records``. Technitium's REST API is
    agent-local (loopback :5380), so the control plane goes over AXFR —
    the same path BIND9 uses."""
    assert hasattr(TechnitiumDriver(), "pull_zone_records")


def test_axfr_filters_dnssec_artefacts() -> None:
    """Signing artefacts are minted and rotated by the authoritative
    server and never modelled as SpatiumDDI records. Unfiltered, drift
    lists every signature as "extra on server" and a signed zone can
    never read as in sync — verified live before the fix. Shared helper,
    so this affects BIND9 too, not just Technitium."""
    from app.drivers.dns._axfr import _DNSSEC_ARTEFACTS

    assert {"RRSIG", "NSEC", "NSEC3", "DNSKEY"} <= _DNSSEC_ARTEFACTS
    # SOA/NS are handled separately (apex-scoped), not via this set.
    assert "SOA" not in _DNSSEC_ARTEFACTS


@pytest.mark.asyncio
async def test_role_assignment_ships_doq_udp_port(db_session, client) -> None:
    """Found on real hardware: the DoQ UDP port was DERIVED correctly and
    then never passed to SupervisorRoleAssignment, so it defaulted to []
    and the appliance firewall never opened udp/<doq_port> — the listener
    came up unreachable while the config read as correct. Ruff can't catch
    it: the variable IS used, just not where it matters."""
    import inspect

    from app.api.v1.appliance import supervisor as sup

    src = inspect.getsource(sup._build_role_assignment)
    # It must be both derived AND handed to the model.
    assert "dns_encrypted_udp_ports.append" in src
    assert "dns_encrypted_udp_ports=dns_encrypted_udp_ports" in src
