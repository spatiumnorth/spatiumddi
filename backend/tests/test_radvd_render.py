"""radvd config rendering + RA config assembly (issue #524).

Pure-function tests (no DB) covering M/O derivation from the DHCPv6 mode, the
RDNSS/DNSSL resolution, lifetime propagation, and the rendered radvd.conf shape.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPScope, DHCPServer, DHCPServerGroup
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.radvd import (
    build_ra_config,
    derive_mo_flags,
    render_radvd_conf,
    resolve_dnssl,
    resolve_rdnss,
)
from app.services.feature_modules import invalidate_cache


def test_derive_mo_flags_from_mode() -> None:
    assert derive_mo_flags("stateful", mo_override=False, managed_flag=False, other_flag=False) == (
        True,
        True,
    )
    assert derive_mo_flags("stateless", mo_override=False, managed_flag=True, other_flag=True) == (
        False,
        True,
    )
    assert derive_mo_flags("slaac", mo_override=False, managed_flag=True, other_flag=True) == (
        False,
        False,
    )


def test_derive_mo_flags_override_wins() -> None:
    # slaac would derive (0,0) but the override uses the literal flags.
    assert derive_mo_flags("slaac", mo_override=True, managed_flag=True, other_flag=False) == (
        True,
        False,
    )


def test_resolve_rdnss_prefers_scope_ipv6_only() -> None:
    rdnss = resolve_rdnss({"dns-servers": ["2001:db8::1", "192.0.2.1"]}, ["2001:db8::9"])
    assert rdnss == ["2001:db8::1"]  # v4 dropped, subnet fallback unused


def test_resolve_rdnss_subnet_fallback() -> None:
    assert resolve_rdnss({}, ["2001:db8::53", "203.0.113.1"]) == ["2001:db8::53"]


def test_resolve_dnssl_order() -> None:
    assert resolve_dnssl({"domain-search": ["a.example", "b.example"]}, "z.example") == [
        "a.example",
        "b.example",
    ]
    assert resolve_dnssl({"domain-name": "one.example"}, "z.example") == ["one.example"]
    assert resolve_dnssl({}, "sub.example") == ["sub.example"]


def _scope(**over: object) -> SimpleNamespace:
    base = dict(
        ra_enabled=True,
        address_family="ipv6",
        v6_address_mode="stateful",
        ra_mo_override=False,
        ra_managed_flag=True,
        ra_other_flag=True,
        ra_router_lifetime=1800,
        ra_max_interval=600,
        ra_prefix_on_link=True,
        ra_prefix_autonomous=True,
        ra_prefix_valid_lifetime=86400,
        ra_prefix_preferred_lifetime=14400,
        ra_interface="eth0",
        options={},
    )
    base.update(over)
    return SimpleNamespace(**base)


def _subnet(network: str, dns=None, domain=None) -> SimpleNamespace:
    return SimpleNamespace(network=network, dns_servers=dns, domain_name=domain)


def test_build_ra_config_none_when_not_enabled() -> None:
    assert build_ra_config(_scope(ra_enabled=False), _subnet("2001:db8::/64")) is None


def test_build_ra_config_none_for_ipv4() -> None:
    assert build_ra_config(_scope(address_family="ipv4"), _subnet("10.0.0.0/24")) is None


def test_build_ra_config_slaac_derives_flags_and_lifetimes() -> None:
    sc = _scope(v6_address_mode="slaac", ra_router_lifetime=900)
    ra = build_ra_config(sc, _subnet("2001:db8:1::/64", dns=["2001:db8::1"], domain="lab.example"))
    assert ra is not None
    assert (ra.managed_flag, ra.other_flag) == (False, False)
    assert ra.router_lifetime == 900
    assert ra.prefix_valid_lifetime == 86400
    assert ra.rdnss == ("2001:db8::1",)
    assert ra.dnssl == ("lab.example",)
    assert ra.subnet_cidr == "2001:db8:1::/64"


def test_render_radvd_conf_stanza() -> None:
    sc = _scope(v6_address_mode="stateless")
    ra = build_ra_config(sc, _subnet("2001:db8::/64", dns=["2001:db8::1"], domain="example.com"))
    assert ra is not None
    text = render_radvd_conf([ra])
    assert "interface eth0 {" in text
    assert "AdvManagedFlag off;" in text  # stateless → M=0
    assert "AdvOtherConfigFlag on;" in text  # stateless → O=1
    assert "prefix 2001:db8::/64 {" in text
    assert "AdvValidLifetime 86400;" in text
    assert "RDNSS 2001:db8::1 {};" in text
    assert "DNSSL example.com {};" in text


def test_render_uses_real_radvd_keywords() -> None:
    """GHSA-6235-5gh6-4hr2: ``AdvMaxInterval`` is not a radvd keyword."""
    ra = build_ra_config(_scope(ra_max_interval=300), _subnet("2001:db8::/64"))
    assert ra is not None
    text = render_radvd_conf([ra])
    assert "MaxRtrAdvInterval 300;" in text
    assert "AdvMaxInterval" not in text


_INJECTIONS = [
    "x.example {}; }; interface eth9 { AdvSendAdvert on; prefix 2001:db8:bad::/64 {};",
    "a.example\nb.example",
    "a b.example",
    'a".example',
    "a;b.example",
    "a{b.example",
]


def test_dnssl_injection_is_dropped_from_subnet_domain() -> None:
    for payload in _INJECTIONS:
        sc = _scope()
        ra = build_ra_config(sc, _subnet("2001:db8::/64", domain=payload))
        assert ra is not None
        assert ra.dnssl == ()
        text = render_radvd_conf([ra])
        assert "DNSSL" not in text
        assert text.count("interface ") == 1


def test_dnssl_injection_is_dropped_from_scope_options() -> None:
    sc = _scope(options={"domain-search": ["ok.example", _INJECTIONS[0]]})
    ra = build_ra_config(sc, _subnet("2001:db8::/64"))
    assert ra is not None
    assert ra.dnssl == ("ok.example",)


def test_render_revalidates_even_a_hand_built_config() -> None:
    from app.drivers.dhcp.base import RAConfigDef

    bad = RAConfigDef(
        subnet_cidr="2001:db8::/64",
        interface="eth0",
        managed_flag=True,
        other_flag=True,
        router_lifetime=1800,
        max_interval=600,
        prefix_on_link=True,
        prefix_autonomous=True,
        prefix_valid_lifetime=86400,
        prefix_preferred_lifetime=14400,
        rdnss=("2001:db8::1", "::1 {}; }; interface eth9 {"),
        dnssl=("ok.example", _INJECTIONS[0]),
    )
    text = render_radvd_conf([bad])
    assert "eth9" not in text
    assert "RDNSS 2001:db8::1 {};" in text
    assert "DNSSL ok.example {};" in text


def test_bad_interface_name_never_reaches_the_file() -> None:
    for iface in (
        "eth0 { AdvSendAdvert on; }; interface eth9",
        "a\nb",
        "eth0;",
        "x" * 16,
        "..",
        '"',
    ):
        ra = build_ra_config(_scope(ra_interface=iface), _subnet("2001:db8::/64"))
        assert ra is not None
        text = render_radvd_conf([ra])
        assert "eth9" not in text
        assert "interface " not in text or text.count("interface ") == 1
        assert iface not in text


def test_api_rejects_injection_in_interface_and_subnet_domain() -> None:
    import pytest
    from pydantic import ValidationError

    from app.api.v1.dhcp.scopes import ScopeCreate, ScopeUpdate
    from app.api.v1.ipam.router import SubnetCreate, SubnetUpdate

    for bad in ("eth0 {", "a;b", "a\nb", "x" * 16, "e th"):
        with pytest.raises(ValidationError):
            ScopeCreate(ra_interface=bad)
        with pytest.raises(ValidationError):
            ScopeUpdate(ra_interface=bad)
    assert ScopeCreate(ra_interface="eth0.100").ra_interface == "eth0.100"
    assert ScopeCreate(ra_interface="").ra_interface == ""
    assert ScopeUpdate().ra_interface is None

    for bad in _INJECTIONS:
        with pytest.raises(ValidationError):
            SubnetUpdate(domain_name=bad)
        with pytest.raises(ValidationError):
            SubnetCreate(
                space_id=uuid.uuid4(),
                block_id=uuid.uuid4(),
                network="2001:db8::/64",
                domain_name=bad,
            )
    assert SubnetUpdate(domain_name="lab.example").domain_name == "lab.example"
    # Not config syntax, and accepted before this fix: must stay accepted.
    assert SubnetUpdate(domain_name="ad_site.example").domain_name == "ad_site.example"
    assert SubnetUpdate(domain_name=None).domain_name is None


def test_render_radvd_conf_empty() -> None:
    assert render_radvd_conf([]) == ""


def test_render_radvd_groups_by_interface() -> None:
    a = build_ra_config(_scope(ra_interface="eth0"), _subnet("2001:db8:a::/64"))
    b = build_ra_config(_scope(ra_interface="eth1"), _subnet("2001:db8:b::/64"))
    assert a is not None and b is not None
    txt = render_radvd_conf([a, b])
    assert txt.count("interface ") == 2
    assert "interface eth0 {" in txt
    assert "interface eth1 {" in txt


# ── Feature-module gating (non-negotiable #14 dormancy, finding #3) ────────


async def _ra_group_scope(db: AsyncSession) -> DHCPServer:
    """A group + Kea server + one RA-enabled IPv6 scope on 2001:db8:524::/64."""
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=547,
        server_group_id=grp.id,
    )
    db.add(srv)
    await db.flush()

    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(name="blk6", space_id=space.id, network="2001:db8:524::/48")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        name="v6",
        space_id=space.id,
        block_id=block.id,
        network="2001:db8:524::/64",
    )
    db.add(subnet)
    await db.flush()

    scope = DHCPScope(
        name="ra-scope",
        group_id=grp.id,
        subnet_id=subnet.id,
        is_active=True,
        address_family="ipv6",
        v6_address_mode="slaac",
        ra_enabled=True,
        ra_interface="eth0",
    )
    db.add(scope)
    await db.flush()
    return srv


async def _set_module(db: AsyncSession, enabled: bool) -> None:
    await db.execute(
        text(
            "INSERT INTO feature_module (id, enabled) VALUES (:id, :en) "
            "ON CONFLICT (id) DO UPDATE SET enabled = :en"
        ).bindparams(id="ipv6.router_advertisements", en=enabled)
    )
    await db.commit()
    invalidate_cache()


async def test_module_enabled_ships_radvd_conf(db_session: AsyncSession) -> None:
    srv = await _ra_group_scope(db_session)
    await _set_module(db_session, True)
    try:
        bundle = await build_config_bundle(db_session, srv)
        assert bundle.radvd_conf  # non-empty
        assert "interface eth0 {" in bundle.radvd_conf
        assert len(bundle.ra_configs) == 1
    finally:
        await _set_module(db_session, True)


async def test_module_disabled_empties_radvd_conf(db_session: AsyncSession) -> None:
    srv = await _ra_group_scope(db_session)
    # Baseline: module on → non-empty, so we can prove the ETag shifts.
    await _set_module(db_session, True)
    on = await build_config_bundle(db_session, srv)
    assert on.radvd_conf

    await _set_module(db_session, False)
    try:
        off = await build_config_bundle(db_session, srv)
        # Feature dormant even with an ra_enabled scope present.
        assert off.radvd_conf == ""
        assert off.ra_configs == ()
        # ETag shifts on/off so the agent actually stops radvd.
        assert off.etag != on.etag
    finally:
        await _set_module(db_session, True)
