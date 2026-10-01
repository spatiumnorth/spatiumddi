"""Tests for DHCP phone profiles (issue #112 phase 1).

Covers the load-bearing pieces: catalog loading, config-bundle
assembly with vendor-class fence + option-set, Kea render shape (the
``code:NN`` form for vendor options Kea doesn't know by name), and
the M:N scope-attachment plumbing.
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dhcp.base import PhoneClassDef
from app.drivers.dhcp.kea import KeaDriver
from app.models.dhcp import (
    DHCPPhoneProfile,
    DHCPPhoneProfileScope,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp.config_bundle import build_config_bundle
from app.services.dhcp.voip_options import get_vendor, load_catalog

# ── Catalog ───────────────────────────────────────────────────────────────


def test_voip_catalog_loads_and_includes_polycom() -> None:
    cat = load_catalog()
    assert any(v.vendor == "Polycom" for v in cat)
    polycom = get_vendor("Polycom")
    assert polycom is not None
    assert polycom.match_hint == "Polycom"
    # Polycom's roster must carry option 66 and 160.
    codes = {o.code for o in polycom.options}
    assert {66, 160}.issubset(codes)


def test_voip_catalog_includes_avaya_modern_option_242() -> None:
    avaya = get_vendor("Avaya")
    assert avaya is not None
    codes = {o.code for o in avaya.options}
    assert 242 in codes


# ── Helpers ───────────────────────────────────────────────────────────────


async def _make_group_server_scope(
    db: AsyncSession,
) -> tuple[DHCPServerGroup, DHCPServer, DHCPScope]:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add(grp)
    await db.flush()
    srv = DHCPServer(
        name=f"s-{uuid.uuid4().hex[:6]}",
        driver="kea",
        host="127.0.0.1",
        port=67,
        server_group_id=grp.id,
    )
    db.add(srv)
    await db.flush()

    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(name="blk", space_id=space.id, network="10.0.20.0/24")
    db.add(block)
    await db.flush()
    subnet = Subnet(
        name="voice",
        space_id=space.id,
        block_id=block.id,
        network="10.0.20.0/24",
    )
    db.add(subnet)
    await db.flush()

    scope = DHCPScope(
        name="voice-vlan-20",
        group_id=grp.id,
        subnet_id=subnet.id,
        is_active=True,
        lease_time=3600,
    )
    db.add(scope)
    await db.flush()
    return grp, srv, scope


# ── Config-bundle assembly ────────────────────────────────────────────────


async def test_phone_profile_renders_when_attached_and_enabled(
    db_session: AsyncSession,
) -> None:
    db = db_session
    grp, srv, scope = await _make_group_server_scope(db)
    prof = DHCPPhoneProfile(
        group_id=grp.id,
        name="Polycom",
        description="",
        enabled=True,
        vendor="Polycom",
        vendor_class_match="Polycom",
        option_set=[
            {"code": 66, "name": "tftp-server-name", "value": "tftp.example.com"},
            {"code": 160, "name": "polycom-config-url", "value": "https://prov.example.com/{mac}"},
        ],
    )
    db.add(prof)
    await db.flush()
    db.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=scope.id))
    await db.flush()

    bundle = await build_config_bundle(db, srv)
    assert len(bundle.phone_classes) == 1
    pc = bundle.phone_classes[0]
    assert pc.name.startswith("voip-")
    # Fence on option-60 substring uses Kea's hex-substring expression.
    assert "option[60].hex" in pc.match_expression
    assert "Polycom" in pc.match_expression
    # The two options the operator set should land in the rendered class.
    assert pc.options.get("tftp-server-name") == "tftp.example.com"
    # #1294 — keyed by code: the agent drops a catalogue name such as
    # ``polycom-config-url``, so option 160 never reached a phone.
    assert pc.options.get("code:160") == "https://prov.example.com/{mac}"
    assert "polycom-config-url" not in pc.options


async def test_disabled_phone_profile_emits_no_class(
    db_session: AsyncSession,
) -> None:
    db = db_session
    grp, srv, scope = await _make_group_server_scope(db)
    prof = DHCPPhoneProfile(
        group_id=grp.id,
        name="Polycom",
        description="",
        enabled=False,  # ← disabled
        vendor="Polycom",
        vendor_class_match="Polycom",
        option_set=[{"code": 66, "name": "tftp-server-name", "value": "x"}],
    )
    db.add(prof)
    await db.flush()
    db.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=scope.id))
    await db.flush()

    bundle = await build_config_bundle(db, srv)
    assert bundle.phone_classes == ()


async def test_phone_profile_unattached_to_scope_emits_no_class(
    db_session: AsyncSession,
) -> None:
    db = db_session
    grp, srv, _scope = await _make_group_server_scope(db)
    prof = DHCPPhoneProfile(
        group_id=grp.id,
        name="Polycom",
        description="",
        enabled=True,
        vendor="Polycom",
        vendor_class_match="Polycom",
        option_set=[{"code": 66, "name": "tftp-server-name", "value": "x"}],
    )
    db.add(prof)
    await db.flush()
    # Deliberately NO DHCPPhoneProfileScope row — profile is orphaned.

    bundle = await build_config_bundle(db, srv)
    assert bundle.phone_classes == ()


# ── Kea render ────────────────────────────────────────────────────────────


def test_kea_render_emits_option_with_code_form_for_vendor_options() -> None:
    """Vendor options Kea doesn't know by name must render with
    ``"code": NN`` rather than ``"name": "<unknown>"``, otherwise Kea
    rejects the config on reload.
    """
    pc = PhoneClassDef(
        name="voip-12345678",
        match_expression="substring(option[60].hex,0,8)=='Polycom'",
        # ``code:160`` is the way the assembler surfaces vendor options
        # the operator left without a recognised name.
        options={"code:160": "https://prov.example.com/{mac}"},
    )
    bundle_json = KeaDriver().render_config(_minimal_bundle_with_phone(pc))
    bundle = json.loads(bundle_json)
    cc = bundle["Dhcp4"]["client-classes"]
    voip = next(c for c in cc if c["name"] == "voip-12345678")
    assert any(
        opt.get("code") == 160 and opt["data"] == "https://prov.example.com/{mac}"
        for opt in voip["option-data"]
    )


def test_kea_render_emits_phone_class_alongside_pxe_and_regular_classes() -> None:
    """Phone classes share Dhcp4 client-classes with regular + PXE."""
    pc = PhoneClassDef(
        name="voip-deadbeef",
        match_expression="substring(option[60].hex,0,7)=='yealink'",
        options={"tftp-server-name": "tftp.example.com"},
    )
    bundle_json = KeaDriver().render_config(_minimal_bundle_with_phone(pc))
    bundle = json.loads(bundle_json)
    names = {c["name"] for c in bundle["Dhcp4"]["client-classes"]}
    assert "voip-deadbeef" in names


def _minimal_bundle_with_phone(pc: PhoneClassDef):
    """Tiny ConfigBundle for render-shape tests — no scopes, just the
    one phone class. Scope-less render still emits Dhcp4 because the
    driver's branch is "v4 if any v4 scopes OR no v6 scopes".
    """
    from datetime import UTC, datetime

    from app.drivers.dhcp.base import ConfigBundle, ServerOptionsDef

    return ConfigBundle(
        server_id="00000000-0000-0000-0000-000000000000",
        server_name="kea-test",
        driver="kea",
        roles=(),
        options=ServerOptionsDef(options={}, lease_time=3600),
        scopes=(),
        client_classes=(),
        phone_classes=(pc,),
        generated_at=datetime.now(UTC),
    )
