"""A PXE profile boots the scopes it is bound to, and no other (#2731).

Each arch-match of a bound PXE profile becomes a Kea client class, and both
the agent and the config preview rendered those classes for the whole
server. Kea evaluates such a class for every packet it serves, so the PXE
clients of a scope with no profile, or with another profile, were offered
the bound profile's next-server and boot file.

Each v4 scope now lists its own profile's classes (``pxe_class_names``), and
the renderers have Kea evaluate a class only for the subnets that list it:
``only-in-additional-list`` on the class, ``evaluate-additional-classes`` on
the subnet. Measured on kea-dhcp4 3.0.3, not assumed: such a class's
``next-server`` and ``boot-file-name`` still reach the OFFER, a subnet that
lists nothing offers neither, and a class with no ``test`` is added for every
client of a subnet that lists it.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dhcp.base import ConfigBundle, PXEClassDef, ScopeDef, ServerOptionsDef
from app.drivers.dhcp.kea import KeaDriver
from app.models.dhcp import DHCPPXEArchMatch, DHCPPXEProfile, DHCPScope, DHCPServerGroup
from app.models.ipam import IPBlock, Subnet
from app.services.dhcp import agent_token as dhcp_tokens
from app.services.dhcp.config_bundle import build_config_bundle
from tests.test_dhcp_phone_profiles import _make_group_server_scope

BOOTED = "10.0.20.0/24"  # the scope _make_group_server_scope makes
PLAIN = "10.0.21.0/24"
OTHER = "10.0.22.0/24"


async def _scope(
    db: AsyncSession,
    grp: DHCPServerGroup,
    space_id: uuid.UUID,
    cidr: str,
    *,
    address_family: str = "ipv4",
) -> DHCPScope:
    """One more scope in ``grp``, on a subnet (and block) of its own."""
    block = IPBlock(name=f"b-{cidr}", space_id=space_id, network=cidr)
    db.add(block)
    await db.flush()
    subnet = Subnet(name=f"s-{cidr}", space_id=space_id, block_id=block.id, network=cidr)
    db.add(subnet)
    await db.flush()
    scope = DHCPScope(
        name=f"sc-{cidr}",
        group_id=grp.id,
        subnet_id=subnet.id,
        is_active=True,
        lease_time=3600,
        address_family=address_family,
    )
    db.add(scope)
    await db.flush()
    return scope


async def _profile(
    db: AsyncSession,
    grp: DHCPServerGroup,
    name: str,
    next_server: str,
    *matches: tuple[int, int, str],
) -> DHCPPXEProfile:
    """A profile with one arch-match per ``(priority, arch, boot file)``."""
    prof = DHCPPXEProfile(group_id=grp.id, name=name, next_server=next_server, enabled=True)
    db.add(prof)
    await db.flush()
    db.add_all(
        DHCPPXEArchMatch(profile_id=prof.id, priority=prio, arch_codes=[arch], boot_filename=boot)
        for prio, arch, boot in matches
    )
    await db.flush()
    return prof


async def _space_id(db: AsyncSession, scope: DHCPScope) -> uuid.UUID:
    subnet = await db.get(Subnet, scope.subnet_id)
    assert subnet is not None
    return subnet.space_id


async def test_each_scope_lists_its_own_profiles_classes_and_no_others(
    db_session: AsyncSession,
) -> None:
    grp, srv, booted = await _make_group_server_scope(db_session)
    space_id = await _space_id(db_session, booted)
    await _scope(db_session, grp, space_id, PLAIN)
    other = await _scope(db_session, grp, space_id, OTHER)
    uefi = await _profile(
        db_session, grp, "uefi", "10.0.0.5", (20, 0, "undionly.kpxe"), (10, 7, "ipxe.efi")
    )
    lab = await _profile(db_session, grp, "lab", "10.0.0.6", (10, 7, "lab.efi"))
    booted.pxe_profile_id = uefi.id
    other.pxe_profile_id = lab.id
    await db_session.flush()

    bundle = await build_config_bundle(db_session, srv)

    boot_file = {c.name: c.boot_file_name for c in bundle.pxe_classes}
    lists = {s.subnet_cidr: s.pxe_class_names for s in bundle.scopes}
    # The profile's own classes, in its priority order.
    assert [boot_file[n] for n in lists[BOOTED]] == ["ipxe.efi", "undionly.kpxe"]
    assert [boot_file[n] for n in lists[OTHER]] == ["lab.efi"]
    # A scope with no profile lists nothing, so no PXE class answers its clients.
    assert lists[PLAIN] == ()
    # Every class belongs to exactly one of the two profiles' scopes.
    assert sorted(lists[BOOTED] + lists[OTHER]) == sorted(boot_file)


async def test_a_v6_scope_lists_no_pxe_classes(db_session: AsyncSession) -> None:
    """PXE classes are Dhcp4-only; a v6 scope bound to the profile lists none."""
    grp, srv, booted = await _make_group_server_scope(db_session)
    v6 = await _scope(
        db_session,
        grp,
        await _space_id(db_session, booted),
        "2001:db8:2731::/64",
        address_family="ipv6",
    )
    uefi = await _profile(db_session, grp, "uefi", "10.0.0.5", (10, 7, "ipxe.efi"))
    booted.pxe_profile_id = uefi.id
    v6.pxe_profile_id = uefi.id
    await db_session.flush()

    bundle = await build_config_bundle(db_session, srv)

    lists = {s.subnet_cidr: s.pxe_class_names for s in bundle.scopes}
    (pxe,) = bundle.pxe_classes
    assert lists[BOOTED] == (pxe.name,)
    assert lists["2001:db8:2731::/64"] == ()


async def test_the_agent_payload_carries_each_scopes_classes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Shipped to the agent, not only hashed into the ETag (#430, #858)."""
    grp, srv, booted = await _make_group_server_scope(db_session)
    await _scope(db_session, grp, await _space_id(db_session, booted), PLAIN)
    uefi = await _profile(db_session, grp, "uefi", "10.0.0.5", (10, 7, "ipxe.efi"))
    booted.pxe_profile_id = uefi.id
    srv.agent_id = uuid.uuid4()
    srv.agent_registered = True
    srv.agent_approved = True
    srv.agent_fingerprint = "fp"
    token, _exp = dhcp_tokens.mint_agent_token(
        server_id=str(srv.id), agent_id=str(srv.agent_id), fingerprint="fp"
    )
    srv.agent_token_hash = dhcp_tokens.hash_token(token)
    await db_session.commit()

    resp = await client.get(
        "/api/v1/dhcp/agents/config", headers={"Authorization": f"Bearer {token}"}
    )

    assert resp.status_code == 200, resp.text
    wire = resp.json()["bundle"]
    (pxe,) = wire["pxe_classes"]
    lists = {s["subnet_cidr"]: s["pxe_class_names"] for s in wire["scopes"]}
    assert lists == {BOOTED: [pxe["name"]], PLAIN: []}


def _bundle(*scopes: ScopeDef, pxe: tuple[PXEClassDef, ...]) -> ConfigBundle:
    return ConfigBundle(
        server_id="00000000-0000-0000-0000-000000000000",
        server_name="kea-pxe-test",
        driver="kea",
        roles=(),
        options=ServerOptionsDef(options={}, lease_time=3600),
        scopes=scopes,
        client_classes=(),
        generated_at=datetime.now(UTC),
        pxe_classes=pxe,
    )


def test_the_preview_evaluates_a_class_only_for_the_scopes_that_list_it() -> None:
    pxe = PXEClassDef(
        name="pxe-a",
        match_expression="option[93].hex == 0x0007",
        next_server="10.0.0.5",
        boot_file_name="ipxe.efi",
    )
    doc = json.loads(
        KeaDriver().render_config(
            _bundle(
                ScopeDef(subnet_cidr=BOOTED, pxe_class_names=("pxe-a",)),
                ScopeDef(subnet_cidr=PLAIN),
                pxe=(pxe,),
            )
        )
    )["Dhcp4"]

    (cls,) = doc["client-classes"]
    assert cls == {
        "name": "pxe-a",
        "next-server": "10.0.0.5",
        "boot-file-name": "ipxe.efi",
        "test": "option[93].hex == 0x0007",
        "only-in-additional-list": True,
    }
    subnets = {s["subnet"]: s for s in doc["subnet4"]}
    assert subnets[BOOTED]["evaluate-additional-classes"] == ["pxe-a"]
    assert "evaluate-additional-classes" not in subnets[PLAIN]
