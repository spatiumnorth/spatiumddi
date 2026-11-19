"""Tests for the OPNsense reconciler.

Stub ``OPNsenseClient`` so we don't need a real firewall. Validates
interface → subnet creation (real LAN semantics: gateway set, broadcast
counted out), DHCP lease + static reservation + ARP status mapping,
operator-row claim + user_modified_at lock, sibling-integration
ownership guard, disappeared-row delete, and cascade on firewall
removal.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.opnsense import OPNsenseRouter
from app.services.opnsense.client import (
    _OPNArpEntry,
    _OPNFirmwareInfo,
    _OPNInterface,
    _OPNLease,
    _OPNLeaseResult,
    _OPNReservation,
    _OPNReservationResult,
    _OPNVlan,
)
from app.services.opnsense.reconcile import reconcile_router

# ── Fixtures ─────────────────────────────────────────────────────────


async def _make_space(db: AsyncSession) -> IPSpace:
    space = IPSpace(name=f"opnsense-test-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


async def _make_router(
    db: AsyncSession,
    space: IPSpace,
    *,
    mirror_dhcp_leases: bool = True,
    mirror_static_mappings: bool = True,
    mirror_arp: bool = False,
) -> OPNsenseRouter:
    router = OPNsenseRouter(
        name=f"fw-{uuid.uuid4().hex[:6]}",
        host="fw.example.test",
        port=443,
        verify_tls=False,
        api_key="KEY",
        # Encrypt a real secret so the reconciler's decrypt guard passes.
        api_secret_encrypted=_encrypt("SECRET"),
        ipam_space_id=space.id,
        mirror_dhcp_leases=mirror_dhcp_leases,
        mirror_static_mappings=mirror_static_mappings,
        mirror_arp=mirror_arp,
    )
    db.add(router)
    await db.flush()
    return router


def _encrypt(value: str) -> bytes:
    from app.core.crypto import encrypt_str  # noqa: PLC0415

    return encrypt_str(value)


class _FakeClient:
    def __init__(
        self,
        *,
        firmware: _OPNFirmwareInfo | None = None,
        interfaces: list[_OPNInterface] | None = None,
        vlans: list[_OPNVlan] | None = None,
        leases: list[_OPNLease] | None = None,
        reservations: list[_OPNReservation] | None = None,
        arp: list[_OPNArpEntry] | None = None,
        lease_sources: list[str] | None = None,
        reservation_sources: list[str] | None = None,
        forbidden: list[str] | None = None,
    ) -> None:
        self.firmware = firmware or _OPNFirmwareInfo(version="OPNsense 26.1")
        self.interfaces = interfaces or []
        self.vlans = vlans or []
        self.leases = leases or []
        self.reservations = reservations or []
        self.arp = arp or []
        # #797 — the real client reports WHICH DHCP backends answered, so
        # the reconciler can tell "DHCP is off" from "we asked a firmware
        # that no longer has these endpoints". Default to a backend having
        # answered, so existing tests exercise the normal path; the
        # no-backend case is asserted explicitly in its own test.
        self.lease_sources = ["kea"] if lease_sources is None else lease_sources
        self.reservation_sources = ["kea"] if reservation_sources is None else reservation_sources
        self.forbidden = forbidden or []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get_firmware(self):
        return self.firmware

    async def list_interfaces(self):
        return self.interfaces

    async def list_vlans(self):
        return self.vlans

    async def list_leases(self):
        return _OPNLeaseResult(
            leases=self.leases,
            sources_found=self.lease_sources,
            sources_forbidden=self.forbidden,
        )

    async def list_reservations(self):
        return _OPNReservationResult(
            reservations=self.reservations,
            sources_found=self.reservation_sources,
            sources_forbidden=self.forbidden,
        )

    async def list_arp(self):
        return self.arp


def _patch_client(fake: _FakeClient):
    def _ctor(**_kwargs):
        return fake

    return patch("app.services.opnsense.reconcile.OPNsenseClient", side_effect=_ctor)


def _iface(name: str, device: str, address: str, cidr: str, descr: str = "") -> _OPNInterface:
    return _OPNInterface(name=name, device=device, description=descr, cidr=cidr, address=address)


# ── Tests ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_interface_creates_subnet_with_gateway_and_lan_semantics(
    db_session: AsyncSession,
) -> None:
    """An OPNsense LAN interface is a real subnet: the firewall's
    interface IP is the gateway, and the /24 has 254 usable hosts
    (broadcast + network counted out)."""
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        interfaces=[_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24", "LAN")],
    )
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)

    assert summary.ok, summary.error
    assert summary.subnets_created == 1

    sub = (
        await db_session.execute(select(Subnet).where(Subnet.opnsense_router_id == router.id))
    ).scalar_one()
    assert str(sub.network) == "10.0.0.0/24"
    assert str(sub.gateway) == "10.0.0.1"
    assert sub.total_ips == 254  # real LAN — broadcast + network out

    # The firewall interface IP lands as a reserved row.
    gw = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.opnsense_router_id == router.id,
                IPAddress.status == "reserved",
                IPAddress.address == "10.0.0.1",
            )
        )
    ).scalar_one()
    assert gw.hostname == router.name


@pytest.mark.asyncio
async def test_lease_and_reservation_status_mapping(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        interfaces=[_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")],
        leases=[
            _OPNLease(
                address="10.0.0.50", mac="bc:24:11:e8:4a:3f", hostname="laptop", state="active"
            )
        ],
        reservations=[
            _OPNReservation(
                address="10.0.0.10", mac="aa:bb:cc:dd:ee:ff", hostname="printer", description="prn"
            )
        ],
    )
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)
    assert summary.ok, summary.error

    lease_row = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.0.0.50"))
    ).scalar_one()
    assert lease_row.status == "dhcp"
    assert lease_row.auto_from_lease is True
    assert lease_row.hostname == "laptop"

    res_row = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.0.0.10"))
    ).scalar_one()
    assert res_row.status == "reserved"
    assert res_row.auto_from_lease is False
    assert res_row.hostname == "printer"


@pytest.mark.asyncio
async def test_arp_only_when_opted_in(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    router = await _make_router(db_session, space, mirror_arp=True)
    await db_session.commit()

    fake = _FakeClient(
        interfaces=[_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")],
        arp=[
            _OPNArpEntry(
                address="10.0.0.77", mac="de:ad:be:ef:00:11", hostname="", interface="igb1"
            )
        ],
    )
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)
    assert summary.ok, summary.error

    arp_row = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.0.0.77"))
    ).scalar_one()
    assert arp_row.status == "opnsense-arp"


@pytest.mark.asyncio
async def test_claims_operator_row_and_locks_soft_fields(db_session: AsyncSession) -> None:
    """A pre-existing operator IP at a desired address is claimed
    (FK stamped + user_modified_at set) and its operator-set hostname is
    NOT overwritten on subsequent reconciles."""
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    # Operator-created block + subnet + IP at 10.0.0.50.
    block = IPBlock(space_id=space.id, network="10.0.0.0/24", name="op-block")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.0.0.0/24", name="op-subnet", total_ips=254
    )
    db_session.add(subnet)
    await db_session.flush()
    op_ip = IPAddress(
        subnet_id=subnet.id,
        address="10.0.0.50",
        status="allocated",
        hostname="operator-named",
    )
    db_session.add(op_ip)
    await db_session.commit()

    fake = _FakeClient(
        interfaces=[_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")],
        leases=[
            _OPNLease(
                address="10.0.0.50", mac="bc:24:11:e8:4a:3f", hostname="dhcp-name", state="active"
            )
        ],
    )
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)
    assert summary.ok, summary.error

    # The operator subnet at the same CIDR was matched, not duplicated.
    assert summary.subnets_matched == 1
    all_subnets = (
        (await db_session.execute(select(Subnet).where(Subnet.network == "10.0.0.0/24")))
        .scalars()
        .all()
    )
    assert len(all_subnets) == 1

    await db_session.refresh(op_ip)
    assert op_ip.opnsense_router_id == router.id  # claimed
    assert op_ip.user_modified_at is not None  # locked
    assert op_ip.hostname == "operator-named"  # NOT clobbered


@pytest.mark.asyncio
async def test_sibling_integration_row_not_claimed(db_session: AsyncSession) -> None:
    """A row already owned by another integration (here Proxmox) must
    not be claimed by the OPNsense reconciler."""
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    block = IPBlock(space_id=space.id, network="10.0.0.0/24", name="op-block")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(
        space_id=space.id, block_id=block.id, network="10.0.0.0/24", name="op-subnet", total_ips=254
    )
    db_session.add(subnet)
    await db_session.flush()
    foreign_node = uuid.uuid4()
    # Fabricate a row that looks proxmox-owned. We can't easily create a
    # real ProxmoxNode FK target without importing it, so stamp the FK
    # directly via a real ProxmoxNode.
    from app.models.proxmox import ProxmoxNode  # noqa: PLC0415

    pnode = ProxmoxNode(
        name=f"pve-{uuid.uuid4().hex[:6]}",
        host="pve.test",
        token_id="root@pam!x",
        ipam_space_id=space.id,
    )
    pnode.id = foreign_node
    db_session.add(pnode)
    await db_session.flush()
    foreign_ip = IPAddress(
        subnet_id=subnet.id,
        address="10.0.0.50",
        status="proxmox-vm",
        hostname="pve-guest",
        proxmox_node_id=pnode.id,
    )
    db_session.add(foreign_ip)
    await db_session.commit()

    fake = _FakeClient(
        interfaces=[_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")],
        leases=[_OPNLease(address="10.0.0.50", mac=None, hostname="dhcp-name", state="active")],
    )
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)
    assert summary.ok, summary.error

    await db_session.refresh(foreign_ip)
    assert foreign_ip.opnsense_router_id is None  # untouched
    assert foreign_ip.proxmox_node_id == pnode.id
    assert any("another integration" in w for w in summary.warnings)


@pytest.mark.asyncio
async def test_disappeared_lease_is_deleted(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    await db_session.commit()

    iface = [_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")]

    # First pass: lease at .50 created.
    with _patch_client(
        _FakeClient(
            interfaces=iface,
            leases=[_OPNLease(address="10.0.0.50", mac=None, hostname="x", state="active")],
        )
    ):
        await reconcile_router(db_session, router)
    assert (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.0.0.50"))
    ).scalar_one_or_none() is not None

    # Second pass: lease gone → row deleted (no operator edits).
    with _patch_client(_FakeClient(interfaces=iface, leases=[])):
        summary = await reconcile_router(db_session, router)
    assert summary.addresses_deleted >= 1
    assert (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.0.0.50"))
    ).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_forbidden_backend_freezes_mirrored_dhcp_rows(db_session: AsyncSession) -> None:
    """#1556 — a 403 from a DHCP backend must freeze that category's
    mirrored rows, not delete them: the backend contributed nothing to
    the desired set, so absence proves nothing this pass."""
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    await db_session.commit()

    iface = [_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")]

    # First pass: lease at .50 and reservation at .60 created.
    with _patch_client(
        _FakeClient(
            interfaces=iface,
            leases=[_OPNLease(address="10.0.0.50", mac=None, hostname="x", state="active")],
            reservations=[
                _OPNReservation(
                    address="10.0.0.60", mac="aa:bb:cc:dd:ee:ff", hostname="r", description=""
                )
            ],
        )
    ):
        await reconcile_router(db_session, router)

    # Second pass: every DHCP backend refuses (403) and returns nothing.
    # Both rows must survive, still owned by this router, with no deletes.
    with _patch_client(
        _FakeClient(
            interfaces=iface,
            leases=[],
            reservations=[],
            lease_sources=[],
            reservation_sources=[],
            forbidden=["kea leases", "kea reservations"],
        )
    ):
        summary = await reconcile_router(db_session, router)
    assert summary.addresses_deleted == 0
    for addr in ("10.0.0.50", "10.0.0.60"):
        row = (
            await db_session.execute(select(IPAddress).where(IPAddress.address == addr))
        ).scalar_one_or_none()
        assert row is not None, addr
        assert row.opnsense_router_id == router.id

    # Third pass: access restored, rows genuinely gone upstream → the
    # normal absence-delete resumes (the freeze was refusal-scoped).
    with _patch_client(_FakeClient(interfaces=iface, leases=[], reservations=[])):
        summary = await reconcile_router(db_session, router)
    assert summary.addresses_deleted >= 2
    for addr in ("10.0.0.50", "10.0.0.60"):
        assert (
            await db_session.execute(select(IPAddress).where(IPAddress.address == addr))
        ).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_delete_router_cascades_ipam_rows(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    await db_session.commit()

    with _patch_client(
        _FakeClient(
            interfaces=[_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")],
            leases=[_OPNLease(address="10.0.0.50", mac=None, hostname="x", state="active")],
        )
    ):
        await reconcile_router(db_session, router)

    rid = router.id
    await db_session.delete(router)
    await db_session.commit()

    # FK ON DELETE CASCADE sweeps the mirrored subnet + address rows.
    assert (
        await db_session.execute(select(Subnet).where(Subnet.opnsense_router_id == rid))
    ).scalar_one_or_none() is None
    assert (
        await db_session.execute(select(IPAddress).where(IPAddress.opnsense_router_id == rid))
    ).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_vlan_label_in_subnet_description(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    await db_session.commit()

    fake = _FakeClient(
        interfaces=[_iface("opt1", "vlan0.20", "192.168.20.1", "192.168.20.0/24", "IoT")],
        vlans=[_OPNVlan(device="vlan0.20", parent="igb1", tag=20, description="IoT net")],
    )
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)
    assert summary.ok, summary.error

    sub = (
        await db_session.execute(select(Subnet).where(Subnet.network == "192.168.20.0/24"))
    ).scalar_one()
    assert "VLAN 20" in (sub.description or "")


@pytest.mark.asyncio
async def test_disappeared_subnet_with_operator_ip_is_unclaimed_not_deleted(
    db_session: AsyncSession,
) -> None:
    """When an interface disappears upstream but its router-owned subnet
    still holds an operator IP (opnsense_router_id IS NULL), the subnet
    must be un-claimed (handed back to manual management), NOT deleted —
    because IPAddress → Subnet is ON DELETE CASCADE with no soft-delete,
    so a blind delete would sweep the operator row too."""
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    await db_session.commit()

    # First pass: the firewall has a LAN interface → router-owned subnet.
    iface = [_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")]
    with _patch_client(_FakeClient(interfaces=iface)):
        await reconcile_router(db_session, router)

    sub = (
        await db_session.execute(select(Subnet).where(Subnet.opnsense_router_id == router.id))
    ).scalar_one()
    sub_id = sub.id

    # Operator drops an unclaimed (operator-owned) IP into that subnet.
    op_ip = IPAddress(
        subnet_id=sub_id,
        address="10.0.0.200",
        status="allocated",
        hostname="operator-host",
    )
    db_session.add(op_ip)
    await db_session.commit()
    # NB: the UUID primary key is a Python-side ``default=uuid.uuid4``
    # column default, so it is only assigned at flush/commit time — NOT
    # at construction. Capturing ``op_ip.id`` before the commit above
    # would record ``None`` and a later ``db_session.get(IPAddress, None)``
    # would (silently) return ``None`` regardless of the real DB state.
    op_ip_id = op_ip.id
    sub_block_id = sub.block_id

    # Second pass: the interface is gone upstream (no interfaces at all).
    with _patch_client(_FakeClient(interfaces=[])):
        summary = await reconcile_router(db_session, router)
    assert summary.ok, summary.error

    # Drop every cached ORM identity so the assertions below read the
    # true post-reconcile DB row state rather than an in-memory object
    # the test mutated/created earlier (the session uses
    # ``expire_on_commit=False``, so committed objects stay un-expired in
    # the identity map and ``db_session.get`` would hand them back
    # without re-querying — masking a cascade delete at the DB level).
    db_session.expire_all()

    # Subnet survives — un-claimed, not deleted.
    assert summary.subnets_deleted == 0
    surviving = await db_session.get(Subnet, sub_id)
    assert surviving is not None
    assert surviving.opnsense_router_id is None  # handed back to manual mgmt

    # Its enclosing block survives too — un-claiming a subnet must never
    # cascade-delete the block the operator IP still hangs off of.
    surviving_block = await db_session.get(IPBlock, sub_block_id)
    assert surviving_block is not None

    # Operator IP survives the cascade that a blind delete would trigger.
    surviving_ip = await db_session.get(IPAddress, op_ip_id)
    assert surviving_ip is not None
    assert surviving_ip.opnsense_router_id is None


@pytest.mark.asyncio
async def test_disappeared_subnet_with_no_foreign_children_is_deleted(
    db_session: AsyncSession,
) -> None:
    """Control case for the un-claim guard: a router-owned subnet with no
    surviving non-OPNsense children IS hard-deleted when its interface
    disappears upstream."""
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    await db_session.commit()

    iface = [_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")]
    with _patch_client(_FakeClient(interfaces=iface)):
        await reconcile_router(db_session, router)
    assert (
        await db_session.execute(select(Subnet).where(Subnet.opnsense_router_id == router.id))
    ).scalar_one_or_none() is not None

    with _patch_client(_FakeClient(interfaces=[])):
        summary = await reconcile_router(db_session, router)
    assert summary.ok, summary.error
    assert summary.subnets_deleted >= 1
    assert (
        await db_session.execute(select(Subnet).where(Subnet.opnsense_router_id == router.id))
    ).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_transient_client_error_aborts_without_deleting_mirror_rows(
    db_session: AsyncSession,
) -> None:
    """A transient client error (5xx / timeout — surfaced as an
    OPNsenseClientError raised from a list method) must abort the
    reconcile with last_sync_error set, NOT diff against an empty desired
    set and mass-delete the existing mirror rows."""
    from app.services.opnsense.client import OPNsenseClientError  # noqa: PLC0415

    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    await db_session.commit()

    # First pass: establish a mirrored lease row.
    iface = [_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")]
    with _patch_client(
        _FakeClient(
            interfaces=iface,
            leases=[_OPNLease(address="10.0.0.50", mac=None, hostname="x", state="active")],
        )
    ):
        await reconcile_router(db_session, router)
    assert (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.0.0.50"))
    ).scalar_one_or_none() is not None

    # Second pass: list_leases raises a transient error (no 404 status →
    # the client would re-raise rather than swallow-to-empty).
    class _RaisingClient(_FakeClient):
        async def list_leases(self):
            raise OPNsenseClientError("HTTP 503 — service unavailable", status_code=503)

    with _patch_client(_RaisingClient(interfaces=iface)):
        summary = await reconcile_router(db_session, router)

    # Reconcile aborted — error recorded, nothing deleted.
    assert not summary.ok
    assert summary.error is not None
    assert summary.addresses_deleted == 0
    await db_session.refresh(router)
    assert router.last_sync_error is not None

    # The mirrored row survived the transient blip.
    assert (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.0.0.50"))
    ).scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_list_leases_swallows_404_but_reraises_5xx(db_session: AsyncSession) -> None:
    """The client distinguishes a genuine 404 (endpoint absent → empty
    table) from a transient 5xx (re-raise)."""
    import httpx  # noqa: PLC0415

    from app.services.opnsense.client import OPNsenseClient, OPNsenseClientError  # noqa: PLC0415

    # 404 → empty list (DHCP service not enabled / endpoint absent).
    def _handler_404(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"message": "not found"})

    client = OPNsenseClient(host="fw.test", port=443, api_key="k", api_secret="s", verify_tls=False)
    client._client = httpx.AsyncClient(
        base_url="https://fw.test:443", transport=httpx.MockTransport(_handler_404)
    )
    try:
        result = await client.list_leases()
        assert result.leases == []
        # #797 — and no backend claimed to have answered, which is what
        # lets the reconciler warn instead of reporting a clean zero.
        assert result.sources_found == []
    finally:
        await client._client.aclose()

    # 5xx → re-raise so the reconciler aborts.
    def _handler_503(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="upstream busy")

    client2 = OPNsenseClient(
        host="fw.test", port=443, api_key="k", api_secret="s", verify_tls=False
    )
    client2._client = httpx.AsyncClient(
        base_url="https://fw.test:443", transport=httpx.MockTransport(_handler_503)
    )
    try:
        with pytest.raises(OPNsenseClientError) as exc_info:
            await client2.list_leases()
        assert exc_info.value.status_code == 503
    finally:
        await client2._client.aclose()


@pytest.mark.asyncio
async def test_same_address_in_another_space_does_not_block_own_space_row(
    db_session: AsyncSession,
) -> None:
    """Phase-1 existence/claim must be scoped to the firewall's IPAM
    space. The same IP existing in a DIFFERENT space (owned by another
    integration) must NOT make the firewall skip creating its legitimate
    row in its own space."""
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)

    # A foreign space with a row at the same address, owned by Proxmox.
    other_space = await _make_space(db_session)
    other_block = IPBlock(space_id=other_space.id, network="10.0.0.0/24", name="other-block")
    db_session.add(other_block)
    await db_session.flush()
    other_subnet = Subnet(
        space_id=other_space.id,
        block_id=other_block.id,
        network="10.0.0.0/24",
        name="other-subnet",
        total_ips=254,
    )
    db_session.add(other_subnet)
    await db_session.flush()

    from app.models.proxmox import ProxmoxNode  # noqa: PLC0415

    pnode = ProxmoxNode(
        name=f"pve-{uuid.uuid4().hex[:6]}",
        host="pve.test",
        token_id="root@pam!x",
        ipam_space_id=other_space.id,
    )
    db_session.add(pnode)
    await db_session.flush()
    foreign_ip = IPAddress(
        subnet_id=other_subnet.id,
        address="10.0.0.50",
        status="proxmox-vm",
        hostname="pve-guest",
        proxmox_node_id=pnode.id,
    )
    db_session.add(foreign_ip)
    await db_session.commit()

    fake = _FakeClient(
        interfaces=[_iface("lan", "igb1", "10.0.0.1", "10.0.0.0/24")],
        leases=[_OPNLease(address="10.0.0.50", mac=None, hostname="dhcp-name", state="active")],
    )
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)
    assert summary.ok, summary.error

    # The firewall's own-space row was created (not skipped by the
    # foreign-space match).
    own_rows = (
        (
            await db_session.execute(
                select(IPAddress)
                .join(Subnet, IPAddress.subnet_id == Subnet.id)
                .where(Subnet.space_id == space.id)
                .where(IPAddress.address == "10.0.0.50")
            )
        )
        .scalars()
        .all()
    )
    assert len(own_rows) == 1
    assert own_rows[0].opnsense_router_id == router.id

    # The foreign-space row is untouched.
    await db_session.refresh(foreign_ip)
    assert foreign_ip.opnsense_router_id is None
    assert foreign_ip.proxmox_node_id == pnode.id


@pytest.mark.asyncio
async def test_no_api_secret_records_error(db_session: AsyncSession) -> None:
    space = await _make_space(db_session)
    router = OPNsenseRouter(
        name=f"fw-{uuid.uuid4().hex[:6]}",
        host="fw.test",
        api_key="KEY",
        api_secret_encrypted=b"",  # unset
        ipam_space_id=space.id,
    )
    db_session.add(router)
    await db_session.commit()

    summary = await reconcile_router(db_session, router)
    assert not summary.ok
    assert summary.error is not None
    await db_session.refresh(router)
    assert router.last_sync_error is not None
    assert router.last_synced_at is not None
    # Watermark is recent.
    assert (datetime.now(UTC) - router.last_synced_at).total_seconds() < 60


# ── #797 — a green sync that mirrors nothing must say why ─────────────


@pytest.mark.asyncio
async def test_no_dhcp_backend_warns_instead_of_reporting_a_clean_zero(
    db_session: AsyncSession,
) -> None:
    """The reported bug, asserted at the reconcile level.

    OPNsense 25.7+ retired the ISC endpoints this integration used to be
    the only consumer of. Every request succeeded, the counts were all
    zero, and ``last_sync_error`` stayed NULL — so the UI showed a
    healthy integration that had never mirrored a single row. The pass
    still succeeds (nothing is wrong with the firewall), but it now
    carries a warning that names the cause.
    """
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    fake = _FakeClient(
        interfaces=[_iface("lan", "igc0", "172.20.1.1", "172.20.1.0/24")],
        leases=[],
        reservations=[],
        lease_sources=[],  # no Kea, no Dnsmasq, no ISC
        reservation_sources=[],
    )
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)

    assert summary.ok  # not an error — the firewall is fine
    assert any("no DHCP backend responded" in w for w in summary.warnings)
    await db_session.refresh(router)
    assert router.last_sync_error is None
    assert router.last_sync_warning is not None
    assert "no DHCP backend responded" in router.last_sync_warning


@pytest.mark.asyncio
async def test_backend_present_with_zero_leases_does_not_warn(
    db_session: AsyncSession,
) -> None:
    """A backend that answered and had nothing to say is a real zero.

    This is the other half of the distinction — without it the warning
    would fire on every quiet firewall and be trained away as noise.
    """
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    fake = _FakeClient(
        interfaces=[_iface("lan", "igc0", "172.20.1.1", "172.20.1.0/24")],
        leases=[],
        reservations=[],
        lease_sources=["kea"],
        reservation_sources=["kea"],
    )
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)

    assert summary.ok
    assert not any("no DHCP backend" in w for w in summary.warnings)
    await db_session.refresh(router)
    assert router.last_sync_warning is None


@pytest.mark.asyncio
async def test_forbidden_backend_warns_about_the_privilege_not_the_firmware(
    db_session: AsyncSession,
) -> None:
    """Kea's lease endpoints carry their own ACL (opnsense/core#7770).

    A 403 there has a different remedy from a 404 — add a privilege, not
    upgrade a firmware — so it gets its own message rather than being
    folded into "no backend responded".
    """
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    fake = _FakeClient(
        interfaces=[_iface("lan", "igc0", "172.20.1.1", "172.20.1.0/24")],
        lease_sources=["dnsmasq"],
        reservation_sources=["dnsmasq"],
        forbidden=["kea leases"],
    )
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)

    assert summary.ok
    assert any("refused by kea leases" in w for w in summary.warnings)
    # A backend DID answer, so the no-backend warning must not also fire.
    assert not any("no DHCP backend responded" in w for w in summary.warnings)


@pytest.mark.asyncio
async def test_zero_interfaces_warns_that_nothing_can_be_mirrored(
    db_session: AsyncSession,
) -> None:
    """Subnets come only from interfaces, and addresses need an enclosing
    subnet — so zero interfaces silently zeroes the entire mirror."""
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    fake = _FakeClient(interfaces=[], lease_sources=["kea"], reservation_sources=["kea"])
    with _patch_client(fake):
        summary = await reconcile_router(db_session, router)

    assert summary.ok
    assert any("no addressed interfaces found" in w for w in summary.warnings)


@pytest.mark.asyncio
async def test_warning_clears_once_the_condition_is_resolved(
    db_session: AsyncSession,
) -> None:
    """A stale amber chip is its own bug — the field is set to NULL on a
    clean pass rather than left at its last value."""
    space = await _make_space(db_session)
    router = await _make_router(db_session, space)
    iface = _iface("lan", "igc0", "172.20.1.1", "172.20.1.0/24")

    with _patch_client(_FakeClient(interfaces=[iface], lease_sources=[], reservation_sources=[])):
        await reconcile_router(db_session, router)
    await db_session.refresh(router)
    assert router.last_sync_warning is not None

    with _patch_client(
        _FakeClient(interfaces=[iface], lease_sources=["kea"], reservation_sources=["kea"])
    ):
        await reconcile_router(db_session, router)
    await db_session.refresh(router)
    assert router.last_sync_warning is None
