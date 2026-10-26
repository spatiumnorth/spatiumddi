"""Tests for the NetBox read-only one-shot IPAM importer (issue #36).

Three layers, mirroring the DHCP / cloud-DNS importer test split:

* **Mapping unit tests** — pure ``mapping.py`` / ``fetch.py`` / ``client.py``
  transforms against recorded NetBox 4.6-shaped dicts. No DB, no network:
  status maps, the block-vs-subnet decision (``classify_prefixes``),
  multicast ``kind`` detection, the dual token auth scheme, and the
  ``scope`` (4.2+) vs ``site`` (≤4.1) version branch.
* **Preview** — ``preview_netbox_import`` driven against a Postgres-backed
  session with the live ``NetBoxClient`` monkeypatched out for a
  ``FakeNetBoxClient`` that replays the recorded fixtures. Asserts the
  per-entity counts + conflict detection against a seeded DB (no writes).
* **Commit** — ``commit_import`` end-to-end: provenance stamping
  (``import_source="netbox"``), ``per_vrf`` → two IPSpaces with the same
  CIDR coexisting, tenant → Customer, VRF import/export targets as JSONB
  lists, region-parent-first site tree, prefix→VLAN ``vlan_ref_id`` link,
  vid/name clash skipped-with-warning, and a RE-RUN being a no-op.

The live NetBox API is never touched: ``preview_netbox_import`` opens a
``NetBoxClient`` directly, so we monkeypatch the class it imports
(``app.services.netbox_import.preview.NetBoxClient``) with a fake whose
``paginate`` yields recorded NetBox 4.6 JSON keyed by endpoint path.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.auth import User
from app.models.ipam import IPAddress, IPSpace, Subnet
from app.models.ownership import Customer, Site
from app.models.vlans import VLAN, Router
from app.models.vrf import VRF
from app.services.netbox_import import commit as nb_commit
from app.services.netbox_import import preview as nb_preview
from app.services.netbox_import.canonical import ImportPreview
from app.services.netbox_import.client import _auth_header
from app.services.netbox_import.commit import commit_import
from app.services.netbox_import.fetch import _normalize_scope
from app.services.netbox_import.mapping import (
    _IP_STATUS_MAP,
    _PREFIX_STATUS_MAP,
    classify_prefixes,
    map_address,
    map_prefix_subnet,
)
from app.services.netbox_import.preview import GLOBAL_SPACE_NAME, preview_netbox_import

# --------------------------------------------------------------------------- #
# Recorded fixtures.
# --------------------------------------------------------------------------- #

_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "netbox" / "netbox_46.json"


def _load_fixture() -> dict[str, Any]:
    data = json.loads(_FIXTURE_PATH.read_text())
    # Drop the leading documentation key.
    return {k: v for k, v in data.items() if not k.startswith("_")}


_FIXTURE = _load_fixture()


# --------------------------------------------------------------------------- #
# Fake NetBox client — replays recorded JSON, no network.
# --------------------------------------------------------------------------- #


class FakeNetBoxClient:
    """Drop-in for :class:`NetBoxClient` that replays recorded fixtures.

    ``paginate(path)`` yields the recorded ``results`` list for ``path``
    (already de-paginated in the fixture). ``detect_version`` returns a
    NetBox 4.6 version string. Constructed with the same kwargs the real
    client takes so the monkeypatch is transparent to ``preview.py``.
    """

    def __init__(self, *, responses: dict[str, list[dict[str, Any]]], **_kw: Any) -> None:
        self._responses = responses
        self.netbox_version = "4.6.3"
        self.api_version = "4.6"

    async def __aenter__(self) -> FakeNetBoxClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def detect_version(self) -> str:
        return "4.6"

    async def paginate(
        self, url: str, params: dict[str, Any] | None = None
    ) -> AsyncIterator[dict[str, Any]]:
        # The fixture is keyed on the bare endpoint path; the importer
        # always passes the same relative paths.
        for obj in self._responses.get(url, []):
            yield obj


def _patch_client(monkeypatch: pytest.MonkeyPatch, responses: dict[str, Any]) -> None:
    """Swap the live NetBoxClient for the recorded-fixture fake."""

    def _factory(**kwargs: Any) -> FakeNetBoxClient:
        return FakeNetBoxClient(responses=responses, **kwargs)

    monkeypatch.setattr(nb_preview, "NetBoxClient", _factory)


# --------------------------------------------------------------------------- #
# Seeding helpers.
# --------------------------------------------------------------------------- #


async def _make_admin(db: AsyncSession) -> User:
    user = User(
        username="netbox-import-admin",
        email="netbox-import-admin@example.com",
        display_name="netbox-import-admin",
        hashed_password="x",
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user


async def _run_preview(db: AsyncSession, **kwargs: Any) -> ImportPreview:
    return await preview_netbox_import(
        db,
        base_url="https://netbox.test",
        token="0123456789abcdef0123456789abcdef01234567",
        **kwargs,
    )


# =========================================================================== #
# 1. Mapping unit tests (pure — no DB, no network).
# =========================================================================== #


def test_prefix_status_map() -> None:
    """NetBox prefix status → Subnet.status; container is absent (→ block)."""
    assert _PREFIX_STATUS_MAP == {
        "active": "active",
        "reserved": "reserved",
        "deprecated": "deprecated",
    }
    assert "container" not in _PREFIX_STATUS_MAP
    # Unknown / missing prefix status falls back to "active" in the mapper.
    prefix = {"id": 1, "prefix": "10.0.0.0/24", "status": "weird"}
    sub = map_prefix_subnet(prefix, space_name="S")
    assert sub is not None and sub.status == "active"


def test_ip_status_map_collapses_dhcp_and_slaac() -> None:
    """IP active→allocated (NOT integration-owned dhcp); dhcp/slaac→allocated."""
    assert _IP_STATUS_MAP["active"] == "allocated"
    assert _IP_STATUS_MAP["reserved"] == "reserved"
    assert _IP_STATUS_MAP["deprecated"] == "deprecated"
    assert _IP_STATUS_MAP["dhcp"] == "allocated"
    assert _IP_STATUS_MAP["slaac"] == "allocated"

    dhcp_ip = map_address({"id": 1, "address": "10.0.0.6/24", "status": "dhcp"})
    assert dhcp_ip is not None and dhcp_ip.status == "allocated"


def test_classify_block_vs_subnet_rule() -> None:
    """container→block, active leaf→subnet, active enclosing→block.

    This pins issue #36 acceptance check #3: "an overlapping active-
    enclosing prefix becomes a block (not a 409)". A container prefix is a
    block. A true leaf is a subnet. An *active* prefix that encloses
    another active prefix in the same VRF must be forced to a block (two
    overlapping prefixes can't both be subnets — Subnet overlap is
    forbidden space-wide, so the enclosing one demotes to a block).

    ``classify_prefixes`` sorts CHILD-first (longer prefixlen first) so a
    more-specific child is classified before the prefix that encloses it —
    only then can ``_encloses_any`` see the child in ``prior`` and demote
    the enclosing /24 to a block. (A naive parent-first sort would process
    the /24 before its /25 and leave it a subnet, 409-ing on the overlap.)
    """
    prefixes = [
        # container → block
        {"id": 1, "prefix": "10.10.0.0/16", "status": "container", "vrf": {"id": 500}},
        # active leaf → subnet
        {"id": 2, "prefix": "10.10.20.0/24", "status": "active", "vrf": {"id": 500}},
        # active prefix enclosing the /25 below → must be forced to block
        {"id": 3, "prefix": "10.20.0.0/24", "status": "active", "vrf": {"id": 500}},
        {"id": 4, "prefix": "10.20.0.0/25", "status": "active", "vrf": {"id": 500}},
    ]
    decisions = classify_prefixes(prefixes)
    assert decisions[1] == "block"  # container
    assert decisions[2] == "subnet"  # true leaf
    assert decisions[3] == "block"  # active but encloses /25 → block (not 409)
    assert decisions[4] == "subnet"  # the enclosed leaf stays a subnet


def test_classify_overlap_across_vrfs_independent() -> None:
    """The same CIDR in two VRFs is classified independently per VRF."""
    prefixes = [
        {"id": 1, "prefix": "10.50.0.0/24", "status": "active", "vrf": {"id": 500}},
        {"id": 2, "prefix": "10.50.0.0/24", "status": "active", "vrf": {"id": 501}},
    ]
    decisions = classify_prefixes(prefixes)
    # Neither encloses anything within its own VRF → both stay subnets.
    assert decisions[1] == "subnet"
    assert decisions[2] == "subnet"


def test_multicast_kind_detection() -> None:
    """IPv4 224.0.0.0/4 / IPv6 ff00::/8 → kind=multicast; else unicast."""
    mc = map_prefix_subnet({"id": 1, "prefix": "239.1.0.0/24", "status": "active"}, space_name="G")
    assert mc is not None and mc.kind == "multicast"
    uc = map_prefix_subnet({"id": 2, "prefix": "10.0.0.0/24", "status": "active"}, space_name="G")
    assert uc is not None and uc.kind == "unicast"
    mc6 = map_prefix_subnet({"id": 3, "prefix": "ff00::/64", "status": "active"}, space_name="G")
    assert mc6 is not None and mc6.kind == "multicast"


def test_auth_scheme_detection() -> None:
    """v1 'Token <hex>' vs v2 'Bearer nbt_…' picked by prefix."""
    v1 = _auth_header("0123456789abcdef0123456789abcdef01234567")
    assert v1["Authorization"].startswith("Token ")
    v2 = _auth_header("nbt_abc.def")
    assert v2["Authorization"].startswith("Bearer nbt_")


def test_scope_vs_site_version_branch() -> None:
    """NetBox 4.2+ scope_type/scope vs ≤4.1 bare site collapse to one site."""
    # 4.2+ shape: scope_type=dcim.site + inlined scope brief.
    v42 = {
        "scope_type": "dcim.site",
        "scope_id": 400,
        "scope": {"id": 400, "name": "DC-1", "slug": "dc-1"},
    }
    site = _normalize_scope(v42)
    assert site is not None and site["slug"] == "dc-1"

    # 4.2+ non-site scope (region) → no Site link.
    v42_region = {"scope_type": "dcim.region", "scope_id": 1, "scope": {"id": 1, "name": "EMEA"}}
    assert _normalize_scope(v42_region) is None

    # ≤4.1 shape: a bare site FK, no scope_type key.
    v41 = {"site": {"id": 400, "name": "DC-1", "slug": "dc-1"}}
    site41 = _normalize_scope(v41)
    assert site41 is not None and site41["slug"] == "dc-1"


# =========================================================================== #
# 2. Preview tests (DB-backed, fixture-replayed; NO writes).
# =========================================================================== #


@pytest.mark.asyncio
async def test_preview_counts_per_vrf(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Preview returns correct per-entity counts and writes nothing."""
    _patch_client(monkeypatch, _FIXTURE)

    preview = await _run_preview(db_session, space_strategy="per_vrf")

    # 1 tenant → 1 customer.
    assert len(preview.customers) == 1
    assert preview.customers[0].name == "Acme Corp"

    # 2 regions (EMEA, London) + 1 site = 3 site nodes.
    assert len(preview.sites) == 3

    # 2 VRFs.
    assert len(preview.vrfs) == 2

    # per_vrf: 2 VRF spaces + 1 Global space.
    space_names = {s.name for s in preview.spaces}
    assert space_names == {"cust-a", "cust-b", GLOBAL_SPACE_NAME}

    # Aggregate 10.0.0.0/8 + the container prefix 10.10.0.0/16 → 2 blocks.
    by_cidr = {b.network: b.name for b in preview.blocks}
    assert "10.0.0.0/8" in by_cidr
    assert "10.10.0.0/16" in by_cidr
    # Real source blocks are named by their description/CIDR — the ``auto:``
    # prefix is reserved for committer-synthesized wrapper blocks.
    assert not by_cidr["10.0.0.0/8"].startswith("auto:")
    assert not by_cidr["10.10.0.0/16"].startswith("auto:")

    # leaf prefixes: 10.10.20.0/24 (cust-a), 10.50.0.0/24 ×2 (cust-a, cust-b),
    # 239.1.0.0/24 (multicast) → 4 subnets.
    assert len(preview.subnets) == 4

    # 2 IP addresses.
    assert len(preview.addresses) == 2

    # 4 VLANs in fixture, but vid-clash (802) + name-clash (803) skip → 2.
    assert {v.vid for v in preview.vlans} == {100, 200}

    # Side-effect-free: nothing committed to the DB.
    assert (await db_session.execute(select(IPSpace))).scalars().first() is None
    assert (await db_session.execute(select(Subnet))).scalars().first() is None


@pytest.mark.asyncio
async def test_preview_warnings_cover_unmodellable(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ip-range, vid/name clashes, and multicast surface as warnings."""
    _patch_client(monkeypatch, _FIXTURE)
    preview = await _run_preview(db_session, space_strategy="per_vrf")

    joined = "\n".join(preview.warnings)
    assert "ip-range" in joined  # ip-range metadata not imported
    assert "vid 100" in joined or "vid 100" in joined.lower()  # vid clash
    assert "clashes" in joined  # name/vid clash
    assert "multicast" in joined  # multicast subnet warns


@pytest.mark.asyncio
async def test_preview_detects_conflicts(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Conflicts are flagged against a seeded DB (existing customer + space)."""
    _patch_client(monkeypatch, _FIXTURE)

    # Seed an existing Customer + IPSpace that collide with the import.
    db_session.add(Customer(name="Acme Corp", status="active"))
    db_session.add(IPSpace(name="cust-a"))
    await db_session.commit()

    preview = await _run_preview(db_session, space_strategy="per_vrf")

    kinds = {(c.kind, c.key) for c in preview.conflicts}
    assert ("customer", "customer:Acme Corp") in kinds
    assert ("ip_space", "ip_space:cust-a") in kinds


# =========================================================================== #
# 3. Commit tests (DB-backed, end-to-end).
# =========================================================================== #


async def _preview_then_commit(
    db_session: AsyncSession,
    actor: User,
    *,
    space_strategy: str = "per_vrf",
    conflict_actions: dict[str, Any] | None = None,
) -> nb_commit.CommitResult:
    preview = await _run_preview(db_session, space_strategy=space_strategy)
    return await commit_import(
        db_session,
        preview=preview,
        conflict_actions=conflict_actions or {},
        space_strategy=space_strategy,
        actor=actor,
    )


@pytest.mark.asyncio
async def test_commit_creates_rows_with_provenance(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Commit creates rows stamped import_source='netbox' + audit rows."""
    _patch_client(monkeypatch, _FIXTURE)
    actor = await _make_admin(db_session)
    await db_session.commit()

    result = await _preview_then_commit(db_session, actor)

    assert result.source == "netbox"
    assert result.total_failed == 0, [e.error for e in result.entities if e.error]
    assert result.customers_created == 1
    assert result.vrfs_created == 2
    assert result.spaces_created == 3  # cust-a + cust-b + Global
    assert result.subnets_created == 4
    # 2 source blocks (aggregate 10.0.0.0/8 + container 10.10.0.0/16) + 3
    # synthesized wrapper blocks for the un-enclosed leaf subnets
    # (10.50.0.0/24 ×2 + the multicast 239.1.0.0/24) — all counted in the
    # ledger, not just the explicit source blocks.
    assert result.blocks_created == 5
    assert result.addresses_created >= 1  # multicast addr-in-subnet may skip; vips land

    # Provenance on a created subnet.
    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.network == "10.10.20.0/24"))
    ).scalar_one()
    assert subnet.import_source == "netbox"
    assert subnet.imported_at is not None
    assert subnet.custom_fields.get("netbox_id") == 701

    # An audit row exists for that subnet.
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "subnet", AuditLog.resource_id == str(subnet.id)
            )
        )
    ).scalar_one()
    assert audit.action == "create"
    assert audit.new_value.get("import_source") == "netbox"


@pytest.mark.asyncio
async def test_commit_per_vrf_overlapping_cidrs_coexist(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """per_vrf → 2 IPSpaces; the same 10.50.0.0/24 lands in each (no 409)."""
    _patch_client(monkeypatch, _FIXTURE)
    actor = await _make_admin(db_session)
    await db_session.commit()

    result = await _preview_then_commit(db_session, actor)
    assert result.total_failed == 0, [e.error for e in result.entities if e.error]

    # Two distinct spaces named after the VRFs.
    space_a = (
        await db_session.execute(select(IPSpace).where(IPSpace.name == "cust-a"))
    ).scalar_one()
    space_b = (
        await db_session.execute(select(IPSpace).where(IPSpace.name == "cust-b"))
    ).scalar_one()
    assert space_a.id != space_b.id

    # The overlapping CIDR exists once in each space.
    subnets = (
        (await db_session.execute(select(Subnet).where(Subnet.network == "10.50.0.0/24")))
        .scalars()
        .all()
    )
    space_ids = {s.space_id for s in subnets}
    assert space_ids == {space_a.id, space_b.id}
    assert len(subnets) == 2


@pytest.mark.asyncio
async def test_commit_tenant_stamped_as_customer(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Tenant → Customer; cust-a VRF carries customer_id of Acme Corp."""
    _patch_client(monkeypatch, _FIXTURE)
    actor = await _make_admin(db_session)
    await db_session.commit()

    await _preview_then_commit(db_session, actor)

    customer = (
        await db_session.execute(select(Customer).where(Customer.name == "Acme Corp"))
    ).scalar_one()
    assert customer.import_source == "netbox"

    vrf_a = (await db_session.execute(select(VRF).where(VRF.name == "cust-a"))).scalar_one()
    assert vrf_a.customer_id == customer.id
    # The cust-b VRF had no tenant → no customer link.
    vrf_b = (await db_session.execute(select(VRF).where(VRF.name == "cust-b"))).scalar_one()
    assert vrf_b.customer_id is None


@pytest.mark.asyncio
async def test_commit_vrf_targets_are_jsonb_lists(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """VRF import_targets / export_targets land as JSONB string lists."""
    _patch_client(monkeypatch, _FIXTURE)
    actor = await _make_admin(db_session)
    await db_session.commit()

    await _preview_then_commit(db_session, actor)

    vrf_a = (await db_session.execute(select(VRF).where(VRF.name == "cust-a"))).scalar_one()
    assert vrf_a.route_distinguisher == "65000:1"
    assert vrf_a.import_targets == ["65000:1"]
    assert sorted(vrf_a.export_targets) == ["65000:1", "65000:100"]


@pytest.mark.asyncio
async def test_commit_site_tree_region_parent_first(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Region nodes import as parent Sites; the site nests under its region."""
    _patch_client(monkeypatch, _FIXTURE)
    actor = await _make_admin(db_session)
    await db_session.commit()

    result = await _preview_then_commit(db_session, actor)
    assert result.sites_created == 3

    emea = (await db_session.execute(select(Site).where(Site.code == "emea"))).scalar_one()
    london = (await db_session.execute(select(Site).where(Site.code == "london"))).scalar_one()
    dc = (await db_session.execute(select(Site).where(Site.code == "dc-london-1"))).scalar_one()

    assert emea.parent_site_id is None  # top of the region tree
    assert london.parent_site_id == emea.id  # region parent chain
    assert dc.parent_site_id == london.id  # site nests under its region


@pytest.mark.asyncio
async def test_commit_prefix_vlan_link(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A prefix carrying a VLAN sets Subnet.vlan_ref_id to the imported VLAN."""
    _patch_client(monkeypatch, _FIXTURE)
    actor = await _make_admin(db_session)
    await db_session.commit()

    result = await _preview_then_commit(db_session, actor)
    assert result.vlans_created == 2

    # The synthetic router exists and holds the deduped VLANs.
    router = (
        await db_session.execute(select(Router).where(Router.name == "Imported VLANs (NetBox)"))
    ).scalar_one()
    vlan_100 = (
        await db_session.execute(
            select(VLAN).where(VLAN.router_id == router.id, VLAN.vlan_id == 100)
        )
    ).scalar_one()

    # 10.10.20.0/24 (prefix 701) referenced VLAN 800 (vid 100) → vlan_ref_id set.
    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.network == "10.10.20.0/24"))
    ).scalar_one()
    assert subnet.vlan_ref_id == vlan_100.id


@pytest.mark.asyncio
async def test_commit_vlan_clash_skipped_not_500(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """vid/name clashes within the synthetic router are skipped-with-warning.

    The fixture carries vlan 802 (vid 100 clash) + vlan 803 (name 'data'
    clash). Both are dropped at preview time with a warning, so the commit
    creates exactly the 2 non-clashing VLANs and never 500s on the
    (router, vid) / (router, name) unique constraint.
    """
    _patch_client(monkeypatch, _FIXTURE)
    actor = await _make_admin(db_session)
    await db_session.commit()

    result = await _preview_then_commit(db_session, actor)
    assert result.total_failed == 0, [e.error for e in result.entities if e.error]

    router = (
        await db_session.execute(select(Router).where(Router.name == "Imported VLANs (NetBox)"))
    ).scalar_one()
    vlans = (
        (await db_session.execute(select(VLAN).where(VLAN.router_id == router.id))).scalars().all()
    )
    assert {v.vlan_id for v in vlans} == {100, 200}
    # A clash warning surfaced.
    assert any("clashes" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_commit_addresses_land_under_subnet(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An IP lands under its most-specific imported subnet, dhcp→allocated."""
    _patch_client(monkeypatch, _FIXTURE)
    actor = await _make_admin(db_session)
    await db_session.commit()

    await _preview_then_commit(db_session, actor)

    subnet = (
        await db_session.execute(select(Subnet).where(Subnet.network == "10.10.20.0/24"))
    ).scalar_one()
    addr = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.10.20.5"))
    ).scalar_one()
    assert addr.subnet_id == subnet.id
    assert addr.import_source == "netbox"
    assert addr.role == "vip"  # role in the SpatiumDDI enum maps straight through
    assert addr.fqdn == "host5.acme.example"

    # The dhcp-status IP collapsed to allocated.
    dhcp_addr = (
        await db_session.execute(select(IPAddress).where(IPAddress.address == "10.10.20.6"))
    ).scalar_one()
    assert dhcp_addr.status == "allocated"


@pytest.mark.asyncio
async def test_commit_rerun_is_noop(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second commit of the same plan creates nothing — all skipped."""
    _patch_client(monkeypatch, _FIXTURE)
    actor = await _make_admin(db_session)
    await db_session.commit()

    first = await _preview_then_commit(db_session, actor)
    assert first.total_created > 0

    # Re-run a fresh preview + commit against the now-populated DB.
    second = await _preview_then_commit(db_session, actor)
    assert second.total_created == 0, [
        (e.kind, e.key) for e in second.entities if e.action_taken == "created"
    ]
    assert second.total_failed == 0, [e.error for e in second.entities if e.error]
    # Everything resolved to a skip.
    assert second.total_skipped > 0

    # Row counts didn't double.
    spaces = (await db_session.execute(select(IPSpace))).scalars().all()
    assert len({s.name for s in spaces}) == 3
    subnets = (await db_session.execute(select(Subnet))).scalars().all()
    assert len(subnets) == 4


@pytest.mark.asyncio
async def test_commit_failed_entity_does_not_poison_the_rest_2816(
    db_session: AsyncSession,
) -> None:
    """A VRF whose write raises rolls back only itself (#2816).

    The old per-entity ``db.rollback()`` expired the signed-in user, so the
    NEXT entity's audit row read ``actor.id`` outside the greenlet and failed
    too. Every entity after the bad one must still be created and audited.
    """
    from app.services.netbox_import.canonical import ImportedVRF

    actor = await _make_admin(db_session)
    await db_session.commit()
    preview = ImportPreview(
        source="netbox",
        vrfs=[
            ImportedVRF(name="good-before"),
            ImportedVRF(name="x" * 300),  # over String(255): the INSERT raises
            ImportedVRF(name="good-after"),
        ],
    )

    result = await commit_import(
        db_session, preview=preview, conflict_actions={}, space_strategy="per_vrf", actor=actor
    )

    taken = [e.action_taken for e in result.entities]
    assert taken == ["created", "failed", "created"], [e.error for e in result.entities]
    names = {v.name for v in (await db_session.execute(select(VRF))).scalars()}
    assert names == {"good-before", "good-after"}
    audited = {
        a.resource_display
        for a in (
            await db_session.execute(select(AuditLog).where(AuditLog.resource_type == "vrf"))
        ).scalars()
    }
    assert audited == {"good-before", "good-after"}
