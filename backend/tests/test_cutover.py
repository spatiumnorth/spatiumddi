"""Windows → SpatiumDDI cutover workflow (#756).

The tests that matter most here are the refusals. A cutover is the one
operation in this codebase that can take a production estate offline while
looking like it succeeded, and the issue names the failure mode explicitly:
migrating an AD-integrated "Secure only" zone means domain controllers can no
longer register their SRV records, which breaks Active Directory itself. That
refusal — and the fact that ``force`` cannot bypass it — is asserted from three
angles below.

Everything talks to fakes: no Windows box, no WinRM, no live DNS.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns.base import RecordData
from app.models.auth import User
from app.models.cutover import CutoverItem, CutoverPlan
from app.models.dhcp import DHCPPool, DHCPScope, DHCPServer, DHCPServerGroup, DHCPStaticAssignment
from app.models.dns import DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.cutover import leases as leases_mod
from app.services.cutover import parity as parity_mod
from app.services.cutover import preflight as preflight_mod
from app.services.cutover import readiness as readiness_mod
from app.services.cutover import switch as switch_mod
from app.services.cutover.canonical import BLOCKER_AD_SECURE_DDNS, blocking

# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class _FakeDNSDriver:
    """Stands in for ``WindowsDNSDriver``'s two read methods."""

    def __init__(
        self,
        records: list[RecordData] | None = None,
        zones: list[dict[str, Any]] | None = None,
        raises: Exception | None = None,
    ) -> None:
        self._records = records or []
        self._zones = zones or []
        self._raises = raises

    async def pull_zone_records(self, server: Any, zone_name: str) -> list[RecordData]:
        if self._raises is not None:
            raise self._raises
        return list(self._records)

    async def pull_zones_from_server(self, server: Any) -> list[dict[str, Any]]:
        if self._raises is not None:
            raise self._raises
        return list(self._zones)


class _FakeDHCPDriver:
    """Stands in for ``WindowsDHCPReadOnlyDriver``.

    ``state_calls`` records every ``set_scope_state`` invocation in order, which
    is what the switch-ordering tests assert on.
    """

    def __init__(
        self,
        scopes: list[dict[str, Any]] | None = None,
        leases: list[dict[str, Any]] | None = None,
    ) -> None:
        self._scopes = scopes or []
        self._leases = leases or []
        self.state_calls: list[tuple[str, bool]] = []

    async def get_scopes(self, server: Any) -> list[dict[str, Any]]:
        return list(self._scopes)

    async def get_leases(self, server: Any) -> list[dict[str, Any]]:
        return list(self._leases)

    async def set_scope_state(self, server: Any, scope_id: str, *, active: bool) -> None:
        self.state_calls.append((scope_id, active))


def _windows_scope(
    *,
    cidr: str = "10.20.0.0/24",
    scope_id: str = "10.20.0.0",
    lease_time: int = 86400,
    is_active: bool = True,
    pools: list[dict[str, Any]] | None = None,
    statics: list[dict[str, Any]] | None = None,
    options: dict[str, Any] | None = None,
    pools_ok: bool = True,
    statics_ok: bool = True,
) -> dict[str, Any]:
    """One entry shaped like ``WindowsDHCPReadOnlyDriver.get_scopes`` returns."""
    return {
        "scope_id": scope_id,
        "subnet_cidr": cidr,
        "name": "test scope",
        "description": "",
        "lease_time": lease_time,
        "is_active": is_active,
        "options": options or {},
        "pools": pools if pools is not None else [],
        "statics": statics if statics is not None else [],
        "pools_ok": pools_ok,
        "statics_ok": statics_ok,
    }


# --------------------------------------------------------------------------- #
# Seeding helpers
# --------------------------------------------------------------------------- #


async def _user(db: AsyncSession) -> User:
    user = User(
        username=f"cutover-{uuid.uuid4().hex[:8]}",
        email=f"cutover-{uuid.uuid4().hex[:8]}@example.com",
        display_name="cutover admin",
        hashed_password="x",
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return user


async def _dns_side(
    db: AsyncSession, *, zone_name: str = "corp.example.", import_source: str | None = None
) -> tuple[DNSServerGroup, DNSServer, DNSServer, DNSZone]:
    """A target group with one managed server, plus a Windows source server."""
    group = DNSServerGroup(name=f"grp-{uuid.uuid4().hex[:6]}")
    db.add(group)
    await db.flush()

    managed = DNSServer(
        group_id=group.id,
        name="ns-managed",
        driver="bind9",
        host="10.0.0.53",
        port=53,
        is_enabled=True,
        is_primary=True,
    )
    source_group = DNSServerGroup(name=f"win-{uuid.uuid4().hex[:6]}")
    db.add_all([managed, source_group])
    await db.flush()
    source = DNSServer(
        group_id=source_group.id,
        name="win-dns",
        driver="windows_dns",
        host="10.0.0.10",
        port=53,
        is_enabled=True,
    )
    zone = DNSZone(
        group_id=group.id,
        name=zone_name,
        zone_type="primary",
        kind="forward",
        ttl=3600,
        minimum=3600,
        import_source=import_source,
    )
    db.add_all([source, zone])
    await db.flush()
    return group, source, managed, zone


async def _dhcp_side(
    db: AsyncSession, *, cidr: str = "10.20.0.0/24", is_active: bool = False
) -> tuple[DHCPServerGroup, DHCPServer, DHCPScope, Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, name="blk", network=cidr)
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, name="sub", network=cidr)
    group = DHCPServerGroup(name=f"dgrp-{uuid.uuid4().hex[:6]}")
    source_group = DHCPServerGroup(name=f"dwin-{uuid.uuid4().hex[:6]}")
    db.add_all([subnet, group, source_group])
    await db.flush()

    # NB: DHCPServer's FK is ``server_group_id`` — DNSServer's is ``group_id``.
    # The two models disagree, so a copy-paste between the halves fails loudly.
    source = DHCPServer(
        server_group_id=source_group.id,
        name="win-dhcp",
        driver="windows_dhcp",
        host="10.0.0.11",
    )
    scope = DHCPScope(
        group_id=group.id,
        subnet_id=subnet.id,
        name="managed scope",
        is_active=is_active,
        lease_time=86400,
        address_family="ipv4",
    )
    # The target group needs at least one server or readiness blocks the
    # cutover — correctly, since activating a scope in an empty group would
    # leave the subnet with nothing handing out addresses.
    managed = DHCPServer(
        server_group_id=group.id,
        name="kea-managed",
        driver="kea",
        host="10.0.0.67",
    )
    db.add_all([source, scope, managed])
    await db.flush()
    return group, source, scope, subnet


async def _plan_with_item(
    db: AsyncSession,
    *,
    kind: str,
    source_ref: str,
    user: User,
    source_dns: DNSServer | None = None,
    source_dhcp: DHCPServer | None = None,
    dns_group_id: uuid.UUID | None = None,
    dhcp_group_id: uuid.UUID | None = None,
    zone: DNSZone | None = None,
    scope: DHCPScope | None = None,
    stage: str = "parity_checked",
    parity_ok: bool = False,
) -> tuple[CutoverPlan, CutoverItem]:
    """Seed a plan with one item.

    ``parity_ok`` stamps a clean parity report onto the item. Readiness treats a
    missing or non-``ok`` report as a hard block — an item whose parity was
    never established cannot be cut over — so any test that exercises the switch
    has to satisfy that first, exactly as an operator would.
    """
    plan = CutoverPlan(
        name=f"plan-{uuid.uuid4().hex[:8]}",
        status="verifying",
        source_dns_server_id=source_dns.id if source_dns else None,
        source_dhcp_server_id=source_dhcp.id if source_dhcp else None,
        target_dns_group_id=dns_group_id,
        target_dhcp_group_id=dhcp_group_id,
        created_by_user_id=user.id,
    )
    db.add(plan)
    await db.flush()
    item = CutoverItem(
        plan_id=plan.id,
        kind=kind,
        source_ref=source_ref,
        zone_id=zone.id if zone else None,
        scope_id=scope.id if scope else None,
        stage=stage,
        blockers=[],
        last_parity=(
            {"status": "ok", "difference_count": 0, "in_sync": 1, "is_parity": True}
            if parity_ok
            else None
        ),
        last_parity_at=datetime.now(UTC) if parity_ok else None,
    )
    db.add(item)
    await db.flush()
    return plan, item


# =========================================================================== #
# 1. The GSS-TSIG refusal — the hazard the issue calls out by name.
# =========================================================================== #


@pytest.mark.parametrize(
    "raw",
    ["Secure", "secure", "SECURE", 2, "2", 2.0],
    ids=["text", "lower", "upper", "int", "numeric-string", "float"],
)
def test_secure_dynamic_update_recognised_in_every_wire_shape(raw: Any) -> None:
    """``ConvertTo-Json`` emits the enum as a string on some builds and an int
    on others. Missing either shape means the AD blocker silently never fires."""
    assert readiness_mod.normalize_dynamic_update(raw) == "secure"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("None", "none"),
        (0, "none"),
        ("NonsecureAndSecure", "nonsecure_and_secure"),
        ("nonsecure and secure", "nonsecure_and_secure"),
        (1, "nonsecure_and_secure"),
        (None, None),
        ("", None),
        ("wat", None),
        # bool is an int subclass; True must not decode as NonsecureAndSecure.
        (True, None),
        (False, None),
    ],
)
def test_dynamic_update_normalisation(raw: Any, expected: str | None) -> None:
    assert readiness_mod.normalize_dynamic_update(raw) == expected


async def test_ad_secure_zone_is_hard_blocked(db_session: AsyncSession) -> None:
    user = await _user(db_session)
    group, source, _managed, zone = await _dns_side(db_session)
    plan, item = await _plan_with_item(
        db_session,
        kind="dns_zone",
        source_ref="corp.example",
        user=user,
        source_dns=source,
        dns_group_id=group.id,
        zone=zone,
    )
    await db_session.commit()

    blockers = await readiness_mod.evaluate_dns_item(
        db_session,
        plan=plan,
        item=item,
        zone=zone,
        source_zone_meta={
            "name": "corp.example",
            "zone_type": "Primary",
            "is_ad_integrated": True,
            "is_reverse_lookup": False,
            "dynamic_update": "Secure",
        },
    )
    hard = blocking(blockers)
    assert BLOCKER_AD_SECURE_DDNS in {b.code for b in hard}
    # The message has to tell the operator what to do about it, not just that
    # it is refused — this is the one refusal they cannot work around.
    msg = next(b.message for b in hard if b.code == BLOCKER_AD_SECURE_DDNS)
    assert "GSS-TSIG" in msg and "444" in msg


async def test_unreadable_dynamic_update_mode_fails_closed(db_session: AsyncSession) -> None:
    """An AD-integrated zone whose mode we cannot interpret is treated as
    Secure. "We could not check" must never resolve to "safe to migrate"."""
    user = await _user(db_session)
    group, source, _managed, zone = await _dns_side(db_session)
    plan, item = await _plan_with_item(
        db_session,
        kind="dns_zone",
        source_ref="corp.example",
        user=user,
        source_dns=source,
        dns_group_id=group.id,
        zone=zone,
    )
    await db_session.commit()

    blockers = await readiness_mod.evaluate_dns_item(
        db_session,
        plan=plan,
        item=item,
        zone=zone,
        source_zone_meta={
            "name": "corp.example",
            "is_ad_integrated": True,
            "dynamic_update": "SomethingNewMicrosoftAdded",
        },
    )
    assert BLOCKER_AD_SECURE_DDNS in {b.code for b in blocking(blockers)}


async def test_cutover_refuses_and_force_cannot_bypass_a_block(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The end-to-end guarantee: a blocked item does not cut over, with or
    without ``force``."""
    user = await _user(db_session)
    group, source, _managed, zone = await _dns_side(db_session)
    plan, item = await _plan_with_item(
        db_session,
        kind="dns_zone",
        source_ref="corp.example",
        user=user,
        source_dns=source,
        dns_group_id=group.id,
        zone=zone,
    )
    await db_session.commit()

    monkeypatch.setattr(
        readiness_mod,
        "get_dns_driver",
        lambda _d: _FakeDNSDriver(
            zones=[
                {
                    "name": "corp.example",
                    "is_ad_integrated": True,
                    "dynamic_update": "Secure",
                    "is_reverse_lookup": False,
                    "zone_type": "Primary",
                }
            ]
        ),
    )

    for force in (False, True):
        with pytest.raises(switch_mod.CutoverBlocked) as exc:
            await switch_mod.execute_cutover(
                db_session, plan=plan, item=item, current_user=user, force=force
            )
        assert BLOCKER_AD_SECURE_DDNS in {b.code for b in exc.value.blockers}

    await db_session.refresh(item)
    assert item.stage != "cut_over"
    assert item.cut_over_at is None


# =========================================================================== #
# 2. DNS parity classification.
# =========================================================================== #


async def _run_dns_parity(
    db: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    *,
    zone: DNSZone,
    source: DNSServer,
    wire: list[RecordData],
) -> Any:
    monkeypatch.setattr(parity_mod, "get_dns_driver", lambda _d: _FakeDNSDriver(records=wire))
    return await parity_mod.compute_dns_parity(
        db, source_server=source, zone=zone, source_zone_name=zone.name.rstrip(".")
    )


async def test_dns_parity_pairs_a_changed_value_into_one_difference(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The delta over #61: same name+type with different data is ONE decision,
    not a missing+extra pair."""
    _group, source, _managed, zone = await _dns_side(db_session, import_source="windows_dns")
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    await db_session.commit()

    report = await _run_dns_parity(
        db_session,
        monkeypatch,
        zone=zone,
        source=source,
        wire=[RecordData(name="www", record_type="A", value="10.0.0.99")],
    )
    assert report.status == "ok"
    assert [d.classification for d in report.differences] == ["value_mismatch"]
    diff = report.differences[0]
    assert diff.source_value == "10.0.0.99"
    assert diff.target_value == "10.0.0.1"


async def test_dns_parity_windows_only_keys_off_import_provenance(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An imported zone that Windows has moved on from reports
    ``drifted_since_import``; one with no provenance reports
    ``never_imported``. Row-level provenance does not exist, so the zone's is
    the only evidence available — assert we use it consistently."""
    for provenance, expected in (
        ("windows_dns", "drifted_since_import"),
        (None, "never_imported"),
    ):
        _g, source, _m, zone = await _dns_side(
            db_session,
            zone_name=f"z{uuid.uuid4().hex[:6]}.example.",
            import_source=provenance,
        )
        await db_session.commit()
        report = await _run_dns_parity(
            db_session,
            monkeypatch,
            zone=zone,
            source=source,
            wire=[RecordData(name="new", record_type="A", value="10.0.0.7")],
        )
        assert [d.classification for d in report.differences] == [expected]


async def test_dns_parity_spatium_only_is_intentionally_diverged(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _g, source, _m, zone = await _dns_side(db_session, import_source="windows_dns")
    db_session.add(DNSRecord(zone_id=zone.id, name="only-here", record_type="A", value="10.0.0.5"))
    await db_session.commit()

    report = await _run_dns_parity(db_session, monkeypatch, zone=zone, source=source, wire=[])
    # Zero-on-the-wire with rows in the DB is the ambiguous case (a parse
    # failure returns [] identically), so it must NOT read as a clean diff.
    assert report.status == "unverified"
    assert not report.is_parity


async def test_dns_parity_in_sync_reports_parity(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _g, source, _m, zone = await _dns_side(db_session, import_source="windows_dns")
    db_session.add(DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"))
    await db_session.commit()

    report = await _run_dns_parity(
        db_session,
        monkeypatch,
        zone=zone,
        source=source,
        wire=[RecordData(name="www", record_type="A", value="10.0.0.1", ttl=60)],
    )
    # TTL-only differences are the pre-flight step's business, not parity's.
    assert report.is_parity
    assert report.in_sync == 1


async def test_dns_parity_pull_failure_is_reported_not_raised(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _g, source, _m, zone = await _dns_side(db_session)
    await db_session.commit()
    monkeypatch.setattr(
        parity_mod,
        "get_dns_driver",
        lambda _d: _FakeDNSDriver(raises=RuntimeError("WinRM transport failure")),
    )
    report = await parity_mod.compute_dns_parity(
        db_session, source_server=source, zone=zone, source_zone_name="corp.example"
    )
    assert report.status == "error"
    assert "WinRM" in (report.error or "")
    assert not report.is_parity


async def test_dns_parity_skips_types_the_read_path_cannot_see(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Path-B pull cannot emit CAA, so a CAA row in the DB must not be
    reported as a difference — that would send the operator to "fix" a record
    that is already correct on both sides."""
    _g, source, _m, zone = await _dns_side(db_session, import_source="windows_dns")
    # Path B is selected by the presence of credentials.
    source.credentials_encrypted = b"not-really-encrypted-but-truthy"
    db_session.add_all(
        [
            DNSRecord(zone_id=zone.id, name="@", record_type="CAA", value='0 issue "le.org"'),
            DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1"),
        ]
    )
    await db_session.commit()

    report = await _run_dns_parity(
        db_session,
        monkeypatch,
        zone=zone,
        source=source,
        wire=[RecordData(name="www", record_type="A", value="10.0.0.1")],
    )
    assert report.is_parity, [d.as_dict() for d in report.differences]
    assert report.not_compared == 1
    assert any("not compared" in w for w in report.warnings)


# =========================================================================== #
# 3. DHCP parity.
# =========================================================================== #


async def test_dhcp_parity_diffs_lease_time_pools_and_reservations(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _group, source, scope, _subnet = await _dhcp_side(db_session)
    db_session.add_all(
        [
            DHCPPool(
                scope_id=scope.id, start_ip="10.20.0.100", end_ip="10.20.0.200", pool_type="dynamic"
            ),
            DHCPStaticAssignment(
                scope_id=scope.id,
                ip_address="10.20.0.50",
                mac_address="aa:bb:cc:dd:ee:ff",
                hostname="printer",
            ),
        ]
    )
    await db_session.commit()

    windows = _windows_scope(
        lease_time=43200,  # differs from the scope's 86400
        pools=[{"start_ip": "10.20.0.100", "end_ip": "10.20.0.150", "pool_type": "dynamic"}],
        statics=[
            # Windows reports the ClientId form with the 01- hardware-type
            # prefix; it must fold onto the same MAC, not read as a difference.
            {
                "mac_address": "01-AA-BB-CC-DD-EE-FF",
                "ip_address": "10.20.0.51",
                "hostname": "printer",
            }
        ],
    )
    monkeypatch.setattr(parity_mod, "get_dhcp_driver", lambda _d: _FakeDHCPDriver(scopes=[windows]))

    report = await parity_mod.compute_dhcp_parity(
        db_session, source_server=source, scope=scope, source_scope_id="10.20.0.0"
    )
    assert report.status == "ok"
    kinds = {(d.name, d.classification) for d in report.differences}
    assert ("lease_time", "value_mismatch") in kinds
    # The reservation folded onto one MAC and differs only by address.
    assert ("aa:bb:cc:dd:ee:ff", "value_mismatch") in kinds
    assert any(name == "pool" for name, _ in kinds)


async def test_dhcp_parity_honours_statics_ok(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#620: an enumeration failure returns an empty ``statics`` list. Treating
    that as "Windows has no reservations" would report every managed
    reservation as diverged off the back of a transient PowerShell error."""
    _group, source, scope, _subnet = await _dhcp_side(db_session)
    db_session.add(
        DHCPStaticAssignment(
            scope_id=scope.id, ip_address="10.20.0.50", mac_address="aa:bb:cc:dd:ee:ff"
        )
    )
    await db_session.commit()

    windows = _windows_scope(lease_time=86400, statics=[], statics_ok=False)
    monkeypatch.setattr(parity_mod, "get_dhcp_driver", lambda _d: _FakeDHCPDriver(scopes=[windows]))

    report = await parity_mod.compute_dhcp_parity(
        db_session, source_server=source, scope=scope, source_scope_id="10.20.0.0"
    )
    assert not any(d.name == "aa:bb:cc:dd:ee:ff" for d in report.differences)
    assert any("could not be enumerated" in w for w in report.warnings)


async def test_dhcp_parity_unmatched_scope(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _group, source, scope, _subnet = await _dhcp_side(db_session)
    await db_session.commit()
    monkeypatch.setattr(
        parity_mod,
        "get_dhcp_driver",
        lambda _d: _FakeDHCPDriver(
            scopes=[_windows_scope(cidr="192.168.9.0/24", scope_id="192.168.9.0")]
        ),
    )
    report = await parity_mod.compute_dhcp_parity(
        db_session, source_server=source, scope=scope, source_scope_id="10.20.0.0"
    )
    assert report.status == "unmatched"
    assert not report.is_parity


# =========================================================================== #
# 4. Lease handover.
# =========================================================================== #


async def test_lease_handover_classifies_every_lease(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _group, source, scope, _subnet = await _dhcp_side(db_session)
    db_session.add(
        DHCPStaticAssignment(
            scope_id=scope.id, ip_address="10.20.0.50", mac_address="11:11:11:11:11:11"
        )
    )
    await db_session.commit()

    driver = _FakeDHCPDriver(
        leases=[
            # Carried across.
            {"ip_address": "10.20.0.60", "mac_address": "22:22:22:22:22:22", "hostname": "laptop"},
            # Outside the managed scope's subnet — belongs to another scope.
            {"ip_address": "192.168.5.10", "mac_address": "33:33:33:33:33:33", "hostname": "far"},
            # MAC already reserved to a DIFFERENT address on this scope.
            {"ip_address": "10.20.0.70", "mac_address": "11:11:11:11:11:11", "hostname": "dup"},
            # No usable MAC.
            {"ip_address": "10.20.0.80", "mac_address": "", "client_id": "not-a-mac"},
        ]
    )
    monkeypatch.setattr(leases_mod, "WindowsDHCPReadOnlyDriver", lambda: driver)

    plan = await leases_mod.preview_lease_handover(
        db_session, source_server=source, scope=scope, source_scope_id="10.20.0.0"
    )
    by_ip = {e.ip_address: e for e in plan.entries}
    assert by_ip["10.20.0.60"].action == "create"
    assert by_ip["192.168.5.10"].action == "skip"
    assert by_ip["10.20.0.70"].action == "conflict"
    assert by_ip["10.20.0.80"].action == "skip"
    assert plan.create_count == 1
    assert plan.conflict_count == 1


async def test_lease_handover_commit_creates_reservations_with_provenance(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session)
    _group, source, scope, _subnet = await _dhcp_side(db_session)
    _plan, item = await _plan_with_item(
        db_session,
        kind="dhcp_scope",
        source_ref="10.20.0.0",
        user=user,
        source_dhcp=source,
        scope=scope,
    )
    await db_session.commit()

    driver = _FakeDHCPDriver(
        leases=[
            {"ip_address": "10.20.0.60", "mac_address": "22:22:22:22:22:22", "hostname": "laptop"},
            {"ip_address": "10.20.0.61", "mac_address": "44:44:44:44:44:44", "hostname": "phone"},
        ]
    )
    monkeypatch.setattr(leases_mod, "WindowsDHCPReadOnlyDriver", lambda: driver)

    preview = await leases_mod.preview_lease_handover(
        db_session, source_server=source, scope=scope, source_scope_id="10.20.0.0"
    )
    result = await leases_mod.commit_lease_handover(
        db_session,
        source_server=source,
        scope=scope,
        item=item,
        plan=preview,
        current_user=user,
    )
    await db_session.commit()

    assert result.created == 2
    assert result.failed == 0
    rows = (
        (
            await db_session.execute(
                DHCPStaticAssignment.__table__.select().where(
                    DHCPStaticAssignment.scope_id == scope.id
                )
            )
        )
        .mappings()
        .all()
    )
    assert {str(r["ip_address"]) for r in rows} == {"10.20.0.60", "10.20.0.61"}
    # Provenance is what makes these findable + removable once leases churn.
    assert all(r["import_source"] == leases_mod.CUTOVER_IMPORT_SOURCE for r in rows)
    assert item.lease_handover["created"] == 2


async def test_lease_handover_empty_pull_warns_rather_than_reporting_success(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty lease list is indistinguishable from a failed read, so it must
    not present as a clean handover."""
    _group, source, scope, _subnet = await _dhcp_side(db_session)
    await db_session.commit()
    monkeypatch.setattr(leases_mod, "WindowsDHCPReadOnlyDriver", lambda: _FakeDHCPDriver(leases=[]))

    plan = await leases_mod.preview_lease_handover(
        db_session, source_server=source, scope=scope, source_scope_id="10.20.0.0"
    )
    assert plan.entries == []
    assert any("no active leases" in w for w in plan.warnings)


# =========================================================================== #
# 5. TTL pre-flight.
# =========================================================================== #


@pytest.mark.parametrize("bad", [0, 29, 86401, 999999])
def test_target_ttl_bounds(bad: int) -> None:
    with pytest.raises(ValueError):
        preflight_mod.validate_target_ttl(bad)


async def test_ttl_preflight_snapshots_once_and_restores_exactly(
    db_session: AsyncSession,
) -> None:
    user = await _user(db_session)
    group, source, _managed, zone = await _dns_side(db_session)
    explicit = DNSRecord(zone_id=zone.id, name="www", record_type="A", value="10.0.0.1", ttl=3600)
    inherited = DNSRecord(zone_id=zone.id, name="app", record_type="A", value="10.0.0.2", ttl=None)
    db_session.add_all([explicit, inherited])
    _plan, item = await _plan_with_item(
        db_session,
        kind="dns_zone",
        source_ref="corp.example",
        user=user,
        source_dns=source,
        dns_group_id=group.id,
        zone=zone,
    )
    await db_session.commit()

    await preflight_mod.apply_ttl_preflight(
        db_session, zone=zone, item=item, target_ttl=300, current_user=user
    )
    await db_session.commit()
    assert zone.ttl == 300
    assert explicit.ttl == 300
    # An inherited TTL is pinned explicitly so the restore can put the
    # inheritance back rather than leaving it stuck at the zone default.
    assert inherited.ttl == 300
    first_snapshot = dict(item.ttl_snapshot or {})

    # A second, lower apply must NOT overwrite the pristine snapshot.
    await preflight_mod.apply_ttl_preflight(
        db_session, zone=zone, item=item, target_ttl=60, current_user=user
    )
    await db_session.commit()
    assert item.ttl_snapshot["zone"] == first_snapshot["zone"]
    assert zone.ttl == 60

    await preflight_mod.restore_ttl_preflight(db_session, zone=zone, item=item, current_user=user)
    await db_session.commit()
    assert zone.ttl == 3600
    assert explicit.ttl == 3600
    assert inherited.ttl is None
    assert item.ttl_snapshot is None


async def test_ttl_restore_without_snapshot_is_a_no_op(db_session: AsyncSession) -> None:
    """Rollback calls this unconditionally, so "nothing was lowered" must not
    be an error."""
    user = await _user(db_session)
    group, source, _managed, zone = await _dns_side(db_session)
    _plan, item = await _plan_with_item(
        db_session,
        kind="dns_zone",
        source_ref="corp.example",
        user=user,
        source_dns=source,
        dns_group_id=group.id,
        zone=zone,
    )
    await db_session.commit()
    assert (
        await preflight_mod.restore_ttl_preflight(
            db_session, zone=zone, item=item, current_user=user
        )
        == 0
    )


# =========================================================================== #
# 6. The DHCP switch — ordering is the whole safety property.
# =========================================================================== #


async def test_dhcp_cutover_deactivates_windows_before_activating_kea(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session)
    group, source, scope, _subnet = await _dhcp_side(db_session, is_active=False)
    plan, item = await _plan_with_item(
        db_session,
        kind="dhcp_scope",
        source_ref="10.20.0.0",
        user=user,
        source_dhcp=source,
        dhcp_group_id=group.id,
        scope=scope,
        parity_ok=True,
    )
    await db_session.commit()

    driver = _FakeDHCPDriver(scopes=[_windows_scope()])
    monkeypatch.setattr(switch_mod, "WindowsDHCPReadOnlyDriver", lambda: driver)
    monkeypatch.setattr(readiness_mod, "get_dhcp_driver", lambda _d: driver)

    await switch_mod.execute_cutover(
        db_session, plan=plan, item=item, current_user=user, force=True
    )
    await db_session.commit()

    # Deactivate-then-activate. The reverse order leaves both servers handing
    # out addresses on the same subnet.
    assert driver.state_calls == [("10.20.0.0", False)]
    assert scope.is_active is True
    assert item.stage == "cut_over"
    assert item.cut_over_at is not None


async def _disabled_phone_pool(db: AsyncSession, group: DHCPServerGroup, scope: DHCPScope):
    """A scope pool restricted to a phone profile that has since been disabled
    (#4376): the class no longer renders, so the pool would match no client."""
    from app.models.dhcp import DHCPPhoneProfile, DHCPPhoneProfileScope
    from app.services.dhcp.class_refs import phone_class_name

    prof = DHCPPhoneProfile(
        group_id=group.id, name="poly", enabled=False, vendor_class_match="Polycom", option_set=[]
    )
    db.add(prof)
    await db.flush()
    db.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=scope.id))
    db.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="10.20.0.10",
            end_ip="10.20.0.50",
            pool_type="dynamic",
            class_restriction=phone_class_name(prof.id),
        )
    )
    await db.flush()


async def test_dhcp_cutover_refused_when_a_pool_class_is_disabled(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#4376: activation by cutover applies the #4367 rule, and Windows is
    never touched when it refuses."""
    from app.services.cutover.canonical import BLOCKER_POOL_CLASS_UNAVAILABLE

    user = await _user(db_session)
    group, source, scope, _subnet = await _dhcp_side(db_session, is_active=False)
    await _disabled_phone_pool(db_session, group, scope)
    plan, item = await _plan_with_item(
        db_session,
        kind="dhcp_scope",
        source_ref="10.20.0.0",
        user=user,
        source_dhcp=source,
        dhcp_group_id=group.id,
        scope=scope,
        parity_ok=True,
    )
    await db_session.commit()

    driver = _FakeDHCPDriver(scopes=[_windows_scope()])
    monkeypatch.setattr(switch_mod, "WindowsDHCPReadOnlyDriver", lambda: driver)
    monkeypatch.setattr(readiness_mod, "get_dhcp_driver", lambda _d: driver)

    with pytest.raises(switch_mod.CutoverBlocked) as exc:
        await switch_mod.execute_cutover(
            db_session, plan=plan, item=item, current_user=user, force=True
        )
    assert any(b.code == BLOCKER_POOL_CLASS_UNAVAILABLE for b in exc.value.blockers)
    assert "10.20.0.10-10.20.0.50" in str(exc.value)
    assert "disabled" in str(exc.value)
    assert driver.state_calls == []
    assert scope.is_active is False


async def test_dhcp_cutover_rechecks_pool_classes_before_touching_windows(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale preflight must not get past ``_cutover_dhcp``: with readiness
    reporting clean, the switch itself still refuses before the WinRM call."""
    user = await _user(db_session)
    group, source, scope, _subnet = await _dhcp_side(db_session, is_active=False)
    await _disabled_phone_pool(db_session, group, scope)
    plan, item = await _plan_with_item(
        db_session,
        kind="dhcp_scope",
        source_ref="10.20.0.0",
        user=user,
        source_dhcp=source,
        dhcp_group_id=group.id,
        scope=scope,
        parity_ok=True,
    )
    await db_session.commit()

    driver = _FakeDHCPDriver(scopes=[_windows_scope()])
    monkeypatch.setattr(switch_mod, "WindowsDHCPReadOnlyDriver", lambda: driver)

    with pytest.raises(switch_mod.CutoverBlocked):
        await switch_mod._cutover_dhcp(
            db_session, plan=plan, item=item, current_user=user, acknowledged=[]
        )
    assert driver.state_calls == []
    assert scope.is_active is False


async def test_dhcp_rollback_reverses_the_switch(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = await _user(db_session)
    group, source, scope, _subnet = await _dhcp_side(db_session, is_active=True)
    plan, item = await _plan_with_item(
        db_session,
        kind="dhcp_scope",
        source_ref="10.20.0.0",
        user=user,
        source_dhcp=source,
        dhcp_group_id=group.id,
        scope=scope,
        stage="cut_over",
    )
    await db_session.commit()

    driver = _FakeDHCPDriver(scopes=[_windows_scope(is_active=False)])
    monkeypatch.setattr(switch_mod, "WindowsDHCPReadOnlyDriver", lambda: driver)

    await switch_mod.execute_rollback(db_session, plan=plan, item=item, current_user=user)
    await db_session.commit()

    assert ("10.20.0.0", True) in driver.state_calls
    assert scope.is_active is False
    assert item.stage == "rolled_back"


async def test_dhcp_cutover_reactivates_windows_when_activation_fails(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the managed side fails to come up, the subnet is left with no DHCP at
    all — so the Windows scope must be put back before the error surfaces."""
    user = await _user(db_session)
    group, source, scope, _subnet = await _dhcp_side(db_session, is_active=False)
    plan, item = await _plan_with_item(
        db_session,
        kind="dhcp_scope",
        source_ref="10.20.0.0",
        user=user,
        source_dhcp=source,
        dhcp_group_id=group.id,
        scope=scope,
        parity_ok=True,
    )
    await db_session.commit()

    driver = _FakeDHCPDriver(scopes=[_windows_scope()])
    monkeypatch.setattr(switch_mod, "WindowsDHCPReadOnlyDriver", lambda: driver)
    monkeypatch.setattr(readiness_mod, "get_dhcp_driver", lambda _d: driver)

    def _boom(*_a: Any, **_kw: Any) -> None:
        raise RuntimeError("wake bus exploded")

    monkeypatch.setattr(switch_mod, "collect_wake", _boom)

    with pytest.raises(RuntimeError, match="wake bus exploded"):
        await switch_mod.execute_cutover(
            db_session, plan=plan, item=item, current_user=user, force=True
        )
    await db_session.rollback()

    assert driver.state_calls == [("10.20.0.0", False), ("10.20.0.0", True)]


# =========================================================================== #
# 7. Regressions from the #756 code review.
# =========================================================================== #


async def test_rollback_clears_cut_over_at_so_pre_switch_blockers_return(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A rolled-back item must be treated as *not* cut over.

    ``readiness._is_cut_over`` short-circuits the pre-switch checks so a
    completed item does not look permanently unready. If a rollback left
    ``cut_over_at`` set, that suppression would persist — and the next attempt
    would skip ``managed_scope_active``, the blocker that refuses a retry while
    both servers are live on the same subnet.
    """
    user = await _user(db_session)
    group, source, scope, _subnet = await _dhcp_side(db_session, is_active=True)
    plan, item = await _plan_with_item(
        db_session,
        kind="dhcp_scope",
        source_ref="10.20.0.0",
        user=user,
        source_dhcp=source,
        dhcp_group_id=group.id,
        scope=scope,
        stage="cut_over",
        parity_ok=True,
    )
    item.cut_over_at = datetime.now(UTC)
    await db_session.commit()

    driver = _FakeDHCPDriver(scopes=[_windows_scope(is_active=False)])
    monkeypatch.setattr(switch_mod, "WindowsDHCPReadOnlyDriver", lambda: driver)
    await switch_mod.execute_rollback(db_session, plan=plan, item=item, current_user=user)
    await db_session.commit()

    assert item.cut_over_at is None
    assert readiness_mod._is_cut_over(item) is False

    # Now simulate the operator re-activating the managed scope by hand while
    # Windows is serving again: the hard block must be back.
    scope.is_active = True
    await db_session.commit()
    blockers = await readiness_mod.evaluate_dhcp_item(
        db_session, plan=plan, item=item, scope=scope, source_scope=_windows_scope(is_active=True)
    )
    assert "managed_scope_active" in {b.code for b in blocking(blockers)}


async def test_match_source_scope_does_not_match_on_empty_cidr() -> None:
    """An item with no linked subnet passes ``subnet_cidr=""``. That must match
    nothing — matching a scope whose own ``subnet_cidr`` is missing would hand
    readiness an unrelated Windows scope and suppress ``source_scope_missing``."""
    scopes = [{"scope_id": "192.168.9.0", "subnet_cidr": ""}]
    assert parity_mod.match_source_scope(scopes, subnet_cidr="", source_scope_id="") is None
    # A real id still matches by scope_id.
    assert (
        parity_mod.match_source_scope(scopes, subnet_cidr="", source_scope_id="192.168.9.0")
        is not None
    )


async def test_ttl_preflight_refuses_when_the_group_primary_is_agentless(
    db_session: AsyncSession,
) -> None:
    """The pre-flight promises never to write to the Windows source. If the
    target group's primary IS an agentless server, ``enqueue_record_ops_batch``
    would dispatch straight at it — so the apply refuses instead."""
    user = await _user(db_session)
    group = DNSServerGroup(name=f"grp-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    db_session.add(
        DNSServer(
            group_id=group.id,
            name="win-dns-primary",
            driver="windows_dns",
            host="10.0.0.10",
            is_enabled=True,
            is_primary=True,
        )
    )
    zone = DNSZone(group_id=group.id, name="risky.example.", zone_type="primary", kind="forward")
    db_session.add(zone)
    await db_session.flush()
    _plan, item = await _plan_with_item(
        db_session, kind="dns_zone", source_ref="risky.example", user=user, zone=zone
    )
    await db_session.commit()

    with pytest.raises(ValueError, match="agentless"):
        await preflight_mod.apply_ttl_preflight(
            db_session, zone=zone, item=item, target_ttl=300, current_user=user
        )


async def test_checklist_read_is_read_only_and_patch_creates_the_row(
    db_session: AsyncSession,
) -> None:
    """Reading a checklist must not write — a GET that seeds rows would owe an
    audit entry and would slip past the maintenance-mode gate."""
    from sqlalchemy import func as sa_func

    from app.models.cutover import CutoverChecklistItem
    from app.services.cutover import checklist as checklist_mod

    user = await _user(db_session)
    plan, _item = await _plan_with_item(
        db_session, kind="dns_zone", source_ref="corp.example", user=user
    )
    await db_session.commit()

    views = await checklist_mod.read_checklist(db_session, plan=plan)
    assert len(views) == len(checklist_mod.DECOMMISSION_CHECKLIST)
    assert all(v.is_done is False for v in views)
    stored = (
        await db_session.execute(
            select(sa_func.count())
            .select_from(CutoverChecklistItem)
            .where(CutoverChecklistItem.plan_id == plan.id)
        )
    ).scalar_one()
    assert stored == 0, "read_checklist must not create rows"

    key = checklist_mod.DECOMMISSION_CHECKLIST[0].key
    row = await checklist_mod.upsert_checklist_row(db_session, plan=plan, key=key)
    assert row is not None
    row.is_done = True
    await db_session.commit()

    views = await checklist_mod.read_checklist(db_session, plan=plan)
    assert next(v for v in views if v.key == key).is_done is True
    # An unknown key must not mint a row.
    assert await checklist_mod.upsert_checklist_row(db_session, plan=plan, key="nope") is None


def test_runbook_and_preflight_share_one_powershell_generator() -> None:
    """Two hand-maintained copies of the same operator command is how one of
    them ends up wrong. The runbook fences the preflight generator's output."""
    from app.services.cutover import runbook as runbook_mod

    fenced = runbook_mod._ps_lower_ttls("dc01.corp.example", "corp.example", 300, 3600)
    body = "\n".join(fenced)
    assert body.startswith("```powershell")
    assert "-ComputerName $Server" in body
    # The same generator, without a computer name, is what the API returns.
    inline = preflight_mod.windows_ttl_powershell("corp.example", 300, 3600)
    assert "-ComputerName" not in inline
    for marker in ("MinimumTimeToLive", "Set-DnsServerResourceRecord", "$NewTtl"):
        assert marker in body and marker in inline


async def test_ttl_preflight_does_not_collapse_a_multi_value_rrset(
    db_session: AsyncSession,
) -> None:
    """Three A records at one name must survive a TTL change.

    The BIND9 agent renders a record op as an RFC 2136 ``replace``, which swaps
    the whole RRset for that op's single value. Emitting one plain update per
    record would therefore leave the zone serving only the last one — a TTL
    change silently costing the operator two thirds of their addresses.
    """
    user = await _user(db_session)
    group, source, _managed, zone = await _dns_side(db_session)
    for addr in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        db_session.add(
            DNSRecord(zone_id=zone.id, name="pool", record_type="A", value=addr, ttl=3600)
        )
    db_session.add(DNSRecord(zone_id=zone.id, name="solo", record_type="A", value="10.0.0.9"))
    _plan, item = await _plan_with_item(
        db_session,
        kind="dns_zone",
        source_ref="corp.example",
        user=user,
        source_dns=source,
        dns_group_id=group.id,
        zone=zone,
    )
    await db_session.commit()

    captured: list[list[dict[str, Any]]] = []

    async def _capture(db: Any, z: Any, ops: list[dict[str, Any]]) -> list[Any]:
        captured.append(ops)
        return [None] * len(ops)

    import pytest as _pytest

    monkeypatch = _pytest.MonkeyPatch()
    monkeypatch.setattr(preflight_mod, "enqueue_record_ops_batch", _capture)
    try:
        await preflight_mod.apply_ttl_preflight(
            db_session, zone=zone, item=item, target_ttl=300, current_user=user
        )
    finally:
        monkeypatch.undo()

    ops = captured[0]
    pool_ops = [o for o in ops if o["record"]["name"] == "pool"]
    solo_ops = [o for o in ops if o["record"]["name"] == "solo"]

    assert len(pool_ops) == 3
    # First clears the RRset, the other two append onto it — so all three values
    # end up served at the new TTL.
    assert "rrset_action" not in pool_ops[0]["record"]
    assert [o["record"].get("rrset_action") for o in pool_ops[1:]] == ["add", "add"]
    assert {o["record"]["value"] for o in pool_ops} == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert all(o["record"]["ttl"] == 300 for o in pool_ops)

    # A single-value RRset is emitted exactly as before.
    assert len(solo_ops) == 1
    assert "rrset_action" not in solo_ops[0]["record"]


# =========================================================================== #
# 8. Regressions from the PR #775 review.
# =========================================================================== #


def test_shadow_does_not_case_fold_txt_rdata() -> None:
    """Folding case on a TXT record would report a match between two values a
    resolver treats as different — DKIM keys and verification tokens are
    case-bearing payloads, not names."""
    from app.services.cutover import shadow as shadow_mod

    lower = shadow_mod.normalise_answers(['"google-site-verification=abc123"'], "TXT")
    upper = shadow_mod.normalise_answers(['"google-site-verification=AbC123"'], "TXT")
    assert lower != upper, "TXT rdata must be compared verbatim"

    # Name-valued and address types still fold, so a rendering difference in
    # case or the root dot is not reported as drift.
    assert shadow_mod.normalise_answers(["Mail.Example.COM."], "CNAME") == (
        shadow_mod.normalise_answers(["mail.example.com"], "CNAME")
    )
    assert shadow_mod.normalise_answers(["2001:DB8::1"], "AAAA") == (
        shadow_mod.normalise_answers(["2001:db8::1"], "AAAA")
    )
    # Order is never meaningful.
    assert shadow_mod.normalise_answers(["10.0.0.2", "10.0.0.1"], "A") == ["10.0.0.1", "10.0.0.2"]


async def test_ttl_restore_sends_the_zone_default_for_inheriting_records(
    db_session: AsyncSession,
) -> None:
    """A record whose TTL is NULL inherits ``zone.ttl``. The BIND9 agent's
    record-op branch falls back to a hardcoded 3600 rather than the zone's own
    default, so shipping the null would write 3600 onto every inheriting record
    of a zone whose default is anything else. The row must stay NULL; the wire
    must carry the resolved value."""
    user = await _user(db_session)
    group, source, _managed, zone = await _dns_side(db_session)
    zone.ttl = 7200  # deliberately NOT the agent's 3600 fallback
    zone.minimum = 7200
    inherited = DNSRecord(zone_id=zone.id, name="app", record_type="A", value="10.0.0.1", ttl=None)
    db_session.add(inherited)
    _plan, item = await _plan_with_item(
        db_session,
        kind="dns_zone",
        source_ref="corp.example",
        user=user,
        source_dns=source,
        dns_group_id=group.id,
        zone=zone,
    )
    await db_session.commit()

    captured: list[list[dict[str, Any]]] = []

    async def _capture(db: Any, z: Any, ops: list[dict[str, Any]]) -> list[Any]:
        captured.append(ops)
        return [None] * len(ops)

    import pytest as _pytest

    monkeypatch = _pytest.MonkeyPatch()
    monkeypatch.setattr(preflight_mod, "enqueue_record_ops_batch", _capture)
    try:
        await preflight_mod.apply_ttl_preflight(
            db_session, zone=zone, item=item, target_ttl=300, current_user=user
        )
        await db_session.commit()
        assert inherited.ttl == 300

        await preflight_mod.restore_ttl_preflight(
            db_session, zone=zone, item=item, current_user=user
        )
        await db_session.commit()
    finally:
        monkeypatch.undo()

    # The row is back to NULL, so inheritance is preserved...
    assert inherited.ttl is None
    assert zone.ttl == 7200
    # ...and the wire carries the zone's own default, not the agent's 3600.
    restore_ops = captured[-1]
    assert [o["record"]["ttl"] for o in restore_ops] == [7200]


async def test_failed_commit_during_cutover_puts_the_windows_scope_back(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The commit is sequenced inside the switch, so a commit failure is
    compensated like any other.

    The Windows scope is already down by the time the transaction is sealed. If
    sealing fails, the database rolls back to "managed inactive" and the subnet
    would have no DHCP at all — so the same compensation that covers a failed
    flush has to cover a failed commit.
    """
    user = await _user(db_session)
    group, source, scope, _subnet = await _dhcp_side(db_session, is_active=False)
    plan, item = await _plan_with_item(
        db_session,
        kind="dhcp_scope",
        source_ref="10.20.0.0",
        user=user,
        source_dhcp=source,
        dhcp_group_id=group.id,
        scope=scope,
        parity_ok=True,
    )
    await db_session.commit()

    driver = _FakeDHCPDriver(scopes=[_windows_scope()])
    monkeypatch.setattr(switch_mod, "WindowsDHCPReadOnlyDriver", lambda: driver)
    monkeypatch.setattr(readiness_mod, "get_dhcp_driver", lambda _d: driver)

    async def _boom() -> None:
        raise RuntimeError("commit failed")

    with pytest.raises(RuntimeError, match="commit failed"):
        await switch_mod.execute_cutover(
            db_session,
            plan=plan,
            item=item,
            current_user=user,
            force=True,
            finalize=_boom,
        )
    await db_session.rollback()

    # Down, then back up — never left with no DHCP server on the subnet.
    assert driver.state_calls == [("10.20.0.0", False), ("10.20.0.0", True)]


async def test_rollback_commits_before_reactivating_windows(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The managed-side deactivation must be sealed *before* Windows comes back.

    Committing afterwards would mean a failed commit rolls the managed scope
    back to active while Windows is already active — both answering for one
    subnet, which is the single outcome the switch ordering exists to prevent.
    """
    user = await _user(db_session)
    group, source, scope, _subnet = await _dhcp_side(db_session, is_active=True)
    plan, item = await _plan_with_item(
        db_session,
        kind="dhcp_scope",
        source_ref="10.20.0.0",
        user=user,
        source_dhcp=source,
        dhcp_group_id=group.id,
        scope=scope,
        stage="cut_over",
        parity_ok=True,
    )
    await db_session.commit()

    driver = _FakeDHCPDriver(scopes=[_windows_scope(is_active=False)])
    monkeypatch.setattr(switch_mod, "WindowsDHCPReadOnlyDriver", lambda: driver)

    order: list[str] = []

    async def _finalize() -> None:
        order.append(f"commit(managed_active={scope.is_active})")
        await db_session.commit()

    original = driver.set_scope_state

    async def _tracked(server: Any, scope_id: str, *, active: bool) -> None:
        order.append(f"winrm(active={active})")
        await original(server, scope_id, active=active)

    monkeypatch.setattr(driver, "set_scope_state", _tracked)

    await switch_mod.execute_rollback(
        db_session, plan=plan, item=item, current_user=user, finalize=_finalize
    )

    assert order == ["commit(managed_active=False)", "winrm(active=True)"], order
    assert scope.is_active is False
    assert item.stage == "rolled_back"
    assert item.cut_over_at is None
