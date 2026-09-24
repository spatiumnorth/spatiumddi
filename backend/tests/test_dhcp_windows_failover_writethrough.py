"""#1110 — the Windows write-through on a group with more than one Windows member.

Before this, every scope / pool / reservation write went to EVERY Windows
member of the group, create-or-update. On a group whose two members are a
failover pair that happened to be harmless. On any other group it was the
outage: an edit to a scope one member held CREATED it on the other, and the
two then handed out the same addresses with nothing on either server
reporting a problem.

A fake driver stands in for WinRM and models each server's scopes and
failover relationships; the assertions are on which servers were written
and whether a write was allowed to create anything.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import (
    DHCPPool,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPStaticAssignment,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp import windows_writethrough as wt

CIDR = "10.30.0.0/24"
SID = "10.30.0.0"


def rel(name: str = "dhcp1-dhcp2", partner: str = "dhcp2", sids: tuple[str, ...] = (SID,)):
    return {
        "name": name,
        "partner_server": partner,
        "mode": "LoadBalance",
        "server_role": None,
        "state": "Normal",
        "load_balance_percent": 50,
        "reserve_percent": None,
        "max_client_lead_time_seconds": 3600,
        "state_switch_interval_seconds": None,
        "auto_state_transition": False,
        "enable_auth": False,
        "scope_ids": list(sids),
    }


class FakeWindows:
    """Per-server model: ``{name: {"scopes": {sid: {"active": bool}}, "rels": [...]}}``."""

    def __init__(self, state: dict[str, dict[str, Any]]) -> None:
        self.state = state
        self.calls: list[tuple[Any, ...]] = []

    def _scopes(self, server: Any) -> dict[str, dict[str, Any]]:
        return self.state[server.name].setdefault("scopes", {})

    async def probe_scopes(self, server: Any, scope_ids: list[str]) -> dict[str, Any]:
        self.calls.append(("probe", server.name))
        st = self.state[server.name]
        if st.get("probe_error"):
            raise RuntimeError(st["probe_error"])
        out = {}
        for sid in scope_ids:
            sc = self._scopes(server).get(sid)
            out[sid] = {
                "present": sc is not None,
                "is_active": sc["active"] if sc else None,
                "start_ip": sc.get("start", "10.30.0.10") if sc else None,
                "end_ip": sc.get("end", "10.30.0.200") if sc else None,
                "exclusions": sc.get("exclusions", []) if sc else [],
            }
        return {
            "scopes": out,
            "failover": {
                "ok": st.get("failover_ok", True),
                "error": st.get("failover_error"),
                "relationships": st.get("rels", []),
            },
        }

    async def apply_scope(
        self, server: Any, *, scope_id: str, create_if_missing: bool = True, **kw
    ):
        self.calls.append(("apply_scope", server.name, create_if_missing, kw.get("is_active")))
        if self.state[server.name].get("vanish"):
            self._scopes(server).pop(scope_id, None)
        present = scope_id in self._scopes(server)
        if not present and not create_if_missing:
            return False
        self._scopes(server)[scope_id] = {"active": kw.get("is_active", True)}
        return True

    async def remove_scope(self, server: Any, scope_id: str) -> bool:
        self.calls.append(("remove_scope", server.name))
        return self._scopes(server).pop(scope_id, None) is not None

    async def apply_reservation(self, server: Any, *, scope_id: str, **kw) -> bool:
        held = scope_id in self._scopes(server)
        self.calls.append(("apply_reservation", server.name, held))
        return held

    async def remove_reservation(self, server: Any, *, scope_id: str, mac_address: str) -> None:
        self.calls.append(("remove_reservation", server.name))

    async def apply_exclusion(self, server: Any, *, scope_id: str, **kw) -> bool:
        held = scope_id in self._scopes(server)
        self.calls.append(("apply_exclusion", server.name, held))
        return held

    async def remove_exclusion(self, server: Any, *, scope_id: str, **kw) -> None:
        self.calls.append(("remove_exclusion", server.name))

    async def add_failover_scopes(self, server: Any, *, name: str, scope_ids: list[str]):
        self.calls.append(("add_failover_scopes", server.name, name, tuple(scope_ids)))
        if self.state[server.name].get("join_error"):
            raise RuntimeError(self.state[server.name]["join_error"])
        return {"ok": True, "error": None, "relationships": []}

    async def remove_failover_scopes(self, server: Any, *, name: str, scope_ids: list[str]):
        self.calls.append(("remove_failover_scopes", server.name, name, tuple(scope_ids)))
        return {"ok": True, "error": None, "relationships": []}

    def written(self, op: str) -> list[str]:
        return [c[1] for c in self.calls if c[0] == op]


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch):
    def install(state: dict[str, dict[str, Any]]) -> FakeWindows:
        drv = FakeWindows(state)
        monkeypatch.setattr(wt, "get_driver", lambda _name: drv)
        return drv

    return install


async def _group(
    db: AsyncSession,
    names: tuple[str, ...] = ("dhcp1", "dhcp2"),
    *,
    active: bool = True,
    transport: str | None = None,
) -> tuple[DHCPServerGroup, Subnet, DHCPScope]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.30.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="office")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([subnet, group])
    await db.flush()
    for n in names:
        db.add(
            DHCPServer(
                name=n,
                driver="windows_dhcp",
                host=f"{n}.corp.example",
                port=67,
                server_group_id=group.id,
                credentials_encrypted=(
                    encrypt_dict({"username": "u", "password": "p", "transport": transport})
                    if transport
                    else None
                ),
            )
        )
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, is_active=active, name="office")
    db.add(scope)
    await db.flush()
    return group, subnet, scope


# ── scope create / update / activate ──────────────────────────────────


@pytest.mark.asyncio
async def test_single_member_is_unchanged_create_or_update_no_probe(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session, ("dhcp1",))
    drv = fake({"dhcp1": {}})
    await wt.push_scope_upsert(db_session, scope)
    assert ("apply_scope", "dhcp1", True, True) in drv.calls
    assert drv.written("probe") == []


@pytest.mark.asyncio
async def test_create_across_two_members_with_no_holder_is_refused(db_session, fake) -> None:
    """The outage, at the moment it would be created: a new scope on a group
    of two Windows servers used to land on both, uncoordinated."""
    _g, _s, scope = await _group(db_session)
    drv = fake({"dhcp1": {}, "dhcp2": {}})
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_scope_upsert(db_session, scope)
    assert exc.value.status_code == 422
    assert "dhcp1 and dhcp2" in exc.value.detail
    assert "windows_placement" in exc.value.detail
    assert "only dhcp1; only dhcp2" in exc.value.detail
    assert drv.written("apply_scope") == [], "nothing may be written before the refusal"


@pytest.mark.asyncio
async def test_create_refusal_names_a_relationship_the_members_already_share(
    db_session, fake
) -> None:
    _g, _s, scope = await _group(db_session)
    shared = rel(name="hq-failover", sids=("10.99.0.0",))
    fake({"dhcp1": {"rels": [shared]}, "dhcp2": {"rels": [shared]}})
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_scope_upsert(db_session, scope)
    # The servers carry no CredSSP credentials, so SpatiumDDI cannot use the
    # relationship itself — but it is offered as a placement.
    assert "failover relationship 'hq-failover'" in exc.value.detail


@pytest.mark.asyncio
async def test_update_goes_only_to_the_member_holding_the_scope(db_session, fake) -> None:
    """The silent path to the outage: editing a scope dhcp1 held used to
    create it on dhcp2 as well."""
    _g, _s, scope = await _group(db_session)
    drv = fake({"dhcp1": {"scopes": {SID: {"active": True}}}, "dhcp2": {}})
    await wt.push_scope_upsert(db_session, scope)
    assert drv.written("apply_scope") == ["dhcp1"]
    assert ("apply_scope", "dhcp1", False, True) in drv.calls, "update-only, never create"
    assert SID not in drv.state["dhcp2"].get("scopes", {})


@pytest.mark.asyncio
async def test_a_failover_pair_gets_the_write_on_both_partners(db_session, fake) -> None:
    """Windows failover syncs leases, not configuration — a change written to
    one partner alone would leave the other serving stale settings after a
    failover."""
    _g, _s, scope = await _group(db_session)
    drv = fake(
        {
            "dhcp1": {"scopes": {SID: {"active": True}}, "rels": [rel(partner="dhcp2")]},
            "dhcp2": {"scopes": {SID: {"active": True}}, "rels": [rel(partner="dhcp1")]},
        }
    )
    await wt.push_scope_upsert(db_session, scope)
    assert sorted(drv.written("apply_scope")) == ["dhcp1", "dhcp2"]
    assert all(c[2] is False for c in drv.calls if c[0] == "apply_scope")


@pytest.mark.asyncio
async def test_a_failover_pair_never_spreads_to_a_third_member(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session, ("dhcp1", "dhcp2", "dhcp3"))
    drv = fake(
        {
            "dhcp1": {"scopes": {SID: {"active": True}}, "rels": [rel(partner="dhcp2")]},
            "dhcp2": {"scopes": {SID: {"active": True}}, "rels": [rel(partner="dhcp1")]},
            "dhcp3": {},
        }
    )
    await wt.push_scope_upsert(db_session, scope)
    assert sorted(drv.written("apply_scope")) == ["dhcp1", "dhcp2"]


@pytest.mark.asyncio
async def test_activating_an_uncoordinated_shared_scope_is_refused(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session, active=True)
    drv = fake(
        {
            "dhcp1": {"scopes": {SID: {"active": True}}},
            "dhcp2": {"scopes": {SID: {"active": False}}},
        }
    )
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_scope_upsert(db_session, scope)
    assert exc.value.status_code == 422
    assert "Refusing to activate" in exc.value.detail
    assert "dhcp2" in exc.value.detail
    assert drv.written("apply_scope") == []


@pytest.mark.asyncio
async def test_activation_refused_when_coordination_cannot_be_read(db_session, fake) -> None:
    """A denied failover read is unknown, not "not covered" — and unknown
    does not get to activate a scope on a second server."""
    _g, _s, scope = await _group(db_session, active=True)
    fake(
        {
            "dhcp1": {
                "scopes": {SID: {"active": True}},
                "failover_ok": False,
                "failover_error": "Access is denied.",
            },
            "dhcp2": {"scopes": {SID: {"active": False}}, "rels": [rel(partner="dhcp1")]},
        }
    )
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_scope_upsert(db_session, scope)
    assert "Access is denied." in exc.value.detail


@pytest.mark.asyncio
async def test_editing_an_already_uncoordinated_active_scope_is_allowed(db_session, fake) -> None:
    """The risk predates the edit and the edit does not widen it; refusing
    would only stop the operator touching the scope at all."""
    _g, _s, scope = await _group(db_session, active=True)
    drv = fake(
        {
            "dhcp1": {"scopes": {SID: {"active": True}}},
            "dhcp2": {"scopes": {SID: {"active": True}}},
        }
    )
    await wt.push_scope_upsert(db_session, scope)
    assert sorted(drv.written("apply_scope")) == ["dhcp1", "dhcp2"]


@pytest.mark.asyncio
async def test_deactivating_an_uncoordinated_shared_scope_is_the_fix_and_allowed(
    db_session, fake
) -> None:
    _g, _s, scope = await _group(db_session, active=False)
    drv = fake(
        {
            "dhcp1": {"scopes": {SID: {"active": True}}},
            "dhcp2": {"scopes": {SID: {"active": False}}},
        }
    )
    await wt.push_scope_upsert(db_session, scope)
    assert sorted(drv.written("apply_scope")) == ["dhcp1", "dhcp2"]
    assert all(c[3] is False for c in drv.calls if c[0] == "apply_scope")


@pytest.mark.asyncio
async def test_a_member_that_cannot_be_probed_fails_the_write(db_session, fake) -> None:
    """A member whose answer is unknown might be one of the holders."""
    _g, _s, scope = await _group(db_session)
    drv = fake(
        {"dhcp1": {"scopes": {SID: {"active": True}}}, "dhcp2": {"probe_error": "WinRM refused"}}
    )
    with pytest.raises(wt.WindowsPushError) as exc:
        await wt.push_scope_upsert(db_session, scope)
    assert exc.value.status_code == 502
    assert "dhcp2: WinRM refused" in exc.value.detail
    assert drv.written("apply_scope") == []


@pytest.mark.asyncio
async def test_a_scope_that_vanishes_mid_write_is_not_recreated(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session)
    drv = fake({"dhcp1": {"scopes": {SID: {"active": True}}, "vanish": True}, "dhcp2": {}})
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_scope_upsert(db_session, scope)
    assert exc.value.status_code == 409
    assert SID not in drv.state["dhcp1"]["scopes"]


# ── scope delete ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_deleting_a_failover_scope_is_refused_with_the_windows_step(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session)
    drv = fake(
        {
            "dhcp1": {"scopes": {SID: {"active": True}}, "rels": [rel(partner="dhcp2")]},
            "dhcp2": {"scopes": {SID: {"active": True}}, "rels": [rel(partner="dhcp1")]},
        }
    )
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_scope_delete(db_session, scope)
    assert exc.value.status_code == 409
    assert "Remove-DhcpServerv4FailoverScope -ComputerName dhcp1" in exc.value.detail
    assert drv.written("remove_scope") == []


@pytest.mark.asyncio
async def test_deleting_a_single_member_failover_scope_is_refused_too(db_session, fake) -> None:
    """One registered member, partner elsewhere: Windows would refuse the
    delete anyway, so say why instead of relaying its error."""
    _g, _s, scope = await _group(db_session, ("dhcp1",))
    fake({"dhcp1": {"scopes": {SID: {"active": True}}, "rels": [rel(partner="dhcp9")]}})
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_scope_delete(db_session, scope)
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_delete_removes_only_from_holders(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session)
    drv = fake({"dhcp1": {"scopes": {SID: {"active": True}}}, "dhcp2": {}})
    await wt.push_scope_delete(db_session, scope)
    assert drv.written("remove_scope") == ["dhcp1"]


@pytest.mark.asyncio
async def test_delete_of_a_scope_no_member_holds_is_a_noop(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session)
    drv = fake({"dhcp1": {}, "dhcp2": {}})
    await wt.push_scope_delete(db_session, scope)
    assert drv.written("remove_scope") == []


# ── pools and reservations (guarded in the driver, no probe) ──────────


@pytest.mark.asyncio
async def test_reservation_lands_on_holders_only(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session)
    drv = fake({"dhcp1": {"scopes": {SID: {"active": True}}}, "dhcp2": {}})
    st = DHCPStaticAssignment(
        scope_id=scope.id, ip_address="10.30.0.5", mac_address="aa:bb:cc:00:00:01"
    )
    db_session.add(st)
    await db_session.flush()
    await wt.push_static_change(db_session, st, action="create")
    applied = [c for c in drv.calls if c[0] == "apply_reservation"]
    assert applied == [("apply_reservation", "dhcp1", True), ("apply_reservation", "dhcp2", False)]
    assert drv.written("probe") == [], "the guard lives in the write, not in a probe"


@pytest.mark.asyncio
async def test_reservation_for_a_scope_no_member_holds_is_refused(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session)
    fake({"dhcp1": {}, "dhcp2": {}})
    st = DHCPStaticAssignment(
        scope_id=scope.id, ip_address="10.30.0.5", mac_address="aa:bb:cc:00:00:01"
    )
    db_session.add(st)
    await db_session.flush()
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_static_change(db_session, st, action="create")
    assert exc.value.status_code == 409
    assert "nothing to add the reservation to" in exc.value.detail


@pytest.mark.asyncio
async def test_exclusion_lands_on_holders_only(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session)
    drv = fake({"dhcp1": {}, "dhcp2": {"scopes": {SID: {"active": True}}}})
    pool = DHCPPool(
        scope_id=scope.id, start_ip="10.30.0.50", end_ip="10.30.0.60", pool_type="excluded"
    )
    db_session.add(pool)
    await db_session.flush()
    await wt.push_pool_change(db_session, pool, action="create")
    assert [c for c in drv.calls if c[0] == "apply_exclusion"] == [
        ("apply_exclusion", "dhcp1", False),
        ("apply_exclusion", "dhcp2", True),
    ]


@pytest.mark.asyncio
async def test_removals_stay_tolerant_everywhere(db_session, fake) -> None:
    """Removing what a member never had leaves it as it should be."""
    _g, _s, scope = await _group(db_session)
    drv = fake({"dhcp1": {}, "dhcp2": {}})
    st = DHCPStaticAssignment(
        scope_id=scope.id, ip_address="10.30.0.5", mac_address="aa:bb:cc:00:00:01"
    )
    db_session.add(st)
    await db_session.flush()
    await wt.push_static_change(db_session, st, action="delete")
    assert drv.written("remove_reservation") == ["dhcp1", "dhcp2"]


# ── placement of a new scope (#1110 Phase 2) ──────────────────────────


@pytest.mark.asyncio
async def test_placement_on_one_server_creates_it_there_only(db_session, fake) -> None:
    """Safe — one server serves it — and the seed for a relationship that
    does not exist yet (Windows cannot create one without a scope)."""
    _g, _s, scope = await _group(db_session)
    servers = (await db_session.execute(select(DHCPServer).order_by(DHCPServer.name))).scalars()
    dhcp2 = [s for s in servers if s.name == "dhcp2"][0]
    drv = fake({"dhcp1": {}, "dhcp2": {}})
    await wt.push_scope_upsert(db_session, scope, placement=wt.WindowsPlacement(server_id=dhcp2.id))
    assert [c for c in drv.calls if c[0] == "apply_scope"] == [("apply_scope", "dhcp2", True, True)]
    assert SID not in drv.state["dhcp1"].get("scopes", {})


@pytest.mark.asyncio
async def test_placement_into_a_relationship_creates_on_one_side_and_joins(
    db_session, fake
) -> None:
    _g, _s, scope = await _group(db_session, transport="credssp")
    drv = fake(
        {
            "dhcp1": {"rels": [rel(partner="dhcp2", sids=("10.99.0.0",))]},
            "dhcp2": {"rels": [rel(partner="dhcp1", sids=("10.99.0.0",))]},
        }
    )
    await wt.push_scope_upsert(
        db_session, scope, placement=wt.WindowsPlacement(failover_relationship="dhcp1-dhcp2")
    )
    assert drv.written("apply_scope") == ["dhcp1"], "created on ONE side only"
    assert ("add_failover_scopes", "dhcp1", "dhcp1-dhcp2", (SID,)) in drv.calls


@pytest.mark.asyncio
async def test_hot_standby_creates_on_the_active_side(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session, transport="credssp")
    active = {**rel(partner="dhcp1", sids=()), "mode": "HotStandby", "server_role": "Active"}
    standby = {**rel(partner="dhcp2", sids=()), "mode": "HotStandby", "server_role": "Standby"}
    drv = fake({"dhcp1": {"rels": [standby]}, "dhcp2": {"rels": [active]}})
    await wt.push_scope_upsert(db_session, scope)
    assert drv.written("apply_scope") == ["dhcp2"]
    assert ("add_failover_scopes", "dhcp2", "dhcp1-dhcp2", (SID,)) in drv.calls


@pytest.mark.asyncio
async def test_the_one_shared_relationship_is_used_without_being_named(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session, transport="credssp")
    drv = fake(
        {
            "dhcp1": {"rels": [rel(partner="dhcp2", sids=())]},
            "dhcp2": {"rels": [rel(partner="dhcp1", sids=())]},
        }
    )
    await wt.push_scope_upsert(db_session, scope)
    assert drv.written("apply_scope") == ["dhcp1"]
    assert drv.written("add_failover_scopes") == ["dhcp1"]


@pytest.mark.asyncio
async def test_placement_into_a_relationship_needs_credssp(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session, transport="ntlm")
    drv = fake(
        {
            "dhcp1": {"rels": [rel(partner="dhcp2", sids=())]},
            "dhcp2": {"rels": [rel(partner="dhcp1", sids=())]},
        }
    )
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_scope_upsert(
            db_session, scope, placement=wt.WindowsPlacement(failover_relationship="dhcp1-dhcp2")
        )
    assert "second hop" in exc.value.detail
    assert drv.written("apply_scope") == []


@pytest.mark.asyncio
async def test_an_unknown_relationship_placement_is_refused(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session, transport="credssp")
    fake({"dhcp1": {}, "dhcp2": {}})
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_scope_upsert(
            db_session, scope, placement=wt.WindowsPlacement(failover_relationship="nope")
        )
    assert "no failover relationship named 'nope'" in exc.value.detail


@pytest.mark.asyncio
async def test_a_failed_join_removes_the_half_created_scope(db_session, fake) -> None:
    """Otherwise Windows keeps a scope the rolled-back row no longer describes."""
    _g, _s, scope = await _group(db_session, transport="credssp")
    drv = fake(
        {
            "dhcp1": {"rels": [rel(partner="dhcp2", sids=())], "join_error": "partner denied"},
            "dhcp2": {"rels": [rel(partner="dhcp1", sids=())]},
        }
    )
    with pytest.raises(wt.WindowsPushError) as exc:
        await wt.push_scope_upsert(db_session, scope)
    assert "partner denied" in exc.value.detail
    assert "removed it again" in exc.value.detail
    assert drv.written("remove_scope") == ["dhcp1"]
    assert SID not in drv.state["dhcp1"]["scopes"]


# ── deleting a failover scope through the relationship ────────────────


@pytest.mark.asyncio
async def test_a_failover_pair_scope_is_deleted_through_the_relationship(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session, transport="credssp")
    drv = fake(
        {
            "dhcp1": {"scopes": {SID: {"active": True}}, "rels": [rel(partner="dhcp2")]},
            "dhcp2": {"scopes": {SID: {"active": True}}, "rels": [rel(partner="dhcp1")]},
        }
    )
    await wt.push_scope_delete(db_session, scope)
    ops = [c[:2] for c in drv.calls if c[0] in ("remove_failover_scopes", "remove_scope")]
    assert ops == [
        ("remove_failover_scopes", "dhcp1"),
        ("remove_scope", "dhcp1"),
    ], "out of the relationship first (Windows deletes the partner's copy), then deleted"


# ── split scopes (#1110) ──────────────────────────────────────────────


def _split_state() -> dict[str, dict[str, Any]]:
    """The Windows split-scope wizard's shape: one range, disjoint exclusions."""
    return {
        "dhcp1": {
            "scopes": {
                SID: {
                    "active": True,
                    "start": "10.30.0.10",
                    "end": "10.30.0.200",
                    "exclusions": [("10.30.0.101", "10.30.0.200")],
                }
            }
        },
        "dhcp2": {
            "scopes": {
                SID: {
                    "active": True,
                    "start": "10.30.0.10",
                    "end": "10.30.0.200",
                    "exclusions": [("10.30.0.10", "10.30.0.100")],
                }
            }
        },
    }


@pytest.mark.asyncio
async def test_a_split_scope_edit_that_keeps_the_halves_apart_is_allowed(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session)
    db_session.add(DHCPPool(scope_id=scope.id, start_ip="10.30.0.10", end_ip="10.30.0.200"))
    await db_session.flush()
    drv = fake(_split_state())
    await wt.push_scope_upsert(db_session, scope)
    assert sorted(drv.written("apply_scope")) == ["dhcp1", "dhcp2"]


@pytest.mark.asyncio
async def test_a_range_that_would_overlap_split_halves_is_refused(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session)
    db_session.add(DHCPPool(scope_id=scope.id, start_ip="10.30.0.5", end_ip="10.30.0.250"))
    await db_session.flush()
    drv = fake(_split_state())
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_scope_upsert(db_session, scope)
    assert "split scope" in exc.value.detail
    assert drv.written("apply_scope") == []


@pytest.mark.asyncio
async def test_removing_a_split_scopes_exclusion_is_refused(db_session, fake) -> None:
    """Pushed to both holders, it would widen dhcp1 into dhcp2's half."""
    _g, _s, scope = await _group(db_session)
    pool = DHCPPool(
        scope_id=scope.id, start_ip="10.30.0.101", end_ip="10.30.0.200", pool_type="excluded"
    )
    db_session.add(pool)
    await db_session.flush()
    drv = fake(_split_state())
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await wt.push_pool_change(db_session, pool, action="delete")
    assert "remove the exclusion" in exc.value.detail
    assert drv.written("remove_exclusion") == []


@pytest.mark.asyncio
async def test_adding_an_exclusion_to_a_split_scope_needs_no_probe(db_session, fake) -> None:
    _g, _s, scope = await _group(db_session)
    pool = DHCPPool(
        scope_id=scope.id, start_ip="10.30.0.50", end_ip="10.30.0.60", pool_type="excluded"
    )
    db_session.add(pool)
    await db_session.flush()
    drv = fake(_split_state())
    await wt.push_pool_change(db_session, pool, action="create")
    assert drv.written("probe") == []


# ── end to end: the refusal happens before commit ─────────────────────


async def _token(db: AsyncSession) -> str:
    user = User(
        username=f"fo-{uuid.uuid4().hex[:6]}",
        email=f"fo-{uuid.uuid4().hex[:6]}@example.test",
        display_name="fo",
        hashed_password=hash_password("x"),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


@pytest.mark.asyncio
async def test_api_create_is_refused_and_nothing_is_committed(
    client: AsyncClient, db_session: AsyncSession, fake
) -> None:
    group, subnet, scope = await _group(db_session)
    # The fixture's scope stands in for an existing one; this test creates a
    # second subnet's scope through the API.
    other = Subnet(
        space_id=subnet.space_id, block_id=subnet.block_id, network="10.30.1.0/24", name="lab"
    )
    db_session.add(other)
    token = await _token(db_session)
    await db_session.commit()
    other_id, group_id = other.id, group.id
    drv = fake({"dhcp1": {}, "dhcp2": {}})

    resp = await client.post(
        f"/api/v1/dhcp/subnets/{other_id}/dhcp-scopes",
        json={"group_id": str(group_id), "name": "lab"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422, resp.text
    assert "Choose where it goes" in resp.json()["detail"]
    assert drv.written("apply_scope") == []
    # The test client shares this session and never closes it, so do what
    # the real ``get_db`` does at the end of a failed request. A row the
    # handler had committed would survive this; a flushed one does not.
    await db_session.rollback()
    rows = (
        (await db_session.execute(select(DHCPScope).where(DHCPScope.subnet_id == other_id)))
        .scalars()
        .all()
    )
    assert rows == [], "the refused scope must not have been committed"


@pytest.mark.asyncio
async def test_api_edit_puts_a_scope_held_nowhere_back_where_it_is_told(
    client: AsyncClient, db_session: AsyncSession, fake
) -> None:
    """A scope restored from Trash — or deleted on Windows — has no holder, and
    without a placement an edit could never put it anywhere again."""
    group, _subnet, scope = await _group(db_session)
    dhcp2 = (
        await db_session.execute(select(DHCPServer).where(DHCPServer.name == "dhcp2"))
    ).scalar_one()
    token = await _token(db_session)
    await db_session.commit()
    scope_id, dhcp2_id = scope.id, dhcp2.id
    drv = fake({"dhcp1": {}, "dhcp2": {}})

    refused = await client.put(
        f"/api/v1/dhcp/scopes/{scope_id}",
        json={"name": "office"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert refused.status_code == 422, refused.text
    await db_session.rollback()

    resp = await client.put(
        f"/api/v1/dhcp/scopes/{scope_id}",
        json={"name": "office", "windows_placement": {"server_id": str(dhcp2_id)}},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    assert [c for c in drv.calls if c[0] == "apply_scope"] == [("apply_scope", "dhcp2", True, True)]
