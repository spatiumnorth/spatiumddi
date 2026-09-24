"""#1110 Phase 2 — managing Windows DHCP failover relationships from SpatiumDDI.

Every ``*-DhcpServerv4Failover*`` cmdlet runs on ONE server and acts on both
partners from there, so the assertions here are mostly about WHERE a cmdlet
runs — the side that holds the scopes for an add, the side that keeps them for
a removal, the named source for a replication — and about what is refused
before anything is sent: a transport that cannot make the second hop, a scope
the partner already has, a relationship name already in use.

A fake driver stands in for WinRM; the routes are exercised end to end so the
audit row (which must never carry the shared secret) is checked too.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import (
    DHCPFailoverRelationship,
    DHCPScope,
    DHCPServer,
    DHCPServerGroup,
    DHCPServerScopeState,
)
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.dhcp import windows_failover_manage as fo_manage
from app.services.dhcp import windows_writethrough as wt

CIDR = "10.70.0.0/24"
SID = "10.70.0.0"
SECRET = "correct-horse-battery-staple"


def _rel(name: str, partner: str, *, sids: tuple[str, ...] = (SID,), **kw: Any) -> dict[str, Any]:
    out = {
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
        "enable_auth": True,
        "scope_ids": list(sids),
    }
    out.update(kw)
    return out


class FakeWindows:
    """Two servers, their scopes and relationships, mutated by the cmdlets
    the way Windows would: a create copies the scopes to the partner, a
    removal deletes the partner's copy."""

    def __init__(self, state: dict[str, dict[str, Any]]) -> None:
        self.state = state
        self.calls: list[tuple[Any, ...]] = []

    def _st(self, server: Any) -> dict[str, Any]:
        return self.state.setdefault(server.name, {})

    def _other(self, server: Any) -> str:
        return next(n for n in self.state if n != server.name)

    def _fo(self, name: str) -> dict[str, Any]:
        return {"ok": True, "error": None, "relationships": self.state[name].get("rels", [])}

    async def probe_scopes(self, server: Any, scope_ids: list[str]) -> dict[str, Any]:
        st = self._st(server)
        return {
            "scopes": {
                sid: {
                    "present": sid in st.get("scopes", set()),
                    "is_active": True,
                    "start_ip": "10.70.0.10",
                    "end_ip": "10.70.0.200",
                    "exclusions": [],
                }
                for sid in scope_ids
            },
            "failover": self._fo(server.name),
        }

    async def get_scopes(self, server: Any) -> list[dict[str, Any]]:
        return [
            {
                "subnet_cidr": f"{sid}/24",
                "is_active": True,
                "lease_time": 86400,
                "options": {},
                "pools": [
                    {"start_ip": "10.70.0.10", "end_ip": "10.70.0.200", "pool_type": "dynamic"}
                ],
                "statics": [],
            }
            for sid in sorted(self._st(server).get("scopes", set()))
        ]

    async def get_failover_relationships(self, server: Any) -> dict[str, Any]:
        return self._fo(server.name)

    async def create_failover_relationship(self, server: Any, **kw: Any) -> dict[str, Any]:
        self.calls.append(("create", server.name, kw))
        partner = self._other(server)
        sids = tuple(kw["scope_ids"])
        self.state[server.name].setdefault("rels", []).append(
            _rel(kw["name"], kw["partner_server"], sids=sids)
        )
        self.state[partner].setdefault("rels", []).append(_rel(kw["name"], server.name, sids=sids))
        self.state[partner].setdefault("scopes", set()).update(sids)
        return self._fo(server.name)

    async def update_failover_relationship(self, server: Any, **kw: Any) -> dict[str, Any]:
        self.calls.append(("update", server.name, kw))
        return self._fo(server.name)

    async def delete_failover_relationship(self, server: Any, *, name: str) -> dict[str, Any]:
        self.calls.append(("delete", server.name, name))
        partner = self._other(server)
        for n in (server.name, partner):
            self.state[n]["rels"] = [r for r in self.state[n].get("rels", []) if r["name"] != name]
        self.state[partner]["scopes"] = set()
        return self._fo(server.name)

    async def add_failover_scopes(self, server: Any, *, name: str, scope_ids: list[str]):
        self.calls.append(("add_scopes", server.name, name, tuple(scope_ids)))
        self.state[self._other(server)].setdefault("scopes", set()).update(scope_ids)
        return self._fo(server.name)

    async def remove_failover_scopes(self, server: Any, *, name: str, scope_ids: list[str]):
        self.calls.append(("remove_scopes", server.name, name, tuple(scope_ids)))
        self.state[self._other(server)]["scopes"] -= set(scope_ids)
        return self._fo(server.name)

    async def replicate_failover(self, server: Any, *, name: str, scope_ids: list[str]):
        self.calls.append(("replicate", server.name, name, tuple(scope_ids)))
        return self._fo(server.name)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch):
    def install(state: dict[str, dict[str, Any]]) -> FakeWindows:
        drv = FakeWindows(state)
        monkeypatch.setattr(fo_manage, "get_driver", lambda _name: drv)
        monkeypatch.setattr(wt, "get_driver", lambda _name: drv)
        return drv

    return install


async def _world(db: AsyncSession, *, transport: str = "credssp") -> dict[str, Any]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.70.0.0/16", name="blk")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network=CIDR, name="office")
    group = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}", description="")
    db.add_all([subnet, group])
    await db.flush()
    creds = encrypt_dict({"username": "u", "password": "p", "transport": transport})
    servers = {}
    for n in ("dhcp1", "dhcp2"):
        servers[n] = DHCPServer(
            name=n,
            driver="windows_dhcp",
            host=f"{n}.corp.example",
            port=67,
            server_group_id=group.id,
            credentials_encrypted=creds,
        )
        db.add(servers[n])
    scope = DHCPScope(group_id=group.id, subnet_id=subnet.id, is_active=True)
    db.add(scope)
    await db.flush()
    return {"group": group, **servers, "scope": scope}


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


async def _observe(db: AsyncSession, server: DHCPServer, rels: list[dict[str, Any]]) -> None:
    """Seed what the topology poll would have recorded."""
    now = datetime.now(UTC)
    server.failover_observed_at = now
    server.scopes_observed_at = now
    for r in rels:
        fields = {k: v for k, v in r.items() if k != "name"}
        db.add(DHCPFailoverRelationship(server_id=server.id, name=r["name"], **fields))
    db.add(
        DHCPServerScopeState(
            server_id=server.id,
            scope_cidr=CIDR,
            is_active=True,
            start_ip="10.70.0.10",
            end_ip="10.70.0.200",
            exclusions=[],
            config_hash="h",
        )
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── create ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_runs_on_the_holder_names_the_partner_and_keeps_the_secret_out(
    client: AsyncClient, db_session: AsyncSession, fake
) -> None:
    w = await _world(db_session)
    token = await _token(db_session)
    await db_session.commit()
    gid, s1, s2 = w["group"].id, w["dhcp1"].id, w["dhcp2"].id
    drv = fake({"dhcp1": {"scopes": {SID}}, "dhcp2": {}})

    resp = await client.post(
        f"/api/v1/dhcp/server-groups/{gid}/failover/relationships",
        json={
            "name": "dhcp1-dhcp2",
            "server_id": str(s1),
            "partner_server_id": str(s2),
            "mode": "LoadBalance",
            "load_balance_percent": 50,
            "max_client_lead_time_seconds": 3600,
            "shared_secret": SECRET,
            "scope_ids": [SID],
        },
        headers=_auth(token),
    )
    assert resp.status_code == 201, resp.text
    (call,) = [c for c in drv.calls if c[0] == "create"]
    assert call[1] == "dhcp1"
    assert call[2]["partner_server"] == "dhcp2.corp.example"
    assert call[2]["shared_secret"] == SECRET, "the secret reaches Windows"

    body = resp.json()
    assert body["ran_on_server_name"] == "dhcp1"
    assert body["partner_server_name"] == "dhcp2"
    (rel,) = body["failover"]["relationships"]
    assert rel["complete"] is True, "both sides were re-read after the create"
    (scope,) = body["failover"]["scopes"]
    assert scope["verdict"] == "failover"
    assert SECRET not in resp.text

    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "failover_create")))
        .scalars()
        .one()
    )
    assert audit.new_value["shared_secret_set"] is True
    assert SECRET not in str(audit.new_value), "the secret must never reach the audit log"


@pytest.mark.asyncio
async def test_create_is_refused_when_the_partner_already_holds_the_scope(
    db_session: AsyncSession, fake
) -> None:
    """Windows copies the scope to the partner and refuses when a copy is
    there — the uncoordinated case, which has to be undone on one side first."""
    w = await _world(db_session)
    drv = fake({"dhcp1": {"scopes": {SID}}, "dhcp2": {"scopes": {SID}}})
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await fo_manage.create_relationship(
            db_session,
            w["group"],
            name="r",
            server_id=w["dhcp1"].id,
            partner_server_id=w["dhcp2"].id,
            scope_ids=[SID],
            mode="LoadBalance",
            load_balance_percent=None,
            server_role=None,
            reserve_percent=None,
            max_client_lead_time_seconds=None,
            auto_state_transition=None,
            state_switch_interval_seconds=None,
            shared_secret=None,
        )
    assert "dhcp2 already holds scope 10.70.0.0" in exc.value.detail
    assert drv.calls == []


@pytest.mark.asyncio
async def test_create_needs_the_scope_on_the_server_it_runs_on(
    db_session: AsyncSession, fake
) -> None:
    w = await _world(db_session)
    fake({"dhcp1": {}, "dhcp2": {}})
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await fo_manage.create_relationship(
            db_session,
            w["group"],
            name="r",
            server_id=w["dhcp1"].id,
            partner_server_id=w["dhcp2"].id,
            scope_ids=[SID],
            mode="LoadBalance",
            load_balance_percent=None,
            server_role=None,
            reserve_percent=None,
            max_client_lead_time_seconds=None,
            auto_state_transition=None,
            state_switch_interval_seconds=None,
            shared_secret=None,
        )
    assert "dhcp1 does not hold scope" in exc.value.detail


@pytest.mark.asyncio
async def test_create_over_ntlm_is_refused_before_anything_is_sent(
    db_session: AsyncSession, fake
) -> None:
    """NTLM cannot make the second hop to the partner, so the cmdlet would
    fail half way — refused from the credentials alone."""
    w = await _world(db_session, transport="ntlm")
    drv = fake({"dhcp1": {"scopes": {SID}}, "dhcp2": {}})
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await fo_manage.create_relationship(
            db_session,
            w["group"],
            name="r",
            server_id=w["dhcp1"].id,
            partner_server_id=w["dhcp2"].id,
            scope_ids=[SID],
            mode="LoadBalance",
            load_balance_percent=None,
            server_role=None,
            reserve_percent=None,
            max_client_lead_time_seconds=None,
            auto_state_transition=None,
            state_switch_interval_seconds=None,
            shared_secret=None,
        )
    assert "CredSSP" in exc.value.detail
    assert drv.calls == []


@pytest.mark.asyncio
async def test_hot_standby_needs_a_role(
    client: AsyncClient, db_session: AsyncSession, fake
) -> None:
    w = await _world(db_session)
    token = await _token(db_session)
    await db_session.commit()
    fake({"dhcp1": {"scopes": {SID}}, "dhcp2": {}})
    resp = await client.post(
        f"/api/v1/dhcp/server-groups/{w['group'].id}/failover/relationships",
        json={
            "name": "r",
            "server_id": str(w["dhcp1"].id),
            "partner_server_id": str(w["dhcp2"].id),
            "mode": "HotStandby",
            "scope_ids": [SID],
        },
        headers=_auth(token),
    )
    assert resp.status_code == 422
    assert "server_role" in resp.json()["detail"]


# ── delete / remove / add / replicate: where the cmdlet runs ─────────


@pytest.mark.asyncio
async def test_delete_runs_on_the_hot_standby_active_side_by_default(
    db_session: AsyncSession, fake
) -> None:
    """Windows deletes the PARTNER's copies, so the side it runs on is the one
    that keeps serving — the Active server, not whichever sorts first."""
    w = await _world(db_session)
    standby = _rel("hs", "dhcp2", mode="HotStandby", server_role="Standby")
    active = _rel("hs", "dhcp1", mode="HotStandby", server_role="Active")
    await _observe(db_session, w["dhcp1"], [standby])
    await _observe(db_session, w["dhcp2"], [active])
    await db_session.flush()
    drv = fake(
        {
            "dhcp1": {"scopes": {SID}, "rels": [standby]},
            "dhcp2": {"scopes": {SID}, "rels": [active]},
        }
    )
    result = await fo_manage.delete_relationship(db_session, w["group"], "hs", keep_server_id=None)
    assert result.ran_on.name == "dhcp2"
    assert drv.calls == [("delete", "dhcp2", "hs")]
    assert drv.state["dhcp1"]["scopes"] == set(), "the partner's copy is gone"


@pytest.mark.asyncio
async def test_remove_scope_keeps_it_on_the_chosen_side(db_session: AsyncSession, fake) -> None:
    w = await _world(db_session)
    r1, r2 = _rel("p", "dhcp2"), _rel("p", "dhcp1")
    await _observe(db_session, w["dhcp1"], [r1])
    await _observe(db_session, w["dhcp2"], [r2])
    await db_session.flush()
    drv = fake({"dhcp1": {"scopes": {SID}, "rels": [r1]}, "dhcp2": {"scopes": {SID}, "rels": [r2]}})
    await fo_manage.remove_scopes(
        db_session, w["group"], "p", scope_ids=[SID], keep_server_id=w["dhcp2"].id
    )
    assert drv.calls == [("remove_scopes", "dhcp2", "p", (SID,))]


@pytest.mark.asyncio
async def test_add_scopes_runs_on_the_side_that_holds_them(db_session: AsyncSession, fake) -> None:
    w = await _world(db_session)
    other = "10.71.0.0"
    r1, r2 = _rel("p", "dhcp2"), _rel("p", "dhcp1")
    await _observe(db_session, w["dhcp1"], [r1])
    await _observe(db_session, w["dhcp2"], [r2])
    await db_session.flush()
    drv = fake(
        {"dhcp1": {"scopes": {SID}, "rels": [r1]}, "dhcp2": {"scopes": {SID, other}, "rels": [r2]}}
    )
    await fo_manage.add_scopes(db_session, w["group"], "p", scope_ids=[other])
    assert drv.calls == [("add_scopes", "dhcp2", "p", (other,))]


@pytest.mark.asyncio
async def test_add_scopes_refuses_a_scope_both_sides_hold(db_session: AsyncSession, fake) -> None:
    w = await _world(db_session)
    other = "10.71.0.0"
    r1, r2 = _rel("p", "dhcp2"), _rel("p", "dhcp1")
    await _observe(db_session, w["dhcp1"], [r1])
    await _observe(db_session, w["dhcp2"], [r2])
    await db_session.flush()
    drv = fake(
        {
            "dhcp1": {"scopes": {SID, other}, "rels": [r1]},
            "dhcp2": {"scopes": {SID, other}, "rels": [r2]},
        }
    )
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await fo_manage.add_scopes(db_session, w["group"], "p", scope_ids=[other])
    assert "both dhcp1 and dhcp2 hold it" in exc.value.detail
    assert drv.calls == []


@pytest.mark.asyncio
async def test_replicate_runs_on_the_named_source(db_session: AsyncSession, fake) -> None:
    w = await _world(db_session)
    r1, r2 = _rel("p", "dhcp2"), _rel("p", "dhcp1")
    await _observe(db_session, w["dhcp1"], [r1])
    await _observe(db_session, w["dhcp2"], [r2])
    await db_session.flush()
    drv = fake({"dhcp1": {"scopes": {SID}, "rels": [r1]}, "dhcp2": {"scopes": {SID}, "rels": [r2]}})
    await fo_manage.replicate(
        db_session, w["group"], "p", source_server_id=w["dhcp2"].id, scope_ids=[SID]
    )
    assert drv.calls == [("replicate", "dhcp2", "p", (SID,))]


@pytest.mark.asyncio
async def test_a_share_change_must_name_its_side(db_session: AsyncSession, fake) -> None:
    """Windows applies the percentage to the server the cmdlet runs on; left
    to pick a side itself, the same request would mean different things."""
    w = await _world(db_session)
    r1, r2 = _rel("p", "dhcp2"), _rel("p", "dhcp1")
    await _observe(db_session, w["dhcp1"], [r1])
    await _observe(db_session, w["dhcp2"], [r2])
    await db_session.flush()
    drv = fake({"dhcp1": {"scopes": {SID}, "rels": [r1]}, "dhcp2": {"scopes": {SID}, "rels": [r2]}})
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await fo_manage.update_relationship(
            db_session, w["group"], "p", changes={"load_balance_percent": 70}
        )
    assert "server_id" in exc.value.detail
    assert drv.calls == []
    await fo_manage.update_relationship(
        db_session,
        w["group"],
        "p",
        changes={"load_balance_percent": 70},
        server_id=w["dhcp2"].id,
    )
    assert drv.calls[0][:2] == ("update", "dhcp2")


@pytest.mark.asyncio
async def test_switching_to_hot_standby_needs_a_role_but_staying_does_not(
    db_session: AsyncSession, fake
) -> None:
    w = await _world(db_session)
    r1, r2 = _rel("p", "dhcp2"), _rel("p", "dhcp1")
    await _observe(db_session, w["dhcp1"], [r1])
    await _observe(db_session, w["dhcp2"], [r2])
    await db_session.flush()
    drv = fake({"dhcp1": {"scopes": {SID}, "rels": [r1]}, "dhcp2": {"scopes": {SID}, "rels": [r2]}})
    with pytest.raises(wt.WindowsServingRefused, match="server_role"):
        await fo_manage.update_relationship(
            db_session, w["group"], "p", changes={"mode": "HotStandby"}
        )
    # An MCLT change touches no per-side value, so any drivable side will do.
    await fo_manage.update_relationship(
        db_session, w["group"], "p", changes={"max_client_lead_time_seconds": 7200}
    )
    assert [c[0] for c in drv.calls] == ["update"]


@pytest.mark.asyncio
async def test_an_unknown_relationship_is_404(db_session: AsyncSession, fake) -> None:
    w = await _world(db_session)
    fake({"dhcp1": {}, "dhcp2": {}})
    with pytest.raises(wt.WindowsServingRefused) as exc:
        await fo_manage.delete_relationship(db_session, w["group"], "nope", keep_server_id=None)
    assert exc.value.status_code == 404


# ── Kea + Windows in one group (#1110) ────────────────────────────────


@pytest.mark.asyncio
async def test_a_kea_server_cannot_join_a_group_with_windows_members(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    w = await _world(db_session)
    token = await _token(db_session)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/dhcp/servers",
        json={
            "name": f"kea-{uuid.uuid4().hex[:6]}",
            "driver": "kea",
            "host": "10.0.0.9",
            "server_group_id": str(w["group"].id),
        },
        headers=_auth(token),
    )
    assert resp.status_code == 422, resp.text
    assert "cannot coordinate" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_an_existing_mixed_group_reports_the_shared_scope_uncoordinated(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Kea renders every active scope of its group, so a Windows-held copy of
    the same scope is a second, uncoordinated server — whatever Windows says."""
    w = await _world(db_session)
    await _observe(db_session, w["dhcp1"], [])
    db_session.add(
        DHCPServer(
            name="kea1", driver="kea", host="10.0.0.9", port=67, server_group_id=w["group"].id
        )
    )
    token = await _token(db_session)
    await db_session.commit()
    resp = await client.get(
        f"/api/v1/dhcp/server-groups/{w['group'].id}/failover", headers=_auth(token)
    )
    body = resp.json()
    assert body["kea_members"] == ["kea1"]
    (scope,) = body["scopes"]
    assert scope["verdict"] == "uncoordinated"
    assert "Kea (kea1)" in scope["detail"]


# ── the alert ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_alert_names_each_uncoordinated_scope(db_session: AsyncSession) -> None:
    from app.services.alerts import _matching_dhcp_scope_uncoordinated_subjects

    w = await _world(db_session)
    await _observe(db_session, w["dhcp1"], [])
    await _observe(db_session, w["dhcp2"], [])
    await db_session.flush()
    hits = await _matching_dhcp_scope_uncoordinated_subjects(db_session, None)  # type: ignore[arg-type]
    assert [(sid, sev) for sid, _d, _m, sev in hits] == [(f"{w['group'].id}:{CIDR}", "critical")]
    assert "same address" in hits[0][2]


@pytest.mark.asyncio
async def test_the_alert_is_silent_for_a_failover_pair(db_session: AsyncSession) -> None:
    from app.services.alerts import _matching_dhcp_scope_uncoordinated_subjects

    w = await _world(db_session)
    await _observe(db_session, w["dhcp1"], [_rel("p", "dhcp2")])
    await _observe(db_session, w["dhcp2"], [_rel("p", "dhcp1")])
    await db_session.flush()
    assert await _matching_dhcp_scope_uncoordinated_subjects(db_session, None) == []  # type: ignore[arg-type]
