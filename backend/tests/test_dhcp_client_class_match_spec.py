"""Client class ``match_spec`` over the API: option 82 builder (#54).

``match_spec`` is compiled server-side into ``match_expression`` in the same
write, so the bundle, the agent and the ETag only ever see the compiled test.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.dhcp import DHCPClientClass, DHCPServer, DHCPServerGroup
from app.services.dhcp.config_bundle import _client_class_def

SPEC = {
    "kind": "relay_agent",
    "combine": "all",
    "conditions": [{"sub_option": 1, "op": "equals", "encoding": "text", "value": "eth0/1:100"}],
}
COMPILED = "(relay4[1].hex == 0x657468302F313A313030)"


async def _headers(db: AsyncSession, *, superadmin: bool = True) -> dict[str, str]:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession, *drivers: str) -> DHCPServerGroup:
    grp = DHCPServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    for i, drv in enumerate(drivers):
        db.add(
            DHCPServer(
                name=f"s-{uuid.uuid4().hex[:6]}",
                driver=drv,
                host=f"10.0.0.{i + 1}",
                port=67,
                server_group_id=grp.id,
            )
        )
    await db.commit()
    return grp


def _url(grp: DHCPServerGroup) -> str:
    return f"/api/v1/dhcp/server-groups/{grp.id}/client-classes"


async def _create(client: AsyncClient, h: dict, grp: DHCPServerGroup, **body: object) -> dict:
    r = await client.post(_url(grp), json={"name": "port", **body}, headers=h)
    assert r.status_code == 201, r.text
    return r.json()


# ── create ───────────────────────────────────────────────────────────────────


async def test_create_compiles_the_spec_into_the_expression(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    body = await _create(client, h, grp, match_spec=SPEC)
    assert body["match_expression"] == COMPILED
    assert body["match_spec"] == SPEC
    row = (await db_session.execute(select(DHCPClientClass))).scalar_one()
    assert row.match_expression == COMPILED
    assert row.match_spec == SPEC
    # The bundle sees only the compiled test: no new wire field, no ETag input.
    cdef = _client_class_def(row)
    assert cdef.match_expression == COMPILED
    assert "match_spec" not in cdef.__dict__


async def test_create_stores_the_normalised_spec(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    body = await _create(
        client,
        h,
        grp,
        match_spec={
            "conditions": [
                {"sub_option": 2, "op": "starts_with", "encoding": "hex", "value": "aa:bb:cc"}
            ]
        },
    )
    assert body["match_spec"] == {
        "kind": "relay_agent",
        "combine": "all",
        "conditions": [
            {"sub_option": 2, "op": "starts_with", "encoding": "hex", "value": "AABBCC"}
        ],
    }
    assert body["match_expression"] == "(substring(relay4[2].hex, 0, 3) == 0xAABBCC)"


async def test_a_hand_written_class_has_no_spec(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    body = await _create(client, h, grp, match_expression="pkt4.mac == 0x01")
    assert body["match_spec"] is None


async def test_the_same_compiled_expression_alongside_the_spec_is_accepted(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    body = await _create(client, h, grp, match_spec=SPEC, match_expression=COMPILED)
    assert body["match_expression"] == COMPILED


async def test_a_different_expression_alongside_the_spec_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    r = await client.post(
        _url(grp),
        json={"name": "p", "match_spec": SPEC, "match_expression": "relay4[1].exists"},
        headers=h,
    )
    assert r.status_code == 422
    assert "send one or the other" in r.json()["detail"]


async def test_an_option82_class_must_be_ipv4(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    for family in ("ipv6", "dual"):
        r = await client.post(
            _url(grp),
            json={"name": "p", "match_spec": SPEC, "address_family": family},
            headers=h,
        )
        assert r.status_code == 422, family
        assert "DHCPv4 only" in r.json()["detail"]


async def test_an_invalid_spec_is_a_422(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    bad = [
        {"conditions": []},
        {"conditions": [{"sub_option": 1, "op": "equals", "value": ""}]},
        {"conditions": [{"sub_option": 1, "op": "equals", "encoding": "hex", "value": "ABC"}]},
        {"conditions": [{"sub_option": 0, "op": "exists"}]},
        {"conditions": [{"sub_option": 1, "op": "exists", "bogus": 1}]},
    ]
    for spec in bad:
        r = await client.post(_url(grp), json={"name": "p", "match_spec": spec}, headers=h)
        assert r.status_code == 422, spec
    assert (await db_session.execute(select(DHCPClientClass))).first() is None


async def test_hostile_values_cannot_reach_the_stored_expression(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    nasty = "') or (relay4[1].exists or (pkt4.mac == '\n\\"
    body = await _create(
        client,
        h,
        grp,
        match_spec={"conditions": [{"sub_option": 1, "op": "equals", "value": nasty}]},
    )
    expr = body["match_expression"]
    assert "'" not in expr and "\\" not in expr and "\n" not in expr
    assert expr == f"(relay4[1].hex == 0x{nasty.encode().hex().upper()})"


# ── Windows and other groups ─────────────────────────────────────────────────


async def test_a_windows_only_group_refuses_an_option82_class(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "windows_dhcp")
    r = await client.post(_url(grp), json={"name": "p", "match_spec": SPEC}, headers=h)
    assert r.status_code == 422
    assert "Kea only" in r.json()["detail"] and "windows_dhcp" in r.json()["detail"]
    # A hand-written class on that group is untouched by this rule.
    await _create(client, h, grp, name="legacy", match_expression="pkt4.mac == 0x01")


async def test_an_empty_group_and_a_mixed_group_allow_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    assert (await _create(client, h, await _group(db_session), match_spec=SPEC))["match_spec"]
    mixed = await _group(db_session, "windows_dhcp", "kea")
    assert (await _create(client, h, mixed, match_spec=SPEC))["match_spec"]


# ── update ───────────────────────────────────────────────────────────────────


async def test_update_replaces_the_spec_and_the_expression_together(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    cc = await _create(client, h, grp, match_spec=SPEC)
    new = {"conditions": [{"sub_option": 2, "op": "exists"}]}
    r = await client.put(
        f"/api/v1/dhcp/client-classes/{cc['id']}", json={"match_spec": new}, headers=h
    )
    assert r.status_code == 200, r.text
    assert r.json()["match_expression"] == "(relay4[2].exists)"
    assert r.json()["match_spec"]["conditions"] == [
        {"sub_option": 2, "op": "exists", "encoding": "text"}
    ]


async def test_an_expression_only_update_of_a_builder_class_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    cc = await _create(client, h, grp, match_spec=SPEC)
    url = f"/api/v1/dhcp/client-classes/{cc['id']}"
    r = await client.put(url, json={"match_expression": "pkt4.mac == 0x01"}, headers=h)
    assert r.status_code == 422
    assert "match_spec: null" in r.json()["detail"]
    # Posting the current compiled text back (a dialog round trip) is a no-op.
    r = await client.put(url, json={"match_expression": COMPILED, "description": "d"}, headers=h)
    assert r.status_code == 200
    assert r.json()["match_spec"] == SPEC


async def test_explicit_null_converts_to_a_hand_written_class(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    cc = await _create(client, h, grp, match_spec=SPEC)
    url = f"/api/v1/dhcp/client-classes/{cc['id']}"
    r = await client.put(url, json={"match_spec": None}, headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["match_spec"] is None
    assert r.json()["match_expression"] == COMPILED  # the compiled text is the starting point
    r = await client.put(url, json={"match_expression": "pkt4.mac == 0x01"}, headers=h)
    assert r.status_code == 200
    assert r.json()["match_expression"] == "pkt4.mac == 0x01"


async def test_null_with_a_new_expression_converts_and_sets_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    cc = await _create(client, h, grp, match_spec=SPEC)
    r = await client.put(
        f"/api/v1/dhcp/client-classes/{cc['id']}",
        json={"match_spec": None, "match_expression": "pkt4.mac == 0x02"},
        headers=h,
    )
    assert r.status_code == 200
    assert (r.json()["match_spec"], r.json()["match_expression"]) == (None, "pkt4.mac == 0x02")


async def test_a_builder_class_cannot_leave_ipv4_and_a_spec_cannot_go_on_a_v6_class(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    cc = await _create(client, h, grp, match_spec=SPEC)
    r = await client.put(
        f"/api/v1/dhcp/client-classes/{cc['id']}", json={"address_family": "ipv6"}, headers=h
    )
    assert r.status_code == 422
    v6 = await _create(client, h, grp, name="v6", address_family="ipv6", match_expression="")
    r = await client.put(
        f"/api/v1/dhcp/client-classes/{v6['id']}", json={"match_spec": SPEC}, headers=h
    )
    assert r.status_code == 422


async def test_update_refuses_a_spec_with_a_conflicting_expression(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    cc = await _create(client, h, grp, match_expression="pkt4.mac == 0x01")
    r = await client.put(
        f"/api/v1/dhcp/client-classes/{cc['id']}",
        json={"match_spec": SPEC, "match_expression": "relay4[1].exists"},
        headers=h,
    )
    assert r.status_code == 422


async def test_an_ordinary_update_leaves_the_spec_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    cc = await _create(client, h, grp, match_spec=SPEC)
    r = await client.put(
        f"/api/v1/dhcp/client-classes/{cc['id']}", json={"description": "x"}, headers=h
    )
    assert r.status_code == 200
    assert (r.json()["match_spec"], r.json()["match_expression"]) == (SPEC, COMPILED)


# ── audit ────────────────────────────────────────────────────────────────────


async def test_the_audit_row_carries_the_spec_and_the_compiled_test(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    cc = await _create(client, h, grp, match_spec=SPEC)
    create = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "dhcp_client_class", AuditLog.action == "create"
            )
        )
    ).scalar_one()
    assert create.new_value["match_spec"] == SPEC
    assert create.new_value["match_expression"] == COMPILED

    await client.put(
        f"/api/v1/dhcp/client-classes/{cc['id']}",
        json={"match_spec": {"conditions": [{"sub_option": 6, "op": "exists"}]}},
        headers=h,
    )
    upd = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "dhcp_client_class", AuditLog.action == "update"
            )
        )
    ).scalar_one()
    assert set(upd.changed_fields) >= {"match_spec", "match_expression"}
    assert upd.new_value["match_expression"] == "(relay4[6].exists)"


# ── compile-match ────────────────────────────────────────────────────────────


async def test_compile_match_is_stateless(client: AsyncClient, db_session: AsyncSession) -> None:
    h = await _headers(db_session)
    r = await client.post(
        "/api/v1/dhcp/client-classes/compile-match", json={"match_spec": SPEC}, headers=h
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["expression"] == COMPILED
    assert body["warnings"] == []
    assert body["windows"] == {"supported": True, "reason": ""}
    assert (await db_session.execute(select(DHCPClientClass))).first() is None
    assert (
        await db_session.execute(
            select(AuditLog).where(AuditLog.resource_type == "dhcp_client_class")
        )
    ).first() is None


async def test_compile_match_reports_windows_support_and_warnings(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    spec = {"conditions": [{"sub_option": 1, "op": "slice", "offset": 2, "value": "x"}]}
    r = await client.post(
        "/api/v1/dhcp/client-classes/compile-match", json={"match_spec": spec}, headers=h
    )
    assert r.status_code == 200
    assert r.json()["windows"]["supported"] is False
    neg = {"conditions": [{"sub_option": 1, "op": "not_equals", "value": "x"}]}
    r = await client.post(
        "/api/v1/dhcp/client-classes/compile-match", json={"match_spec": neg}, headers=h
    )
    assert any("not equals" in w for w in r.json()["warnings"])


async def test_compile_match_422s_on_a_bad_spec(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    r = await client.post(
        "/api/v1/dhcp/client-classes/compile-match",
        json={"match_spec": {"conditions": [{"sub_option": 999, "op": "exists"}]}},
        headers=h,
    )
    assert r.status_code == 422


async def test_compile_match_needs_only_read_but_still_needs_it(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    anon = await client.post("/api/v1/dhcp/client-classes/compile-match", json={"match_spec": SPEC})
    assert anon.status_code in (401, 403)
    h = await _headers(db_session, superadmin=False)
    r = await client.post(
        "/api/v1/dhcp/client-classes/compile-match", json={"match_spec": SPEC}, headers=h
    )
    assert r.status_code == 403


async def test_a_nul_in_text_is_a_clean_422_not_a_storage_error(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    spec = {"conditions": [{"sub_option": 1, "op": "equals", "value": "a\x00b"}]}
    r = await client.post(_url(grp), json={"name": "p", "match_spec": spec}, headers=h)
    assert r.status_code == 422
    assert "hex" in str(r.json())


# ── a non-Kea server joining a group that holds option 82 classes ────────────


async def test_a_windows_server_cannot_join_a_group_with_an_option82_class(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The class API refuses a spec on a Windows-only group; the same rule has to
    hold when the Windows server arrives after the class (create and move)."""
    h = await _headers(db_session)
    grp = await _group(db_session)  # empty: the class is allowed
    await _create(client, h, grp, match_spec=SPEC)
    body = {
        "name": "w1",
        "driver": "windows_dhcp",
        "host": "10.9.9.9",
        "server_group_id": str(grp.id),
        "windows_credentials": {"username": "u", "password": "p"},
    }
    r = await client.post("/api/v1/dhcp/servers", json=body, headers=h)
    assert r.status_code == 422, r.text
    assert "option 82" in r.json()["detail"]

    # Move: an existing Windows server in another group cannot be moved in.
    other = await _group(db_session, "windows_dhcp")
    srv = (
        await db_session.execute(select(DHCPServer).where(DHCPServer.server_group_id == other.id))
    ).scalar_one()
    r = await client.put(
        f"/api/v1/dhcp/servers/{srv.id}", json={"server_group_id": str(grp.id)}, headers=h
    )
    assert r.status_code == 422, r.text
    assert "option 82" in r.json()["detail"]

    # A Kea server, and a group with only hand-written classes, are unaffected.
    kea = {**body, "name": "k1", "driver": "kea"}
    kea.pop("windows_credentials")
    assert (await client.post("/api/v1/dhcp/servers", json=kea, headers=h)).status_code == 201
    plain = await _group(db_session)
    await _create(client, h, plain, match_expression="pkt4.mac == 0x01")
    ok = {**body, "name": "w2", "server_group_id": str(plain.id)}
    r = await client.post("/api/v1/dhcp/servers", json=ok, headers=h)
    assert "option 82" not in r.text, r.text


async def test_no_spec_is_sql_null_not_json_null(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A JSONB ``None`` is stored as the JSON value ``null`` unless the column says
    ``none_as_null``; ``IS NOT NULL`` (the option 82 filters) then counts every class."""
    h = await _headers(db_session)
    grp = await _group(db_session, "kea")
    await _create(client, h, grp, name="plain", match_expression="pkt4.mac == 0x01")
    built = await _create(client, h, grp, name="built", match_spec=SPEC)
    await client.put(
        f"/api/v1/dhcp/client-classes/{built['id']}", json={"match_spec": None}, headers=h
    )
    db_session.expire_all()
    n = (
        await db_session.execute(
            select(DHCPClientClass.id).where(DHCPClientClass.match_spec.is_not(None))
        )
    ).all()
    assert n == []
