"""Editing a PXE rule's selector keeps its Kea class (#3374).

The dialog now names each existing rule by id, so the server updates that row
in place instead of deleting and re-creating it. The generated class name
embeds the row id, so a pool bound to it keeps matching; deleting a rule a pool
still names is refused.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dhcp import DHCPPool, DHCPScope
from app.services.dhcp.config_bundle import build_config_bundle
from tests.test_dhcp_phone_profiles import _make_group_server_scope
from tests.test_dhcp_pxe_vendor_match_validation import _headers


def _m(prio: int, arch: int, boot: str) -> dict:
    return {
        "priority": prio,
        "match_kind": "first_stage",
        "vendor_class_match": "PXEClient",
        "arch_codes": [arch],
        "boot_filename": boot,
    }


async def _setup(client: AsyncClient, db: AsyncSession, bind_rule: int = 0):
    h = await _headers(db)
    grp, srv, scope = await _make_group_server_scope(db)
    await db.commit()
    created = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/pxe-profiles",
        headers=h,
        json={
            "name": "boot",
            "next_server": "10.0.0.5",
            "matches": [_m(10, 7, "ipxe.efi"), _m(20, 0, "undionly.kpxe")],
        },
    )
    assert created.status_code == 201, created.text
    prof = created.json()
    rule = sorted(prof["matches"], key=lambda m: m["priority"])[bind_rule]
    cls = f"pxe-{prof['id'][:8]}-{rule['id'][:8]}"
    sc = await db.get(DHCPScope, scope.id)
    assert sc is not None
    sc.pxe_profile_id = uuid.UUID(prof["id"])
    db.add(
        DHCPPool(
            scope_id=scope.id,
            start_ip="10.0.20.10",
            end_ip="10.0.20.50",
            pool_type="dynamic",
            class_restriction=cls,
        )
    )
    await db.commit()
    return h, srv, prof, rule, cls


def _body(prof: dict, matches: list[dict]) -> dict:
    return {"name": prof["name"], "matches": matches}


def _with_ids(prof: dict) -> list[dict]:
    keys = ("id", "priority", "match_kind", "vendor_class_match", "arch_codes", "boot_filename")
    return [{k: m[k] for k in keys} for m in sorted(prof["matches"], key=lambda m: m["priority"])]


async def test_selector_edit_with_id_keeps_class_and_pool_binding(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, srv, prof, rule, cls = await _setup(client, db_session)
    rows = _with_ids(prof)
    rows[0]["arch_codes"] = [9]
    rows[0]["vendor_class_match"] = "HTTPClient"
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=_body(prof, rows)
    )
    assert resp.status_code == 200, resp.text
    edited = next(m for m in resp.json()["matches"] if m["id"] == rule["id"])
    assert edited["arch_codes"] == [9]
    assert edited["vendor_class_match"] == "HTTPClient"
    assert {m["id"] for m in resp.json()["matches"]} == {m["id"] for m in prof["matches"]}

    bundle = await build_config_bundle(db_session, srv)
    assert cls in {c.name for c in bundle.pxe_classes}
    pools = [p for s in bundle.scopes for p in s.pools]
    assert [p.class_restriction for p in pools] == [cls]


async def test_foreign_or_unknown_id_is_422(client: AsyncClient, db_session: AsyncSession) -> None:
    h, _srv, prof, _rule, _cls = await _setup(client, db_session)
    other = await client.post(
        f"/api/v1/dhcp/server-groups/{prof['group_id']}/pxe-profiles",
        headers=h,
        json={"name": "other", "next_server": "10.0.0.6", "matches": [_m(10, 7, "x.efi")]},
    )
    assert other.status_code == 201, other.text
    foreign = other.json()["matches"][0]["id"]
    rows = _with_ids(prof)
    rows[0]["id"] = foreign
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=_body(prof, rows)
    )
    assert resp.status_code == 422, resp.text
    rows[0]["id"] = str(uuid.uuid4())
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=_body(prof, rows)
    )
    assert resp.status_code == 422, resp.text


async def test_no_ids_still_pairs_by_selector(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, rule, _cls = await _setup(client, db_session)
    rows = [{k: v for k, v in r.items() if k != "id"} for r in _with_ids(prof)]
    rows[0]["boot_filename"] = "renamed.efi"
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=_body(prof, rows)
    )
    assert resp.status_code == 200, resp.text
    kept = next(m for m in resp.json()["matches"] if m["id"] == rule["id"])
    assert kept["boot_filename"] == "renamed.efi"


async def test_removing_a_rule_a_pool_names_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, _rule, cls = await _setup(client, db_session)
    rows = _with_ids(prof)[1:]  # drop the bound rule
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=_body(prof, rows)
    )
    assert resp.status_code == 409, resp.text
    assert cls in resp.json()["detail"]
    still = await client.get(f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h)
    assert len(still.json()["matches"]) == 2

    # Dropping the other, unreferenced rule is fine.
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=_body(prof, _with_ids(prof)[:1])
    )
    assert resp.status_code == 200, resp.text


async def test_duplicated_id_and_invalid_edited_rule_are_422(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, _rule, _cls = await _setup(client, db_session)
    rows = _with_ids(prof)
    rows[1]["id"] = rows[0]["id"]
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=_body(prof, rows)
    )
    assert resp.status_code == 422, resp.text

    # An identified edit is still validated like any other rule.
    rows = _with_ids(prof)
    rows[0]["vendor_class_match"] = "PXE'Client"
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=_body(prof, rows)
    )
    assert resp.status_code == 422, resp.text
    rows = _with_ids(prof)
    rows[0]["arch_codes"] = [300]
    resp = await client.put(
        f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=_body(prof, rows)
    )
    assert resp.status_code == 422, resp.text
    still = await client.get(f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h)
    assert still.json()["matches"] == prof["matches"]


async def test_deleting_a_profile_whose_rule_a_pool_names_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, _rule, cls = await _setup(client, db_session)
    resp = await client.delete(f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h)
    assert resp.status_code == 409, resp.text
    assert cls in resp.json()["detail"]
    assert "10.0.20.10-10.0.20.50" in resp.json()["detail"]
    still = await client.get(f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h)
    assert still.status_code == 200
    assert len(still.json()["matches"]) == 2

    # Once no pool names its classes, the profile deletes as before.
    other = await client.post(
        f"/api/v1/dhcp/server-groups/{prof['group_id']}/pxe-profiles",
        headers=h,
        json={"name": "spare", "next_server": "10.0.0.6", "matches": [_m(10, 7, "x.efi")]},
    )
    assert other.status_code == 201, other.text
    resp = await client.delete(f"/api/v1/dhcp/pxe-profiles/{other.json()['id']}", headers=h)
    assert resp.status_code == 204, resp.text
