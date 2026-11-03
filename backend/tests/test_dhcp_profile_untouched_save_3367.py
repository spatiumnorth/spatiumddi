"""An untouched Save of a PXE / phone profile changes nothing (#3367).

#3086 made the generic update handlers audit only moved fields; these two
still reported ``matches`` / ``scope_attachments`` as changed, and the PXE
save deleted and re-created its boot rules. The Kea class name embeds the
match id, so that also renamed every class and shifted the bundle ETag.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.dhcp import DHCPPXEArchMatch, DHCPScope
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


async def _audit_changes(db: AsyncSession, rtype: str) -> list[list[str]]:
    rows = (
        await db.execute(
            select(AuditLog).where(AuditLog.resource_type == rtype, AuditLog.action == "update")
        )
    ).scalars()
    return [list(r.changed_fields or []) for r in rows]


async def test_untouched_pxe_save_keeps_rule_ids_etag_and_audits_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, srv, scope = await _make_group_server_scope(db_session)
    await db_session.commit()
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
    scope_row = await db_session.get(DHCPScope, scope.id)
    assert scope_row is not None
    scope_row.pxe_profile_id = uuid.UUID(prof["id"])
    await db_session.commit()
    etag0 = (await build_config_bundle(db_session, srv)).etag

    body = {
        "name": prof["name"],
        "description": prof["description"],
        "next_server": prof["next_server"],
        "enabled": prof["enabled"],
        "tags": prof["tags"],
        "matches": [{k: m[k] for k in _m(0, 0, "x")} for m in prof["matches"]],
    }
    resp = await client.put(f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=body)
    assert resp.status_code == 200, resp.text
    assert [m["id"] for m in resp.json()["matches"]] == [m["id"] for m in prof["matches"]]
    assert await _audit_changes(db_session, "dhcp_pxe_profile") == [[]]
    assert (await build_config_bundle(db_session, srv)).etag == etag0

    # A real edit still audits `matches`, keeps the untouched rule's id and
    # updates the other in place.
    body["matches"][1]["boot_filename"] = "other.kpxe"
    resp = await client.put(f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=body)
    assert resp.status_code == 200, resp.text
    ids = {m["boot_filename"]: m["id"] for m in resp.json()["matches"]}
    assert ids["ipxe.efi"] == prof["matches"][0]["id"]
    assert ids["other.kpxe"] == prof["matches"][1]["id"]
    assert ["matches"] in await _audit_changes(db_session, "dhcp_pxe_profile")

    # Dropping one deletes only that row; adding creates only a new one.
    body["matches"] = body["matches"][:1] + [_m(30, 9, "new.efi")]
    resp = await client.put(f"/api/v1/dhcp/pxe-profiles/{prof['id']}", headers=h, json=body)
    assert resp.status_code == 200, resp.text
    rows = (await db_session.execute(select(DHCPPXEArchMatch.boot_filename))).scalars().all()
    assert sorted(rows) == ["ipxe.efi", "new.efi"]


async def test_untouched_phone_scope_attach_audits_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    grp, _srv, scope = await _make_group_server_scope(db_session)
    await db_session.commit()
    created = await client.post(
        f"/api/v1/dhcp/server-groups/{grp.id}/phone-profiles",
        headers=h,
        json={"name": "ph", "enabled": False, "scope_ids": []},
    )
    assert created.status_code == 201, created.text
    pid = created.json()["id"]
    url = f"/api/v1/dhcp/phone-profiles/{pid}/scopes"

    r = await client.put(url, headers=h, json={"scope_ids": [str(scope.id)]})
    assert r.status_code == 200, r.text
    assert await _audit_changes(db_session, "dhcp_phone_profile") == [["scope_attachments"]]

    r = await client.put(url, headers=h, json={"scope_ids": [str(scope.id)]})
    assert r.status_code == 200, r.text
    assert r.json()["scope_ids"] == [str(scope.id)]
    assert await _audit_changes(db_session, "dhcp_phone_profile") == [["scope_attachments"]]
