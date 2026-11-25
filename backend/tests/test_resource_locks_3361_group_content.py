"""A DNS server group's edit lock also freezes its ACLs, TSIG keys, trust
anchors and server options (#3361). A delete lock does not, and annotations
(an ACL's description, a key's notes) stay editable."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServerGroup
from tests.test_resource_locks_3361 import _lock, _user


@pytest.mark.asyncio
async def test_group_edit_lock_freezes_acls_keys_anchors_and_options(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session)
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db_session.add(group)
    await db_session.flush()
    gid = group.id
    await db_session.commit()
    base = f"/api/v1/dns/groups/{gid}"

    # Seed one of each while the group is unlocked.
    acl = await client.post(
        f"{base}/acls",
        headers=admin,
        json={"name": "office", "entries": [{"value": "10.0.0.0/8"}]},
    )
    assert acl.status_code == 201, acl.text
    acl_id = acl.json()["id"]
    key = await client.post(
        f"{base}/tsig-keys", headers=admin, json={"name": "k1", "algorithm": "hmac-sha256"}
    )
    assert key.status_code == 201, key.text
    key_id = key.json()["id"]
    anchor = await client.post(
        f"{base}/options/trust-anchors",
        headers=admin,
        json={
            "zone_name": "corp.example.",
            "key_tag": 1,
            "algorithm": 13,
            "public_key": "AwEAAbcd" * 8,
        },
    )
    assert anchor.status_code == 201, anchor.text
    anchor_id = anchor.json()["id"]

    # A delete lock freezes none of it.
    assert (await _lock(client, admin, "dns_group", gid, "delete")).status_code == 200
    assert (
        await client.put(f"{base}/acls/{acl_id}", headers=admin, json={"description": "d1"})
    ).status_code == 200
    opt = await client.put(f"{base}/options", headers=admin, json={"recursion_enabled": False})
    assert opt.status_code == 200, opt.text

    assert (await _lock(client, admin, "dns_group", gid, "edit")).status_code == 200

    def locked(r: object) -> bool:
        return r.status_code == 423 and r.json()["detail"]["resource_type"] == "dns_group"  # type: ignore[attr-defined]

    # ACLs
    assert locked(
        await client.post(f"{base}/acls", headers=admin, json={"name": "new", "entries": []})
    )
    assert locked(
        await client.put(
            f"{base}/acls/{acl_id}",
            headers=admin,
            json={"entries": [{"value": "192.168.0.0/16"}]},
        )
    )
    assert locked(await client.put(f"{base}/acls/{acl_id}", headers=admin, json={"name": "x"}))
    assert locked(await client.delete(f"{base}/acls/{acl_id}", headers=admin))
    # ...but re-sending what is stored, and the description, are not changes.
    same = await client.put(
        f"{base}/acls/{acl_id}",
        headers=admin,
        json={"name": "office", "description": "annotated", "entries": [{"value": "10.0.0.0/8"}]},
    )
    assert same.status_code == 200, same.text

    # TSIG keys
    assert locked(
        await client.post(
            f"{base}/tsig-keys", headers=admin, json={"name": "k2", "algorithm": "hmac-sha256"}
        )
    )
    assert locked(
        await client.put(f"{base}/tsig-keys/{key_id}", headers=admin, json={"name": "k9"})
    )
    assert locked(await client.post(f"{base}/tsig-keys/{key_id}/rotate", headers=admin))
    assert locked(await client.delete(f"{base}/tsig-keys/{key_id}", headers=admin))
    assert locked(await client.post(f"{base}/group-tsig-key/rotate", headers=admin))
    notes = await client.put(
        f"{base}/tsig-keys/{key_id}", headers=admin, json={"notes": "rotated quarterly"}
    )
    assert notes.status_code == 200, notes.text

    # Trust anchors
    assert locked(
        await client.post(
            f"{base}/options/trust-anchors",
            headers=admin,
            json={
                "zone_name": "other.example.",
                "key_tag": 2,
                "algorithm": 13,
                "public_key": "AwEAAefg" * 8,
            },
        )
    )
    assert locked(await client.delete(f"{base}/options/trust-anchors/{anchor_id}", headers=admin))

    # Options
    stored = (await client.get(f"{base}/options", headers=admin)).json()["recursion_enabled"]
    assert locked(
        await client.put(f"{base}/options", headers=admin, json={"recursion_enabled": not stored})
    )
    assert (
        await client.put(f"{base}/options", headers=admin, json={"recursion_enabled": stored})
    ).status_code != 423

    # Unlocking releases all of it.
    assert (
        await client.post(
            f"/api/v1/locks/dns_group/{gid}/unlock", headers=admin, json={"reason": "done"}
        )
    ).status_code == 204
    assert (await client.delete(f"{base}/acls/{acl_id}", headers=admin)).status_code == 204
