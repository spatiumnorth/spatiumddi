"""A phone profile reads what it can be saved with while a scope is in the Trash (#3448).

Deleting a scope puts it in the Trash and keeps its phone-profile attachment
row, so a restore brings the scope back attached. The profile's read, the
list and the copilot's count leave the Trash scope out, as the bundle does
(``_assemble_phone_classes`` walks live, active scopes only), so a client can
save back exactly what it read. A save while the scope is in the Trash leaves
its attachment alone, so a restore brings back the class its pools name, and
#3388's guard still counts only active scopes.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.models.dhcp import DHCPPhoneProfile, DHCPPhoneProfileScope, DHCPPool
from app.services.dhcp.class_refs import phone_class_name
from app.services.dhcp.config_bundle import build_config_bundle
from tests.test_dhcp_class_refs_scope_3388 import _second_scope
from tests.test_dhcp_phone_profiles import _make_group_server_scope
from tests.test_dhcp_profile_untouched_save_3367 import _audit_changes
from tests.test_dhcp_pxe_vendor_match_validation import _headers


async def _setup(client: AsyncClient, db: AsyncSession, *, c_pool_names_the_class: bool = False):
    """Profile attached to scopes A and C, then C deleted (A keeps the class).
    With ``c_pool_names_the_class``, C has a pool restricted to the profile's
    class, which goes to the Trash with C."""
    h = await _headers(db)
    _grp, srv, a = await _make_group_server_scope(db)
    c = await _second_scope(db, a, octet=23)
    prof = DHCPPhoneProfile(
        group_id=a.group_id,
        name="polycom",
        enabled=True,
        vendor_class_match="Polycom",
        option_set=[],
    )
    db.add(prof)
    await db.flush()
    db.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=a.id))
    db.add(DHCPPhoneProfileScope(profile_id=prof.id, scope_id=c.id))
    if c_pool_names_the_class:
        db.add(
            DHCPPool(
                scope_id=c.id,
                start_ip="10.0.23.10",
                end_ip="10.0.23.50",
                pool_type="dynamic",
                class_restriction=phone_class_name(prof.id),
            )
        )
    await db.commit()
    r = await client.delete(f"/api/v1/dhcp/scopes/{c.id}", headers=h)
    assert r.status_code == 204, r.text
    return h, srv, prof, a, c


async def _attached(db: AsyncSession, prof: DHCPPhoneProfile) -> set:
    rows = await db.execute(
        select(DHCPPhoneProfileScope.scope_id).where(DHCPPhoneProfileScope.profile_id == prof.id)
    )
    return set(rows.scalars().all())


async def test_a_trashed_scope_leaves_the_profiles_read_and_the_list(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, a, c = await _setup(client, db_session)

    r = await client.get(f"/api/v1/dhcp/phone-profiles/{prof.id}", headers=h)
    assert r.status_code == 200, r.text
    assert r.json()["scope_ids"] == [str(a.id)]

    r = await client.get(f"/api/v1/dhcp/server-groups/{a.group_id}/phone-profiles", headers=h)
    assert r.status_code == 200, r.text
    assert [p["scope_ids"] for p in r.json()] == [[str(a.id)]]
    # The attachment itself stays for a restore.
    assert await _attached(db_session, prof) == {a.id, c.id}


async def test_the_copilots_profile_list_does_not_count_a_trashed_scope(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.ai.tools.dhcp import ListPhoneProfilesArgs, list_phone_profiles

    _h, _srv, _prof, a, _c = await _setup(client, db_session)
    user = (await db_session.execute(select(User).limit(1))).scalar_one()
    rows = await list_phone_profiles(
        db_session, user, ListPhoneProfilesArgs(group_id=str(a.group_id))
    )
    assert [r["scope_count"] for r in rows] == [1]


async def test_saving_back_what_the_profile_reads_succeeds_and_changes_nothing(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, srv, prof, a, c = await _setup(client, db_session)
    url = f"/api/v1/dhcp/phone-profiles/{prof.id}"
    listed = (await client.get(url, headers=h)).json()["scope_ids"]
    etag = (await build_config_bundle(db_session, srv)).etag

    r = await client.put(f"{url}/scopes", headers=h, json={"scope_ids": listed})
    assert r.status_code == 200, r.text
    assert r.json()["scope_ids"] == listed
    # #3367: an untouched Save rewrites, audits and renders nothing new.
    assert await _audit_changes(db_session, "dhcp_phone_profile") == []
    assert await _attached(db_session, prof) == {a.id, c.id}
    assert (await build_config_bundle(db_session, srv)).etag == etag


async def test_a_save_while_a_scope_is_in_the_trash_keeps_it_attached_for_its_restore(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h, _srv, prof, a, c = await _setup(client, db_session)
    d = await _second_scope(db_session, a, octet=24)
    await db_session.commit()
    url = f"/api/v1/dhcp/phone-profiles/{prof.id}"

    r = await client.put(f"{url}/scopes", headers=h, json={"scope_ids": [str(a.id), str(d.id)]})
    assert r.status_code == 200, r.text
    assert sorted(r.json()["scope_ids"]) == sorted([str(a.id), str(d.id)])
    assert await _audit_changes(db_session, "dhcp_phone_profile") == [["scope_attachments"]]

    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{c.id}/restore", headers=h)
    assert r.status_code == 200, r.text
    r = await client.get(url, headers=h)
    assert sorted(r.json()["scope_ids"]) == sorted([str(a.id), str(c.id), str(d.id)])


async def test_the_last_active_scope_still_cannot_go_while_another_is_in_the_trash(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#3388: a Trash scope renders no class, so it does not stand in for the
    last active one; detaching that is still refused while a pool names it."""
    h, srv, prof, a, c = await _setup(client, db_session)
    b = await _second_scope(db_session, a, octet=25)
    cls = phone_class_name(prof.id)
    db_session.add(
        DHCPPool(
            scope_id=b.id,
            start_ip="10.0.25.10",
            end_ip="10.0.25.50",
            pool_type="dynamic",
            class_restriction=cls,
        )
    )
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/phone-profiles/{prof.id}/scopes", headers=h, json={"scope_ids": []}
    )
    assert r.status_code == 409, r.text
    assert cls in r.json()["detail"]
    assert await _attached(db_session, prof) == {a.id, c.id}
    bundle = await build_config_bundle(db_session, srv)
    assert cls in {pc.name for pc in bundle.phone_classes}


async def test_a_restore_after_a_save_that_emptied_the_profile_renders_its_pools_class(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#3430: no live pool may name a phone class nothing renders. C's own pool
    names the class and went to the Trash with C, so detaching A, the last live
    scope, is allowed. The restore brings C back attached, so the class its pool
    names renders again instead of coming back orphaned."""
    h, srv, prof, _a, c = await _setup(client, db_session, c_pool_names_the_class=True)
    url = f"/api/v1/dhcp/phone-profiles/{prof.id}"

    r = await client.put(f"{url}/scopes", headers=h, json={"scope_ids": []})
    assert r.status_code == 200, r.text
    assert r.json()["scope_ids"] == []

    r = await client.post(f"/api/v1/admin/trash/dhcp_scope/{c.id}/restore", headers=h)
    assert r.status_code == 200, r.text
    bundle = await build_config_bundle(db_session, srv)
    assert phone_class_name(prof.id) in {pc.name for pc in bundle.phone_classes}
    r = await client.get(url, headers=h)
    assert r.json()["scope_ids"] == [str(c.id)]
