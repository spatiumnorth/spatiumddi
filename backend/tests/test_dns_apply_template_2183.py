"""#2183 - apply a record template to an existing zone: preview -> apply."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import APIToken, Group, Role, User
from app.models.dns import DNSRecord, DNSRecordOp, DNSServerGroup, DNSZone

pytestmark = pytest.mark.asyncio

MAIL = {"template_id": "mail-basic", "params": {"mx_host": "mx.apply.test."}}


async def _user(db: AsyncSession, perms: list[dict] | None, *, superadmin: bool = False) -> User:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(u)
    await db.flush()
    if perms is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:8]}", description="", permissions=perms)
        db.add(role)
        await db.flush()
        g = Group(name=f"g-{uuid.uuid4().hex[:8]}", description="")
        g.roles = [role]
        g.users = [u]
        db.add(g)
        await db.flush()
    return u


def _bearer(u: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _zone(db: AsyncSession, name: str = "apply.test.") -> tuple[DNSServerGroup, DNSZone]:
    grp = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    zone = DNSZone(group_id=grp.id, name=name, zone_type="primary", kind="forward")
    db.add(zone)
    await db.flush()
    return grp, zone


def _url(grp: DNSServerGroup, zone: DNSZone, tail: str = "") -> str:
    return f"/api/v1/dns/groups/{grp.id}/zones/{zone.id}/apply-template{tail}"


async def _rows(db: AsyncSession, zone: DNSZone) -> list[DNSRecord]:
    return list((await db.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))).scalars())


def _by(items: list[dict[str, Any]], status: str) -> list[dict[str, Any]]:
    return [i for i in items if i["status"] == status]


async def test_preview_writes_nothing_then_apply_adds_and_audits(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, None, superadmin=True)
    grp, zone = await _zone(db_session)
    await db_session.commit()
    h = _bearer(admin)

    pre = await client.post(_url(grp, zone, "/preview"), headers=h, json=MAIL)
    assert pre.status_code == 200, pre.text
    body = pre.json()
    assert body["add"] == 3 and body["present"] == 0 and body["conflict"] == 0
    assert await _rows(db_session, zone) == []
    assert (await db_session.execute(select(func.count()).select_from(DNSRecordOp))).scalar() == 0

    res = await client.post(_url(grp, zone), headers=h, json=MAIL)
    assert res.status_code == 201, res.text
    assert res.json()["created"] == 3
    rows = await _rows(db_session, zone)
    assert {(r.name, r.record_type) for r in rows} == {
        ("@", "MX"),
        ("@", "TXT"),
        ("_dmarc", "TXT"),
    }
    audit = (
        (await db_session.execute(select(AuditLog).where(AuditLog.action == "apply_template")))
        .scalars()
        .all()
    )
    assert len(audit) == 1
    assert audit[0].new_value["template_id"] == "mail-basic"
    assert audit[0].new_value["created"] == 3


async def test_reapply_is_idempotent(client: AsyncClient, db_session: AsyncSession) -> None:
    admin = await _user(db_session, None, superadmin=True)
    grp, zone = await _zone(db_session)
    await db_session.commit()
    h = _bearer(admin)
    assert (await client.post(_url(grp, zone), headers=h, json=MAIL)).status_code == 201
    again = await client.post(_url(grp, zone), headers=h, json=MAIL)
    assert again.status_code == 201, again.text
    assert again.json()["created"] == 0 and again.json()["present"] == 3
    assert len(await _rows(db_session, zone)) == 3
    pre = (await client.post(_url(grp, zone, "/preview"), headers=h, json=MAIL)).json()
    assert pre["present"] == 3 and pre["add"] == 0


async def test_existing_spf_is_a_conflict_not_a_second_record(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, None, superadmin=True)
    grp, zone = await _zone(db_session)
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            fqdn=zone.name,
            name="@",
            record_type="TXT",
            value="v=spf1 include:other.test -all",
        )
    )
    await db_session.commit()
    h = _bearer(admin)
    pre = (await client.post(_url(grp, zone, "/preview"), headers=h, json=MAIL)).json()
    conflicts = _by(pre["items"], "conflict")
    assert len(conflicts) == 1 and "v=spf1" in conflicts[0]["reason"]
    assert pre["add"] == 2

    refused = await client.post(_url(grp, zone), headers=h, json=MAIL)
    assert refused.status_code == 409
    assert len(await _rows(db_session, zone)) == 1

    ok = await client.post(_url(grp, zone), headers=h, json={**MAIL, "skip_conflicts": True})
    assert ok.status_code == 201, ok.text
    assert ok.json()["created"] == 2 and len(ok.json()["skipped"]) == 1
    texts = [
        r.value for r in await _rows(db_session, zone) if r.name == "@" and r.record_type == "TXT"
    ]
    assert texts == ["v=spf1 include:other.test -all"]


async def test_cname_exclusivity_is_a_conflict(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, None, superadmin=True)
    grp, zone = await _zone(db_session)
    db_session.add(
        DNSRecord(
            zone_id=zone.id,
            fqdn="_mta-sts.apply.test.",
            name="_mta-sts",
            record_type="CNAME",
            value="elsewhere.test.",
        )
    )
    await db_session.commit()
    pre = await client.post(
        _url(grp, zone, "/preview"),
        headers=_bearer(admin),
        json={"template_id": "mta-sts", "params": {"policy_id": "20261118"}},
    )
    assert pre.status_code == 200, pre.text
    (c,) = _by(pre.json()["items"], "conflict")
    assert c["name"] == "_mta-sts" and "CNAME" in c["reason"]


async def test_new_catalog_templates_materialise(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    admin = await _user(db_session, None, superadmin=True)
    grp, zone = await _zone(db_session)
    await db_session.commit()
    h = _bearer(admin)
    r = await client.post(
        _url(grp, zone),
        headers=h,
        json={
            "template_id": "caa",
            "params": {"ca_domain": "letsencrypt.org", "iodef": "mailto:s@apply.test"},
        },
    )
    assert r.status_code == 201, r.text
    r = await client.post(
        _url(grp, zone),
        headers=h,
        json={"template_id": "tls-rpt", "params": {"rua": "mailto:t@apply.test"}},
    )
    assert r.status_code == 201, r.text
    vals = {(x.name, x.record_type): x.value for x in await _rows(db_session, zone)}
    assert vals[("_smtp._tls", "TXT")] == "v=TLSRPTv1; rua=mailto:t@apply.test"
    caa = [x.value for x in await _rows(db_session, zone) if x.record_type == "CAA"]
    assert sorted(caa) == ['0 iodef "mailto:s@apply.test"', '0 issue "letsencrypt.org"']
    cat = (await client.get("/api/v1/dns/zone-templates", headers=h)).json()["templates"]
    caa_t = next(t for t in cat if t["id"] == "caa")
    assert caa_t["source"].endswith("rfc8659") and caa_t["version"] == "1"


async def test_bad_input(client: AsyncClient, db_session: AsyncSession) -> None:
    admin = await _user(db_session, None, superadmin=True)
    grp, zone = await _zone(db_session)
    await db_session.commit()
    h = _bearer(admin)
    r = await client.post(_url(grp, zone, "/preview"), headers=h, json={"template_id": "nope"})
    assert r.status_code == 404
    r = await client.post(
        _url(grp, zone, "/preview"), headers=h, json={"template_id": "mail-basic", "params": {}}
    )
    assert r.status_code == 422


async def test_rbac_matrix(client: AsyncClient, db_session: AsyncSession) -> None:
    viewer = await _user(db_session, [{"action": "read", "resource_type": "*"}])
    editor = await _user(
        db_session,
        [
            {"action": "read", "resource_type": "*"},
            {"action": "write", "resource_type": "dns_record"},
        ],
    )
    zone_writer_only = await _user(
        db_session,
        [
            {"action": "read", "resource_type": "*"},
            {"action": "write", "resource_type": "dns_zone"},
        ],
    )
    admin = await _user(db_session, None, superadmin=True)
    grp, zone = await _zone(db_session)
    grp2, other = await _zone(db_session, "other.test.")
    raw, _p, token_hash = generate_api_token()
    db_session.add(
        APIToken(
            name="scoped",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=[],
            resource_grants=[
                {"action": "write", "resource_type": "dns_zone", "resource_id": str(other.id)},
                {"action": "write", "resource_type": "dns_record"},
                {"action": "read", "resource_type": "dns_record"},
                {"action": "read", "resource_type": "dns_group"},
            ],
            user_id=admin.id,
            created_by_user_id=admin.id,
            is_active=True,
        )
    )
    await db_session.commit()

    for who, preview, apply in [
        (viewer, 403, 403),
        (zone_writer_only, 403, 403),
        (editor, 200, 201),
    ]:
        h = _bearer(who)
        a = await client.post(_url(grp, zone, "/preview"), headers=h, json=MAIL)
        assert a.status_code == preview, (a.status_code, a.text)
        b = await client.post(_url(grp, zone), headers=h, json=MAIL)
        assert b.status_code == apply, (b.status_code, b.text)
        if apply == 201:
            # editor wrote them; clear for the next actor
            for r in await _rows(db_session, zone):
                await db_session.delete(r)
            await db_session.commit()

    tok = {"Authorization": f"Bearer {raw}"}
    a = await client.post(_url(grp, zone, "/preview"), headers=tok, json=MAIL)
    b = await client.post(_url(grp, zone), headers=tok, json=MAIL)
    assert a.status_code == 403 and b.status_code == 403, (a.text, b.text)
    assert await _rows(db_session, zone) == []
    ok = await client.post(_url(grp2, other), headers=tok, json=MAIL)
    assert ok.status_code == 201, ok.text


async def test_copilot_preview_tool_is_read_only(db_session: AsyncSession) -> None:
    from app.services.ai.tools.dns import (
        FindZoneTemplatesArgs,
        PreviewZoneTemplateArgs,
        find_zone_templates,
        preview_zone_template,
    )

    admin = await _user(db_session, None, superadmin=True)
    _, zone = await _zone(db_session)
    await db_session.commit()
    found = await find_zone_templates(db_session, admin, FindZoneTemplatesArgs(search="caa"))
    assert [t["id"] for t in found] == ["caa"]
    out = await preview_zone_template(
        db_session,
        admin,
        PreviewZoneTemplateArgs(
            zone_id=zone.id, template_id=MAIL["template_id"], params=MAIL["params"]
        ),
    )
    assert out["add"] == 3
    assert await _rows(db_session, zone) == []
    bad = await preview_zone_template(
        db_session,
        admin,
        PreviewZoneTemplateArgs(zone_id=zone.id, template_id="mail-basic", params={}),
    )
    assert "required" in bad["error"]
