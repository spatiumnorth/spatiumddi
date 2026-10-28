"""spatiumddi#2915 / #2916 / #2917 — every zone write path runs the zone rules.

From-template skipped the zone name / type rules and the record API's rules;
the zone dialog's Admin Email had no host-name rule (BIND then refused the
zone); and zone create / edit / from-template stored another group's view.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dns import DNSRecord, DNSServerGroup, DNSView, DNSZone


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"u2915-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="admin",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _group(db: AsyncSession, view_name: str | None = None):
    grp = DNSServerGroup(name=f"g2915-{uuid.uuid4().hex[:6]}")
    db.add(grp)
    await db.flush()
    view = None
    if view_name:
        view = DNSView(group_id=grp.id, name=view_name)
        db.add(view)
        await db.flush()
    return grp, view


def _tpl(grp: DNSServerGroup) -> str:
    return f"/api/v1/dns/groups/{grp.id}/zones/from-template"


def _zones(grp: DNSServerGroup) -> str:
    return f"/api/v1/dns/groups/{grp.id}/zones"


async def _count_zones(db: AsyncSession, grp: DNSServerGroup) -> int:
    return len(
        (await db.execute(select(DNSZone.id).where(DNSZone.group_id == grp.id))).scalars().all()
    )


# ── #2915 ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "name",
    ["tpl..example.test", "-tpl.example.test", "a" * 64 + ".example.test"],
)
async def test_template_refuses_bad_zone_names(
    client: AsyncClient, db_session: AsyncSession, name: str
) -> None:
    headers = await _headers(db_session)
    grp, _ = await _group(db_session)
    await db_session.commit()
    resp = await client.post(
        _tpl(grp),
        headers=headers,
        json={"template_id": "web-basic", "zone_name": name, "params": {"origin_ip": "192.0.2.1"}},
    )
    assert resp.status_code == 422, resp.text
    assert await _count_zones(db_session, grp) == 0
    # Same name through zone create is refused too (parity).
    assert (await client.post(_zones(grp), headers=headers, json={"name": name})).status_code == 422


async def test_template_refuses_bogus_zone_type(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp, _ = await _group(db_session)
    await db_session.commit()
    resp = await client.post(
        _tpl(grp),
        headers=headers,
        json={
            "template_id": "web-basic",
            "zone_name": "ok.example.test",
            "zone_type": "bogus",
            "params": {"origin_ip": "192.0.2.1"},
        },
    )
    assert resp.status_code == 422
    assert "zone_type" in resp.text
    assert await _count_zones(db_session, grp) == 0


@pytest.mark.parametrize(
    "template,params,needle",
    [
        ("web-basic", {"origin_ip": "not-an-ip"}, "IPv4"),
        (
            "mail-basic",
            {"mx_host": "mail.example.net.", "dkim_selector": "bad selector"},
            "bad selector",
        ),
    ],
)
async def test_template_refuses_values_the_record_api_refuses(
    client: AsyncClient,
    db_session: AsyncSession,
    template: str,
    params: dict[str, str],
    needle: str,
) -> None:
    headers = await _headers(db_session)
    grp, _ = await _group(db_session)
    await db_session.commit()
    resp = await client.post(
        _tpl(grp),
        headers=headers,
        json={"template_id": template, "zone_name": "tp.example.test", "params": params},
    )
    assert resp.status_code == 422, resp.text
    assert needle in resp.text
    # Nothing written: no zone, no records.
    assert await _count_zones(db_session, grp) == 0
    assert (await db_session.execute(select(DNSRecord.id))).first() is None


async def test_every_template_still_creates_with_its_placeholders(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Positive control — the shipped catalogue is not broken by the new rules."""
    catalog = json.loads(
        (Path(__file__).parent.parent / "app" / "data" / "dns_zone_templates.json").read_text()
    )
    templates = catalog["templates"] if isinstance(catalog, dict) else catalog
    headers = await _headers(db_session)
    grp, _ = await _group(db_session)
    await db_session.commit()
    assert len(templates) >= 4
    created = 0
    for i, t in enumerate(templates):
        # Twice per template: only the required parameters, then every
        # parameter, so the records behind optional ones (DMARC, DKIM, the
        # AAAA, the AD site records) are held to the rules too.
        for j, only_required in enumerate((True, False)):
            params = {
                p["key"]: (p.get("default") or p.get("placeholder") or "192.0.2.1")
                for p in t["parameters"]
                if p.get("required") or not only_required
            }
            resp = await client.post(
                _tpl(grp),
                headers=headers,
                json={
                    "template_id": t["id"],
                    "zone_name": f"t{i}-{j}.example.test",
                    "params": params,
                },
            )
            # A placeholder that is not a legal value for its own template is
            # a test-data problem, so report which one.
            assert resp.status_code == 201, (t["id"], params, resp.text)
            created += 1
    assert created == 2 * len(templates)
    # Every record a template materialised was written.
    assert (await db_session.execute(select(DNSRecord.id))).first() is not None


@pytest.mark.parametrize("zone_type", ["secondary", "stub", "forward"])
async def test_template_refuses_a_zone_type_that_serves_no_records(
    client: AsyncClient, db_session: AsyncSession, zone_type: str
) -> None:
    """A secondary / stub zone made here would have no masters (zone create
    refuses that), and none of the three serves the template's records."""
    headers = await _headers(db_session)
    grp, _ = await _group(db_session)
    await db_session.commit()
    resp = await client.post(
        _tpl(grp),
        headers=headers,
        json={
            "template_id": "web-basic",
            "zone_name": "zt.example.test",
            "zone_type": zone_type,
            "params": {"origin_ip": "192.0.2.1"},
        },
    )
    assert resp.status_code == 422, resp.text
    assert "zone_type" in resp.text
    assert await _count_zones(db_session, grp) == 0


async def test_template_creates_valid_zone(client: AsyncClient, db_session: AsyncSession) -> None:
    headers = await _headers(db_session)
    grp, _ = await _group(db_session)
    await db_session.commit()
    resp = await client.post(
        _tpl(grp),
        headers=headers,
        json={
            "template_id": "web-basic",
            "zone_name": "Good.Example.Test",
            "params": {"origin_ip": "192.0.2.1"},
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["name"] == "good.example.test."


# ── #2916 ──────────────────────────────────────────────────────────────────


# Measured against named-checkzone 9.20 (-k fail): BIND reads the RNAME as a
# mailbox — any printable local part, then host-name labels. The single label
# loads in BIND but names a mailbox at the root, refused as for Primary NS.
ADMIN_EMAIL_BAD = [
    "hostmaster.under_score.rn.example.test.",  # BIND: bad name (check-names)
    "hostmaster.-lead.example.test.",  # BIND: bad name (check-names)
    "hostmaster.trail-.example.test.",  # BIND: bad name (check-names)
    "hostmaster." + "a" * 64 + ".test.",  # BIND: label too long
    "a" * 64 + ".example.test.",  # BIND: label too long
    "hostmaster",
    "hostmaster.",
    "hostmaster..example.test.",
    "hostmaster@example.test",
    # BIND loads an escaped dot in the local part, but a backslash is
    # zone-file syntax the SOA fields have refused since #597.
    "first\\.last.example.test.",
    "hostmaster.b\u00fccher.example.",
]
ADMIN_EMAIL_GOOD = [
    "hostmaster.rn.example.test.",
    "hostmaster.rn.example.test",
    "dns-admin.example.test.",
    "dns_admin.example.test.",
    "host_master.example.test",
    "admin+dns.example.test.",
    "a!b.example.test.",
    "first.last.example.test.",
    "hostmaster.xn--bcher-kva.example.",
    "",
]


def test_admin_email_rule_vectors() -> None:
    from app.core.dns_names import admin_email_error

    for bad in ADMIN_EMAIL_BAD:
        assert admin_email_error(bad) is not None, bad
    for good in ADMIN_EMAIL_GOOD:
        assert admin_email_error(good) is None, good


@pytest.mark.parametrize(
    "value",
    [
        "hostmaster.under_score.rn.example.test.",
        "hostmaster",
        "hostmaster." + "a" * 64 + ".test.",
    ],
)
async def test_admin_email_must_be_a_mailbox_name(
    client: AsyncClient, db_session: AsyncSession, value: str
) -> None:
    headers = await _headers(db_session)
    grp, _ = await _group(db_session)
    await db_session.commit()
    resp = await client.post(
        _zones(grp), headers=headers, json={"name": "rn.example.test", "admin_email": value}
    )
    assert resp.status_code == 422, resp.text
    assert "admin_email" in resp.text
    assert await _count_zones(db_session, grp) == 0


@pytest.mark.parametrize(
    "value",
    ["hostmaster.rn.example.test.", "host_master.example.test", "admin+dns.example.test.", ""],
)
async def test_admin_email_valid_forms_pass(
    client: AsyncClient, db_session: AsyncSession, value: str
) -> None:
    from app.core.dns_names import admin_email_error

    assert admin_email_error(value) is None
    headers = await _headers(db_session)
    grp, _ = await _group(db_session)
    await db_session.commit()
    resp = await client.post(
        _zones(grp), headers=headers, json={"name": "rn.example.test", "admin_email": value}
    )
    assert resp.status_code == 201, resp.text


async def test_admin_email_update_holds_changed_value_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp, _ = await _group(db_session)
    legacy = DNSZone(
        group_id=grp.id,
        name="legacy.example.test.",
        zone_type="primary",
        kind="forward",
        admin_email="host.under_score.example.test.",
    )
    db_session.add(legacy)
    await db_session.commit()
    url = f"{_zones(grp)}/{legacy.id}"
    # Re-sending the stored value alongside another change stays editable.
    ok = await client.put(
        url, headers=headers, json={"admin_email": legacy.admin_email, "ttl": 600}
    )
    assert ok.status_code == 200, ok.text
    # The dialog re-sends every field on save: an edit of any of them keeps
    # the legacy Admin Email it does not change.
    full = {
        "admin_email": legacy.admin_email,
        "primary_ns": "",
        "ttl": 900,
        "refresh": 7200,
        "retry": 1800,
        "expire": 1209600,
        "minimum": 600,
        "color": "",
        "tags": {"k": "v"},
    }
    again = await client.put(url, headers=headers, json=full)
    assert again.status_code == 200, again.text
    bad = await client.put(url, headers=headers, json={"admin_email": "hostmaster"})
    assert bad.status_code == 422
    assert "admin_email" in bad.text


# ── #2917 ──────────────────────────────────────────────────────────────────


async def test_zone_create_refuses_a_view_of_another_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp_a, _ = await _group(db_session)
    _, view_b = await _group(db_session, "v2")
    await db_session.commit()
    resp = await client.post(
        _zones(grp_a),
        headers=headers,
        json={"name": "l14.example.test", "view_id": str(view_b.id)},
    )
    assert resp.status_code == 422
    assert "view_id does not name a view in this zone's server group" in resp.text
    assert await _count_zones(db_session, grp_a) == 0


async def test_zone_update_refuses_a_view_of_another_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp_a, _ = await _group(db_session)
    _, view_b = await _group(db_session, "v2")
    zone = DNSZone(group_id=grp_a.id, name="u.example.test.", zone_type="primary", kind="forward")
    db_session.add(zone)
    await db_session.commit()
    resp = await client.put(
        f"{_zones(grp_a)}/{zone.id}", headers=headers, json={"view_id": str(view_b.id)}
    )
    assert resp.status_code == 422
    assert "view_id does not name a view" in resp.text
    await db_session.refresh(zone)
    assert zone.view_id is None


async def test_template_refuses_a_view_of_another_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp_a, _ = await _group(db_session)
    _, view_b = await _group(db_session, "v2")
    await db_session.commit()
    resp = await client.post(
        _tpl(grp_a),
        headers=headers,
        json={
            "template_id": "web-basic",
            "zone_name": "vt.example.test",
            "view_id": str(view_b.id),
            "params": {"origin_ip": "192.0.2.1"},
        },
    )
    assert resp.status_code == 422
    assert await _count_zones(db_session, grp_a) == 0


async def test_own_group_view_is_accepted_everywhere(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session)
    grp, view = await _group(db_session, "internal")
    other = DNSZone(group_id=grp.id, name="o.example.test.", zone_type="primary", kind="forward")
    db_session.add(other)
    await db_session.commit()
    r1 = await client.post(
        _zones(grp), headers=headers, json={"name": "a.example.test", "view_id": str(view.id)}
    )
    assert r1.status_code == 201, r1.text
    r2 = await client.put(
        f"{_zones(grp)}/{other.id}", headers=headers, json={"view_id": str(view.id)}
    )
    assert r2.status_code == 200, r2.text
    r3 = await client.post(
        _tpl(grp),
        headers=headers,
        json={
            "template_id": "web-basic",
            "zone_name": "t.example.test",
            "view_id": str(view.id),
            "params": {"origin_ip": "192.0.2.1"},
        },
    )
    assert r3.status_code == 201, r3.text
