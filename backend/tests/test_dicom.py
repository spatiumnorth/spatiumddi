"""DICOM AE Title registry tests — issue #723 (part of #543).

Two load-bearing areas.

**The unique-title constraint.** AE Titles are institution-wide-unique by
specification (PS3.15 Annex H), and a duplicate breaks C-MOVE, Storage
Commitment and Modality Worklist in ways that take days to trace. The
registry has to answer a collision with a 409 naming the AE that already
holds the title, not a raw ``IntegrityError`` surfacing as a 500.

**The AE value representation.** 16 *bytes*, spaces legal as padding,
all-space forbidden, no backslash, no control characters. Getting this
wrong in the strict direction is the failure the registry exists to
prevent, arriving from our own validator: a title real devices use gets
rejected, so the recorded plan fails at commissioning.

Also covers the nullable-anchor reservation semantics (the deliberate
difference from BACnet's CASCADE), the peer/impact surface, the CSV
importer, and the ``network.dicom`` feature-module gate.
"""

from __future__ import annotations

import csv
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.dicom import DICOMApplicationEntity
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services.dicom.titles import (
    AETitleError,
    is_vendor_default,
    validate_ae_title,
)


async def _make_superadmin(db: AsyncSession) -> tuple[User, str]:
    u = User(
        username=f"admin-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="Admin",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return u, create_access_token(str(u.id))


async def _make_user_with_perm(db: AsyncSession, perm: dict | None) -> tuple[User, str]:
    u = User(
        username=f"user-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@x.com",
        display_name="User",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db.add(u)
    await db.flush()
    if perm is not None:
        role = Role(name=f"r-{uuid.uuid4().hex[:6]}", description="", permissions=[perm])
        db.add(role)
        await db.flush()
        group = Group(name=f"g-{uuid.uuid4().hex[:6]}", description="")
        group.roles = [role]
        group.users = [u]
        db.add(group)
        await db.flush()
    return u, create_access_token(str(u.id))


async def _make_subnet(db: AsyncSession, network: str = "10.30.0.0/24") -> Subnet:
    space = IPSpace(name=f"dicom-space-{uuid.uuid4().hex[:8]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, name="b", network="10.30.0.0/16")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, name="s", network=network)
    db.add(subnet)
    await db.flush()
    return subnet


async def _make_ip(db: AsyncSession, subnet: Subnet, addr: str) -> IPAddress:
    ip = IPAddress(subnet_id=subnet.id, address=addr, status="allocated")
    db.add(ip)
    await db.flush()
    return ip


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── AE Title value representation ─────────────────────────────────────


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("CT1", "CT1"),
        # Spaces are legal padding — trimmed, not rejected.
        ("  PACS_MAIN  ", "PACS_MAIN"),
        # Internal spaces are legal and significant enough to keep.
        ("MR SCANNER 2", "MR SCANNER 2"),
        # Hyphens, underscores, digits and mixed case are all fine: there
        # is no alphanumeric-only rule in the VR.
        ("Dept-CT_01", "Dept-CT_01"),
        # Exactly at the 16-byte ceiling.
        ("ABCDEFGHIJKLMNOP", "ABCDEFGHIJKLMNOP"),
    ],
)
def test_valid_ae_titles_are_accepted(raw: str, expected: str) -> None:
    assert validate_ae_title(raw) == expected


@pytest.mark.parametrize(
    "raw,fragment",
    [
        ("", "empty"),
        # All-space is explicitly forbidden by the specification, and
        # after trimming padding it is the same statement as empty.
        ("    ", "empty"),
        # 0x5C is the DICOM multi-value delimiter.
        ("CT\\1", "backslash"),
        ("CT\t1", "control characters"),
        ("ABCDEFGHIJKLMNOPQ", "16 bytes"),
    ],
)
def test_invalid_ae_titles_are_rejected(raw: str, fragment: str) -> None:
    with pytest.raises(AETitleError) as exc:
        validate_ae_title(raw)
    assert fragment in str(exc.value)


async def test_padded_16_byte_title_is_accepted_over_the_api(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A 16-byte title carrying legal pad space must survive the API.

    Regression: a ``max_length=16`` on the pydantic field counted
    *characters* on the *untrimmed* value, so ``"QRSTUVWXYZABCDEF "`` —
    16 significant chars plus one pad space — was rejected before the
    validator ever trimmed it. Spaces are non-significant padding per
    PS3.5, so the ceiling has to be applied after trimming, in bytes.
    That failure is the exact "strict in the wrong direction" mode this
    registry exists to avoid: a title real devices use, refused.
    """
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/dicom/aes",
        headers=_auth(token),
        json={"ae_title": "QRSTUVWXYZABCDEF "},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["ae_title"] == "QRSTUVWXYZABCDEF"


async def test_over_length_title_reports_bytes_over_the_api(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The refusal has to come from the byte validator, so its message
    says "bytes" — an operator counting characters on a multi-byte title
    cannot otherwise see why 15 characters is too long."""
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/dicom/aes",
        headers=_auth(token),
        json={"ae_title": "ÄÖÜÄÖÜÄÖÜÄÖÜÄÖÜ"},
    )
    assert resp.status_code == 422, resp.text
    assert "bytes" in resp.text


def test_length_ceiling_is_bytes_not_characters() -> None:
    """The VR caps at 16 *bytes*. A 16-character title with a non-ASCII
    character in it is over the limit, and an operator counting
    characters will not see why unless the message says bytes."""
    fifteen_chars_seventeen_bytes = "ÄÖÜÄÖÜÄÖÜÄÖÜÄÖÜ"  # 15 chars, 30 bytes
    with pytest.raises(AETitleError) as exc:
        validate_ae_title(fifteen_chars_seventeen_bytes)
    assert "bytes" in str(exc.value)


def test_vendor_default_detection_is_case_insensitive() -> None:
    """ "Did anyone change this from the box" — a device shipped as
    ANY-SCP and re-typed as Any-SCP is equally un-changed."""
    assert is_vendor_default("DCM4CHEE") is True
    assert is_vendor_default("any-scp") is True
    assert is_vendor_default(" Orthanc ") is True
    assert is_vendor_default("CT1_RADIOLOGY") is False


# ── AE CRUD ───────────────────────────────────────────────────────────


async def test_ae_crud_round_trip(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    ip = await _make_ip(db_session, subnet, "10.30.0.5")
    await db_session.commit()
    headers = _auth(token)

    created = await client.post(
        "/api/v1/dicom/aes",
        headers=headers,
        json={
            "ae_title": "CT1_RAD",
            "ip_address_id": str(ip.id),
            "port": 104,
            "device_class": "modality",
            "role": "both",
            "vendor": "Siemens",
            "model_name": "SOMATOM",
            "department": "Radiology",
        },
    )
    assert created.status_code == 201, created.text
    body = created.json()
    ae_id = body["id"]
    assert body["ae_title"] == "CT1_RAD"
    assert body["address"] == "10.30.0.5"
    # Denormalised copy the per-subnet grouping + conformity read.
    assert body["subnet_id"] == str(subnet.id)
    assert body["is_reservation"] is False
    assert body["is_vendor_default"] is False

    listed = await client.get("/api/v1/dicom/aes", headers=headers)
    assert listed.status_code == 200, listed.text
    assert listed.json()["total"] == 1

    patched = await client.patch(
        f"/api/v1/dicom/aes/{ae_id}",
        headers=headers,
        json={"department": "Radiology (main)", "tls_enabled": True},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["tls_enabled"] is True

    deleted = await client.delete(f"/api/v1/dicom/aes/{ae_id}", headers=headers)
    assert deleted.status_code == 204, deleted.text
    assert (await db_session.scalar(select(func.count()).select_from(DICOMApplicationEntity))) == 0


async def test_duplicate_ae_title_409_names_the_conflicting_ae(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """THE constraint. The conflicting AE is very often in another
    department, owned by another vendor's service engineer, so the
    response has to name it rather than saying "already in use"."""
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    first = await _make_ip(db_session, subnet, "10.30.0.5")
    second = await _make_ip(db_session, subnet, "10.30.0.6")
    await db_session.commit()
    headers = _auth(token)

    a = await client.post(
        "/api/v1/dicom/aes",
        headers=headers,
        json={"ae_title": "PACS_MAIN", "ip_address_id": str(first.id)},
    )
    assert a.status_code == 201, a.text

    b = await client.post(
        "/api/v1/dicom/aes",
        headers=headers,
        json={"ae_title": "PACS_MAIN", "ip_address_id": str(second.id)},
    )
    assert b.status_code == 409, b.text
    assert "PACS_MAIN" in b.json()["detail"]
    assert b.headers["X-Conflicting-Ae-Id"] == a.json()["id"]


async def test_invalid_ae_title_is_422_naming_the_rule(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    resp = await client.post(
        "/api/v1/dicom/aes", headers=_auth(token), json={"ae_title": "BAD\\TITLE"}
    )
    assert resp.status_code == 422, resp.text
    assert "backslash" in resp.text


# ── Reservation semantics ────────────────────────────────────────────


async def test_ae_can_be_created_without_an_anchor(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An unbound AE is a *reservation*, not an error: a title still
    burned into peer config across the estate whose host is gone."""
    _, token = await _make_superadmin(db_session)
    resp = await client.post(
        "/api/v1/dicom/aes", headers=_auth(token), json={"ae_title": "OLD_MR1"}
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["is_reservation"] is True
    assert resp.json()["address"] is None


async def test_deleting_the_ip_demotes_the_ae_to_a_reservation(
    db_session: AsyncSession,
) -> None:
    """The deliberate difference from ``bacnet_device``'s CASCADE.
    Decommissioning a host must not hand its AE Title straight back to
    the next commissioning engineer."""
    subnet = await _make_subnet(db_session)
    ip = await _make_ip(db_session, subnet, "10.30.0.5")
    ae = DICOMApplicationEntity(ae_title="MR1_MAIN", ip_address_id=ip.id, subnet_id=subnet.id)
    db_session.add(ae)
    await db_session.flush()
    ae_id = ae.id

    # Raw DELETE so the FK's ON DELETE SET NULL is what is exercised,
    # not any ORM-side cascade configuration.
    await db_session.execute(text("DELETE FROM ip_address WHERE id = :i"), {"i": str(ip.id)})
    await db_session.flush()
    db_session.expire_all()

    survivor = await db_session.get(DICOMApplicationEntity, ae_id)
    assert survivor is not None, "the AE Title must outlive its host"
    assert survivor.ip_address_id is None


async def test_patch_can_clear_the_anchor(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    ip = await _make_ip(db_session, subnet, "10.30.0.5")
    await db_session.commit()
    headers = _auth(token)

    created = await client.post(
        "/api/v1/dicom/aes",
        headers=headers,
        json={"ae_title": "US1_MAIN", "ip_address_id": str(ip.id)},
    )
    assert created.status_code == 201, created.text

    cleared = await client.patch(
        f"/api/v1/dicom/aes/{created.json()['id']}",
        headers=headers,
        json={"ip_address_id": None},
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["is_reservation"] is True
    assert cleared.json()["subnet_id"] is None


async def test_unbound_filter_lists_only_reservations(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    ip = await _make_ip(db_session, subnet, "10.30.0.5")
    db_session.add_all(
        [
            DICOMApplicationEntity(ae_title="BOUND1", ip_address_id=ip.id, subnet_id=subnet.id),
            DICOMApplicationEntity(ae_title="RESERVED1"),
        ]
    )
    await db_session.commit()

    resp = await client.get("/api/v1/dicom/aes", headers=_auth(token), params={"unbound": "true"})
    assert resp.status_code == 200, resp.text
    assert [r["ae_title"] for r in resp.json()["items"]] == ["RESERVED1"]


# ── Peers + impact ───────────────────────────────────────────────────


async def test_peer_round_trip_and_impact_splits_by_direction(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Direction is the point: outbound edges stop sending, inbound ones
    lose their target — different remediation lists."""
    _, token = await _make_superadmin(db_session)
    db_session.add_all(
        [
            DICOMApplicationEntity(ae_title="CT1"),
            DICOMApplicationEntity(ae_title="ARCHIVE"),
            DICOMApplicationEntity(ae_title="VIEWER"),
        ]
    )
    await db_session.commit()
    headers = _auth(token)

    ids = {
        r["ae_title"]: r["id"]
        for r in (await client.get("/api/v1/dicom/aes", headers=headers)).json()["items"]
    }

    made = await client.post(
        "/api/v1/dicom/peers",
        headers=headers,
        json={
            "source_ae_id": ids["CT1"],
            "target_ae_id": ids["ARCHIVE"],
            "services": ["C-STORE"],
        },
    )
    assert made.status_code == 201, made.text
    assert made.json()["source_ae_title"] == "CT1"
    assert made.json()["target_ae_title"] == "ARCHIVE"

    inbound = await client.post(
        "/api/v1/dicom/peers",
        headers=headers,
        json={"source_ae_id": ids["VIEWER"], "target_ae_id": ids["CT1"]},
    )
    assert inbound.status_code == 201, inbound.text

    impact = await client.get(f"/api/v1/dicom/aes/{ids['CT1']}/impact", headers=headers)
    assert impact.status_code == 200, impact.text
    body = impact.json()
    assert body["total_peers"] == 2
    assert [p["target_ae_title"] for p in body["outbound"]] == ["ARCHIVE"]
    assert [p["source_ae_title"] for p in body["inbound"]] == ["VIEWER"]


async def test_duplicate_peer_pair_is_409(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_superadmin(db_session)
    db_session.add_all(
        [DICOMApplicationEntity(ae_title="A1"), DICOMApplicationEntity(ae_title="B1")]
    )
    await db_session.commit()
    headers = _auth(token)
    ids = {
        r["ae_title"]: r["id"]
        for r in (await client.get("/api/v1/dicom/aes", headers=headers)).json()["items"]
    }
    payload = {"source_ae_id": ids["A1"], "target_ae_id": ids["B1"]}

    assert (
        await client.post("/api/v1/dicom/peers", headers=headers, json=payload)
    ).status_code == 201
    dupe = await client.post("/api/v1/dicom/peers", headers=headers, json=payload)
    assert dupe.status_code == 409, dupe.text


async def test_self_peer_is_refused(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_superadmin(db_session)
    db_session.add(DICOMApplicationEntity(ae_title="SOLO"))
    await db_session.commit()
    headers = _auth(token)
    ae_id = (await client.get("/api/v1/dicom/aes", headers=headers)).json()["items"][0]["id"]
    resp = await client.post(
        "/api/v1/dicom/peers",
        headers=headers,
        json={"source_ae_id": ae_id, "target_ae_id": ae_id},
    )
    assert resp.status_code == 422, resp.text


# ── Importer ─────────────────────────────────────────────────────────

_CSV = """AE Title,IP,Port,Class,Vendor,Dept
CT1_RAD,10.30.0.5,104,CT,Siemens,Radiology
PACS_MAIN,10.30.0.6,11112,PACS Archive,Philips,IT
OLD_MR,,11112,MR,GE,Radiology
"""

_COLUMN_MAP = {
    "ae_title": "AE Title",
    "address": "IP",
    "port": "Port",
    "device_class": "Class",
    "vendor": "Vendor",
    "department": "Dept",
}


async def test_import_preview_then_commit(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    await _make_ip(db_session, subnet, "10.30.0.5")
    await _make_ip(db_session, subnet, "10.30.0.6")
    await db_session.commit()
    headers = _auth(token)
    body = {"csv_text": _CSV, "column_map": _COLUMN_MAP}

    preview = await client.post("/api/v1/dicom/aes/import/preview", headers=headers, json=body)
    assert preview.status_code == 200, preview.text
    # Three creates: two bound, and OLD_MR as an unbound reservation —
    # a blank address is not an error.
    assert preview.json()["create_count"] == 3
    assert preview.json()["error_count"] == 0
    # Preview writes nothing.
    assert (await db_session.scalar(select(func.count()).select_from(DICOMApplicationEntity))) == 0

    commit = await client.post("/api/v1/dicom/aes/import/commit", headers=headers, json=body)
    assert commit.status_code == 201, commit.text
    assert commit.json()["created"] == 3

    rows = (await client.get("/api/v1/dicom/aes", headers=headers)).json()["items"]
    by_title = {r["ae_title"]: r for r in rows}
    assert by_title["CT1_RAD"]["port"] == 104
    # "CT" and "PACS Archive" are aliased onto the vocabulary rather
    # than rejected — institutions name their columns locally.
    assert by_title["CT1_RAD"]["device_class"] == "modality"
    assert by_title["PACS_MAIN"]["device_class"] == "archive"
    assert by_title["OLD_MR"]["is_reservation"] is True


async def test_import_reports_duplicate_titles_in_the_file(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A duplicate inside the file is the exact collision this registry
    exists to surface — reported, not resolved by last-write-wins."""
    _, token = await _make_superadmin(db_session)
    csv = "AE Title\nCT1\nCT1\n"
    resp = await client.post(
        "/api/v1/dicom/aes/import/preview",
        headers=_auth(token),
        json={"csv_text": csv, "column_map": {"ae_title": "AE Title"}},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["error_count"] == 1
    errored = [r for r in resp.json()["rows"] if r["action"] == "error"]
    assert "duplicate AE Title" in errored[0]["reason"]


async def test_import_rejects_a_mapped_column_missing_from_the_header(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A typo'd mapping must not look like a successful import that
    quietly dropped a column."""
    _, token = await _make_superadmin(db_session)
    resp = await client.post(
        "/api/v1/dicom/aes/import/preview",
        headers=_auth(token),
        json={
            "csv_text": "AE Title\nCT1\n",
            "column_map": {"ae_title": "AE Title", "vendor": "Manufacturer"},
        },
    )
    assert resp.status_code == 422, resp.text
    assert "Manufacturer" in resp.json()["detail"]


async def test_import_errors_an_unknown_address_but_keeps_good_rows(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_superadmin(db_session)
    subnet = await _make_subnet(db_session)
    await _make_ip(db_session, subnet, "10.30.0.5")
    await db_session.commit()
    csv = "AE Title,IP\nGOOD1,10.30.0.5\nBAD1,10.99.99.99\n"

    resp = await client.post(
        "/api/v1/dicom/aes/import/commit",
        headers=_auth(token),
        json={"csv_text": csv, "column_map": {"ae_title": "AE Title", "address": "IP"}},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["created"] == 1
    assert resp.json()["errors"] == 1


async def test_reimport_without_tls_column_does_not_reset_tls(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """An overwrite re-import from a table lacking TLS / port columns
    must leave those alone. Flipping every encrypted AE to plaintext
    would poison ``dicom_ae_no_tls`` — a compliance report reading worse
    than reality is its own wrong answer."""
    _, token = await _make_superadmin(db_session)
    db_session.add(DICOMApplicationEntity(ae_title="MR1", port=2762, tls_enabled=True))
    await db_session.commit()
    headers = _auth(token)

    resp = await client.post(
        "/api/v1/dicom/aes/import/commit",
        headers=headers,
        json={
            "csv_text": "AE Title,Vendor\nMR1,Philips\n",
            "column_map": {"ae_title": "AE Title", "vendor": "Vendor"},
            "overwrite_existing": True,
        },
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["updated"] == 1

    row = (await client.get("/api/v1/dicom/aes", headers=headers)).json()["items"][0]
    assert row["vendor"] == "Philips"
    assert row["tls_enabled"] is True, "a missing TLS column must not mean 'false'"
    assert row["port"] == 2762, "a missing port column must not mean 'the default'"


async def test_blank_tls_cell_does_not_clear_a_stored_true(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """ "The operator left this blank" and "the operator wrote no" are
    different statements; only the second overwrites."""
    _, token = await _make_superadmin(db_session)
    db_session.add(DICOMApplicationEntity(ae_title="CT9", tls_enabled=True))
    await db_session.commit()
    headers = _auth(token)

    resp = await client.post(
        "/api/v1/dicom/aes/import/commit",
        headers=headers,
        json={
            "csv_text": "AE Title,TLS\nCT9,\n",
            "column_map": {"ae_title": "AE Title", "tls_enabled": "TLS"},
            "overwrite_existing": True,
        },
    )
    assert resp.status_code == 201, resp.text
    row = (await client.get("/api/v1/dicom/aes", headers=headers)).json()["items"][0]
    assert row["tls_enabled"] is True

    # An explicit "no" *does* overwrite.
    resp = await client.post(
        "/api/v1/dicom/aes/import/commit",
        headers=headers,
        json={
            "csv_text": "AE Title,TLS\nCT9,no\n",
            "column_map": {"ae_title": "AE Title", "tls_enabled": "TLS"},
            "overwrite_existing": True,
        },
    )
    assert resp.status_code == 201, resp.text
    row = (await client.get("/api/v1/dicom/aes", headers=headers)).json()["items"][0]
    assert row["tls_enabled"] is False


@pytest.mark.parametrize("eol", ["\n", "\r\n", "\r"], ids=["LF", "CRLF", "CR"])
async def test_import_reads_every_line_ending(
    eol: str, client: AsyncClient, db_session: AsyncSession
) -> None:
    """A table saved with classic Mac line endings (a bare carriage return
    between rows) imports like any other (#1370). The CR reached the csv
    reader inside an unquoted field, and preview and commit answered 500."""
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    headers = _auth(token)
    body = {
        "csv_text": eol.join(["AE Title,Vendor", "CT1,Siemens", "MR1,GE"]) + eol,
        "column_map": {"ae_title": "AE Title", "vendor": "Vendor"},
    }

    preview = await client.post("/api/v1/dicom/aes/import/preview", headers=headers, json=body)
    assert preview.status_code == 200, preview.text
    assert [(r["ae_title"], r["action"]) for r in preview.json()["rows"]] == [
        ("CT1", "create"),
        ("MR1", "create"),
    ]

    commit = await client.post("/api/v1/dicom/aes/import/commit", headers=headers, json=body)
    assert commit.status_code == 201, commit.text
    rows = (await client.get("/api/v1/dicom/aes", headers=headers)).json()["items"]
    assert {r["ae_title"]: r["vendor"] for r in rows} == {"CT1": "Siemens", "MR1": "GE"}


async def test_import_answers_422_when_the_csv_reader_refuses_the_text(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Whatever else the csv reader refuses is a 422 that says why, not a
    500 (#1370): here a cell over the reader's field size limit, well
    inside the body cap."""
    _, token = await _make_superadmin(db_session)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/dicom/aes/import/preview",
        headers=_auth(token),
        json={
            "csv_text": "AE Title,Notes\nCT1," + "x" * (csv.field_size_limit() + 1) + "\n",
            "column_map": {"ae_title": "AE Title"},
        },
    )
    assert resp.status_code == 422, resp.text[:300]
    assert resp.json()["detail"].startswith("CSV could not be read"), resp.json()["detail"]


# ── Permissions + module gate ────────────────────────────────────────


async def test_requires_dicom_ae_permission(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user_with_perm(db_session, None)
    await db_session.commit()
    resp = await client.get("/api/v1/dicom/aes", headers=_auth(token))
    assert resp.status_code == 403, resp.text


async def test_module_gate_404s_the_surface_when_disabled(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    from app.services.feature_modules import invalidate_cache

    _, token = await _make_superadmin(db_session)
    await db_session.execute(
        text(
            "INSERT INTO feature_module (id, enabled) VALUES (:id, false) "
            "ON CONFLICT (id) DO UPDATE SET enabled = false"
        ).bindparams(id="network.dicom")
    )
    await db_session.commit()
    invalidate_cache()
    try:
        resp = await client.get("/api/v1/dicom/aes", headers=_auth(token))
        assert resp.status_code == 404, resp.text
    finally:
        await db_session.execute(
            text("UPDATE feature_module SET enabled = true WHERE id = :id").bindparams(
                id="network.dicom"
            )
        )
        await db_session.commit()
        invalidate_cache()
