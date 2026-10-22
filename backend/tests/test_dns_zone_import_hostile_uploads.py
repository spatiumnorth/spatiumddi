"""#2139 / #2166 walk case 15 — hostile uploads to the zone record import.

A corrupt XLSX, an entity-bomb XLSX, an XLSX over 100 MB uncompressed, a CSV
with over 100k blank rows and a file over 10 MB each answer 422 or 413, never
500 and never a hang; a UTF-16 CSV imports. Every file is generated here
(nothing large is committed) and posted to BOTH the preview and the commit
route through the real app.
"""

from __future__ import annotations

import io
import os
import time
import zipfile

import pytest
from httpx import AsyncClient
from openpyxl import Workbook
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSRecord
from tests.test_dns_zone_spreadsheet_2139 import (
    COLS,
    ZONE,
    _base,
    _headers,
    _zone,
)

XLSX_CT = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
# Bound for the bomb cases: they must be refused up front, not ground through.
MAX_SECONDS = 15.0


def _valid_xlsx() -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = "records"
    ws.append(COLS)
    ws.append(["", "www", "A", "300", "192.0.2.1"] + [""] * (len(COLS) - 5))
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _rewrite(data: bytes, replace: dict[str, bytes], add: dict[str, bytes] | None = None) -> bytes:
    out = io.BytesIO()
    with (
        zipfile.ZipFile(io.BytesIO(data)) as zin,
        zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zout,
    ):
        for info in zin.infolist():
            zout.writestr(info.filename, replace.get(info.filename, zin.read(info.filename)))
        for name, body in (add or {}).items():
            zout.writestr(name, body)
    return out.getvalue()


def _sheet_name(data: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return next(n for n in z.namelist() if n.startswith("xl/worksheets/sheet"))


def _corrupt_random() -> bytes:
    return os.urandom(4096)


def _corrupt_truncated() -> bytes:
    good = _valid_xlsx()
    return good[: len(good) // 2]


def _corrupt_bad_sheet_xml() -> bytes:
    good = _valid_xlsx()
    return _rewrite(good, {_sheet_name(good): b"<worksheet><sheetData><row"})


def _entity_bomb() -> bytes:
    good = _valid_xlsx()
    lols = ['<!ENTITY lol0 "lol">']
    for i in range(1, 10):
        prev = f"&lol{i - 1};"
        lols.append(f'<!ENTITY lol{i} "{prev * 10}">')
    xml = (
        '<?xml version="1.0"?><!DOCTYPE worksheet [' + "".join(lols) + "]>"
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>&lol9;</t></is></c></row>'
        "</sheetData></worksheet>"
    ).encode()
    return _rewrite(good, {_sheet_name(good): xml})


def _xml_external_entity() -> bytes:
    good = _valid_xlsx()
    xml = (
        b'<?xml version="1.0"?><!DOCTYPE worksheet [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        b'<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>&x;</t></is></c></row>'
        b"</sheetData></worksheet>"
    )
    return _rewrite(good, {_sheet_name(good): xml})


def _zip_bomb_xlsx() -> bytes:
    """~150 MB uncompressed, ~150 KB on the wire."""
    return _rewrite(_valid_xlsx(), {}, {"xl/padding.bin": b"\0" * (150 * 1024 * 1024)})


def _blank_row_csv() -> bytes:
    return (",".join(COLS) + "\n" + ",\n" * 150_000).encode()


def _oversize_csv() -> bytes:
    return (",".join(COLS) + "\n" + "x" * (10 * 1024 * 1024 + 1024)).encode()


def _oversize_xlsx() -> bytes:
    # Incompressible, so the 10 MB cap (not the uncompressed one) is what trips.
    return _rewrite(_valid_xlsx(), {}, {"xl/blob.bin": os.urandom(11 * 1024 * 1024)})


CASES = [
    ("corrupt-random", "x.xlsx", _corrupt_random, (422,)),
    ("corrupt-truncated", "x.xlsx", _corrupt_truncated, (422,)),
    ("corrupt-sheet-xml", "x.xlsx", _corrupt_bad_sheet_xml, (422,)),
    ("entity-bomb", "x.xlsx", _entity_bomb, (422,)),
    ("external-entity", "x.xlsx", _xml_external_entity, (422,)),
    ("zip-bomb", "x.xlsx", _zip_bomb_xlsx, (422, 413)),
    ("blank-rows-csv", "x.csv", _blank_row_csv, (422,)),
    ("oversize-csv", "x.csv", _oversize_csv, (413,)),
    ("oversize-xlsx", "x.xlsx", _oversize_xlsx, (413,)),
    ("garbage-as-csv", "x.csv", lambda: os.urandom(8192), (200, 422)),
    ("bad-utf16-csv", "x.csv", lambda: b"\xff\xfe" + b"a\x00b", (200, 422)),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("route", ["preview", "commit"])
@pytest.mark.parametrize("label,filename,make,expected", CASES, ids=[c[0] for c in CASES])
async def test_hostile_upload_is_refused_not_500(
    client: AsyncClient,
    db_session: AsyncSession,
    route: str,
    label: str,
    filename: str,
    make,
    expected: tuple[int, ...],
) -> None:
    h = await _headers(db_session)
    grp, zone, _ = await _zone(db_session)
    await db_session.commit()
    data = make()
    start = time.monotonic()
    r = await client.post(
        f"{_base(grp, zone)}/import/spreadsheet/{route}",
        headers=h,
        files={"file": (filename, data, XLSX_CT if filename.endswith("xlsx") else "text/csv")},
        data={"mode": "merge"},
    )
    elapsed = time.monotonic() - start
    print(f"HOSTILE {route} {label}: {r.status_code} in {elapsed:.2f}s")
    assert r.status_code in expected, (label, r.status_code, r.text[:300])
    assert r.status_code < 500
    assert elapsed < MAX_SECONDS, f"{label} took {elapsed:.1f}s"
    if r.status_code == 422:
        assert "detail" in r.json()
    # Nothing was written by a refused upload.
    rows = (await db_session.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id))).all()
    assert rows == [] or label.startswith("garbage") or label.startswith("bad-")


@pytest.mark.asyncio
@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le-bom", "utf-16-be-bom"])
async def test_utf16_csv_imports(
    client: AsyncClient, db_session: AsyncSession, encoding: str
) -> None:
    h = await _headers(db_session)
    grp, zone, _ = await _zone(db_session)
    await db_session.commit()
    text = (
        ",".join(COLS)
        + "\r\n"
        + ",www,A,300,192.0.2.10,,,,,,\r\n"
        + ",mail,CNAME,,www."
        + ZONE
        + ",,,,,,\r\n"
    )
    if encoding == "utf-16":
        data = text.encode("utf-16")  # BOM + native order
    elif encoding == "utf-16-le-bom":
        data = b"\xff\xfe" + text.encode("utf-16-le")
    else:
        data = b"\xfe\xff" + text.encode("utf-16-be")

    url = f"{_base(grp, zone)}/import/spreadsheet"
    files = {"file": ("records.csv", data, "text/csv")}
    pv = await client.post(f"{url}/preview", headers=h, files=files, data={"mode": "merge"})
    assert pv.status_code == 200, pv.text
    body = pv.json()
    assert body["errors"] == []
    assert {(c["name"], c["record_type"], c["value"]) for c in body["to_create"]} == {
        ("www", "A", "192.0.2.10"),
        ("mail", "CNAME", "www." + ZONE),
    }

    cm = await client.post(f"{url}/commit", headers=h, files=files, data={"mode": "merge"})
    assert cm.status_code == 200, cm.text
    recs = (
        (await db_session.execute(select(DNSRecord).where(DNSRecord.zone_id == zone.id)))
        .scalars()
        .all()
    )
    got = {(r.name, r.record_type, r.value) for r in recs}
    assert ("www", "A", "192.0.2.10") in got
    assert ("mail", "CNAME", "www." + ZONE) in got
