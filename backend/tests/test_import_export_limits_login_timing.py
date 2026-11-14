"""Spreadsheet import bounds, CSV export cell escaping, uniform login cost."""

from __future__ import annotations

import io
import re
import uuid
import zipfile
from pathlib import Path

import pytest
from fastapi import HTTPException
from httpx import AsyncClient
from openpyxl import Workbook
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import security
from app.models.auth import User
from app.services.dns_io import spreadsheet as sheet_io
from app.services.ipam_io.parser import parse_xlsx


def test_ipam_xlsx_that_expands_too_far_is_refused() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("xl/sharedStrings.xml", b"\0" * (sheet_io.MAX_XLSX_UNCOMPRESSED_BYTES + 1))
    with pytest.raises(HTTPException) as exc:
        parse_xlsx(buf.getvalue())
    assert exc.value.status_code == 422
    assert "expands to more than" in str(exc.value.detail)


def test_ipam_xlsx_row_count_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sheet_io, "MAX_SHEET_ROWS", 5)
    wb = Workbook()
    ws = wb.active
    ws.title = "addresses"
    ws.append(["address"])
    for i in range(10):
        ws.append([f"192.0.2.{i + 1}"])
    raw = io.BytesIO()
    wb.save(raw)
    with pytest.raises(HTTPException) as exc:
        parse_xlsx(raw.getvalue())
    assert exc.value.status_code == 422
    assert "rows" in str(exc.value.detail)


def test_every_csv_writer_escapes_formula_cells() -> None:
    root = Path(__file__).resolve().parents[1] / "app"
    offenders = []
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"csv\.(writer|DictWriter)\(", text) and not re.search(
            r"sanitize_cell|_csv_safe", text
        ):
            offenders.append(str(path.relative_to(root)))
    assert offenders == []


@pytest.mark.asyncio
async def test_unknown_username_costs_one_password_hash(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[int] = []
    real = security.bcrypt.checkpw

    def counting(*a, **k):  # type: ignore[no-untyped-def]
        calls.append(1)
        return real(*a, **k)

    monkeypatch.setattr(security.bcrypt, "checkpw", counting)
    resp = await client.post(
        "/api/v1/auth/login",
        json={"username": f"nobody-{uuid.uuid4().hex[:8]}", "password": "x" * 12},
    )
    assert resp.status_code == 401
    assert len(calls) == 1

    calls.clear()
    user = User(
        username=f"nohash-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="n",
        hashed_password="",
        auth_source="local",
        is_active=True,
        is_superadmin=False,
    )
    db_session.add(user)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/auth/login", json={"username": user.username, "password": "x" * 12}
    )
    assert resp.status_code == 401
    assert len(calls) == 1
