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


async def _directory_login(
    db_session: AsyncSession,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    username: str,
    row_source: str | None,
) -> tuple[int, int, int]:
    """Wrong-password sign-in; returns (status, password compares, provider calls)."""
    from app.api.v1.auth import router as auth_router
    from app.models.auth_provider import AuthProvider

    if row_source is not None:
        db_session.add(
            User(
                username=username,
                email=f"{uuid.uuid4().hex[:8]}@x.com",
                display_name="d",
                hashed_password="",
                auth_source=row_source,
                is_active=True,
                is_superadmin=False,
            )
        )
    for i in range(2 if row_source is not None else 0):
        db_session.add(
            AuthProvider(
                name=f"dir-{uuid.uuid4().hex[:6]}",
                type="ldap" if i == 0 else "radius",
                is_enabled=True,
                priority=10 * (i + 1),
                config={},
            )
        )
    await db_session.commit()

    compares: list[int] = []
    real = security.bcrypt.checkpw

    def counting(*a, **k):  # type: ignore[no-untyped-def]
        compares.append(1)
        return real(*a, **k)

    provider_calls: list[int] = []

    def reject(provider, user, password):  # type: ignore[no-untyped-def]
        provider_calls.append(1)
        return None

    monkeypatch.setattr(security.bcrypt, "checkpw", counting)
    monkeypatch.setitem(auth_router._PASSWORD_AUTH_DISPATCH, "ldap", (reject, Exception))
    monkeypatch.setitem(auth_router._PASSWORD_AUTH_DISPATCH, "radius", (reject, Exception))
    resp = await client.post(
        "/api/v1/auth/login", json={"username": username, "password": "x" * 12}
    )
    return resp.status_code, len(compares), len(provider_calls)


@pytest.mark.asyncio
async def test_refused_directory_signin_costs_the_same_as_an_unknown_name(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    known = await _directory_login(
        db_session, client, monkeypatch, f"dir-{uuid.uuid4().hex[:8]}", "ldap"
    )
    unknown = await _directory_login(
        db_session, client, monkeypatch, f"nobody-{uuid.uuid4().hex[:8]}", None
    )
    assert known == (401, 1, 2)
    assert unknown == known


def test_ldap_unknown_name_does_the_same_binds_as_a_known_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ldap3.core.exceptions import LDAPInvalidCredentialsResult

    from app.core.auth import ldap as ldap_mod

    class Conn:
        def unbind(self) -> None:
            pass

    binds: list[str] = []

    def fake_open(cfg, user, password):  # type: ignore[no-untyped-def]
        binds.append(user)
        if user != "cn=svc":
            raise LDAPInvalidCredentialsResult()
        return Conn()

    cfg = ldap_mod.LDAPConfig(
        host="h",
        port=389,
        backup_hosts=[],
        use_ssl=False,
        start_tls=False,
        bind_dn="cn=svc",
        bind_password="p",
        user_base_dn="ou=u,dc=x",
        user_filter="(uid={username})",
        group_base_dn="ou=g,dc=x",
        attr_username="uid",
        attr_email="mail",
        attr_display_name="cn",
        attr_member_of="memberOf",
    )
    monkeypatch.setattr(ldap_mod.LDAPConfig, "from_provider", classmethod(lambda c, p: cfg))
    monkeypatch.setattr(ldap_mod, "_open", fake_open)

    monkeypatch.setattr(
        ldap_mod, "_search_user", lambda conn, c, u: {"dn": "uid=a,ou=u,dc=x", "attributes": {}}
    )
    assert ldap_mod.authenticate_ldap(object(), "a", "wrong-pass") is None  # type: ignore[arg-type]
    known_binds = len(binds)

    binds.clear()
    monkeypatch.setattr(ldap_mod, "_search_user", lambda conn, c, u: None)
    assert ldap_mod.authenticate_ldap(object(), "zz", "wrong-pass") is None  # type: ignore[arg-type]
    assert len(binds) == known_binds == 2
    assert binds[1].endswith(",ou=u,dc=x")
