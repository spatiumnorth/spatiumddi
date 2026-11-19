"""#1964: the conformity export.pdf must survive markup in any text it prints.

reportlab's ``Paragraph`` parses a mini-XML dialect, so an unescaped ``<?``
in the ``framework`` filter, or in a stored policy / result text, raised
``paraparser: syntax error`` and answered 500. Driven through the real
endpoint, asserting status and that the body is a complete PDF.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.conformity import ConformityPolicy, ConformityResult


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"su-{uuid.uuid4().hex[:8]}",
        email=f"su-{uuid.uuid4().hex[:8]}@t.io",
        display_name="su",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _is_pdf(data: bytes) -> bool:
    return data.startswith(b"%PDF-") and b"%%EOF" in data[-1024:]


@pytest.mark.parametrize("value", ["<?", "a<b", "<b>x", "R&D", "PCI", "<legacy>"])
async def test_framework_filter_text_never_500s(
    client: AsyncClient, db_session: AsyncSession, value: str
) -> None:
    h = await _headers(db_session)
    r = await client.get("/api/v1/conformity/export.pdf", params={"framework": value}, headers=h)
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/pdf")
    assert _is_pdf(r.content)


async def test_stored_text_with_markup_renders(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    fw = "<?fw"
    # The PDF reports a policy's most recent pass (#2278), so the result
    # must carry the policy's ``last_evaluated_at`` to reach the renderer.
    when = datetime.now(UTC)
    pol = ConformityPolicy(
        name="a<b & <legacy>",
        description="desc <b>unclosed",
        framework=fw,
        reference="<ref",
        severity="warn",
        target_kind="subnet",
        check_kind="has_field",
        last_evaluated_at=when,
    )
    db_session.add(pol)
    await db_session.flush()
    db_session.add(
        ConformityResult(
            policy_id=pol.id,
            resource_kind="subnet",
            resource_id="x",
            resource_display="<net> & co",
            evaluated_at=when,
            status="fail",
            detail="bad <thing",
            diagnostic={"k": "<v>&"},
        )
    )
    await db_session.commit()
    for params in ({}, {"framework": fw}):
        r = await client.get("/api/v1/conformity/export.pdf", params=params, headers=h)
        assert r.status_code == 200, r.text
        assert _is_pdf(r.content)
