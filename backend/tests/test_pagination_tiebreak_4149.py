"""Offset paging needs a total ordering (#4149).

A sort on a non-unique column (``last_seen_at``, ``expired_at``) without a
unique tiebreaker lets rows that share a value fall either side of a page
boundary between requests, so a client walking the pages skips or repeats
rows. ``paginate`` now ends every ORDER BY in the primary key; ad-hoc
``.order_by(...).offset(...)`` list endpoints must do the same.
"""

from __future__ import annotations

import ast
import pathlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.api.pagination import with_pk_tiebreak
from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.dhcp import DHCPLease, DHCPServer

API_DIR = pathlib.Path(__file__).resolve().parents[1] / "app" / "api"


def _chain_has_offset(node: ast.AST) -> ast.Call | None:
    """Return the ``.order_by(...)`` call upstream of an ``.offset(...)`` call."""
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "offset"
    ):
        return None
    cur: ast.AST = node.func.value
    while isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
        if cur.func.attr == "order_by":
            return cur
        cur = cur.func.value
    return None


def test_adhoc_paginated_orderings_end_in_id() -> None:
    offenders: list[str] = []
    for path in API_DIR.rglob("*.py"):
        rel = "app/api/" + path.relative_to(API_DIR).as_posix()
        for node in ast.walk(ast.parse(path.read_text())):
            ob = _chain_has_offset(node)
            if ob is None or not ob.args:
                continue
            tail = ast.unparse(ob.args[-1])
            if ".id" not in tail:
                offenders.append(f"{rel}:{ob.lineno} ORDER BY ... {tail}")
    assert (
        not offenders
    ), "paginated ORDER BY must end in a unique column (Model.id), see #4149:\n" + "\n".join(
        offenders
    )


def test_with_pk_tiebreak_appends_primary_key_once() -> None:
    q = select(DHCPLease).order_by(DHCPLease.last_seen_at.desc())
    sql = str(with_pk_tiebreak(q).compile())
    assert sql.rstrip().endswith("dhcp_lease.id")
    # already ends in the key: untouched
    again = str(with_pk_tiebreak(with_pk_tiebreak(q)).compile())
    assert again == sql
    # no ORDER BY requested: no order imposed
    assert "ORDER BY" not in str(with_pk_tiebreak(select(DHCPLease)).compile())


@pytest.mark.asyncio
async def test_lease_pages_cover_every_row_exactly_once(client: AsyncClient, db_session) -> None:
    user = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    await db_session.flush()
    auth_headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}
    server = DHCPServer(name="s-4149", driver="kea", host="127.0.0.1", port=8000)
    db_session.add(server)
    await db_session.flush()
    stamp = datetime.now(UTC) - timedelta(minutes=5)
    n = 45
    for i in range(n):
        db_session.add(
            DHCPLease(
                server_id=server.id,
                ip_address=f"10.4.9.{i + 1}",
                mac_address=f"aa:bb:cc:00:00:{i:02x}",
                state="active",
                last_seen_at=stamp,  # every row shares the sort key
            )
        )
    await db_session.commit()

    seen: list[str] = []
    for page in range(1, 10):
        r = await client.get(
            f"/api/v1/dhcp/servers/{server.id}/leases",
            params={"page": page, "page_size": 10},
            headers=auth_headers,
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == n
        seen.extend(item["id"] for item in body["items"])
    assert len(seen) == n
    assert len(set(seen)) == n
    assert uuid.UUID(seen[0])
