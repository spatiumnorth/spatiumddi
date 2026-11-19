"""#2748 — every rule type the platform seeds is described by
``GET /alerts/rule-types``, so the editor never has to guess why a stored
rule's type is missing (it blamed a feature module that was on)."""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.services import alerts
from app.services.alert_rule_catalogue import build_catalogue

pytestmark = pytest.mark.asyncio


def test_every_externally_driven_type_is_in_the_catalogue() -> None:
    described = {s.rule_type for s in build_catalogue()}
    missing = alerts._EXTERNALLY_DRIVEN_RULE_TYPES - described  # noqa: SLF001
    assert missing == set()


def test_system_driven_types_are_not_creatable() -> None:
    sys_types = {s.rule_type for s in build_catalogue() if s.system_driven}
    assert "cluster_upgrade_failed" in sys_types
    assert sys_types.isdisjoint(alerts.RULE_TYPES)


async def test_rule_types_endpoint_describes_cluster_upgrade_failed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    u = User(
        username=f"u-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(u)
    await db_session.commit()
    h = {"Authorization": f"Bearer {create_access_token(str(u.id))}"}
    r = await client.get("/api/v1/alerts/rule-types", headers=h)
    assert r.status_code == 200
    spec = next(s for s in r.json() if s["rule_type"] == "cluster_upgrade_failed")
    assert spec["system_driven"] is True
    assert spec["params"] == []
    assert spec["description"]
    # ...and it still cannot be created.
    c = await client.post(
        "/api/v1/alerts/rules",
        json={"name": "x", "rule_type": "cluster_upgrade_failed"},
        headers=h,
    )
    assert c.status_code == 422
