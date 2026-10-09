"""The #408 secret reveals spend the step-up budget, and a spent budget is
audited and says when it resets (#1413).

#1355 put a per-account wrong-answer budget behind the operator step-up, but
the older reveals (agent keys, pairing codes, kubeconfig, SNMP community,
block-sync and firewall-feed secrets, the approvals break-glass) called
``reverify_operator`` directly, so a stolen session could guess the
operator's password through any of them without limit.
"""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth_throttle import StepupThrottleUnavailable
from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User

_PW = "Admin-pw-1413!"
_API = Path(__file__).resolve().parents[1] / "app" / "api"


@pytest.fixture(autouse=True)
def _budget(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Stand in for the Redis-backed step-up budget."""
    import app.api.stepup as stepup

    state: dict[str, object] = {"blocked": False, "down": False, "failures": []}

    async def _blocked(_user_id: object) -> bool:
        if state["down"]:
            raise StepupThrottleUnavailable
        return bool(state["blocked"])

    async def _record(user_id: object) -> None:
        state["failures"].append(user_id)  # type: ignore[union-attr]

    async def _left(_user_id: object) -> int:
        return 300

    monkeypatch.setattr(stepup, "stepup_password_blocked", _blocked)
    monkeypatch.setattr(stepup, "record_stepup_password_failure", _record)
    monkeypatch.setattr(stepup, "stepup_block_seconds_left", _left)
    return state


async def _admin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"a-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.test",
        display_name="admin",
        hashed_password=hash_password(_PW),
        auth_source="local",
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.commit()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _denials(db: AsyncSession, action: str) -> list[AuditLog]:
    return list(
        (await db.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("url", "denied_action"),
    [
        ("/api/v1/admin/agent-keys/reveal", "agent_keys_reveal_denied"),
        ("/api/v1/settings/snmp/reveal-community", "snmp_community_reveal_denied"),
    ],
)
async def test_a_wrong_answer_to_a_reveal_spends_the_budget(
    client: AsyncClient,
    db_session: AsyncSession,
    _budget: dict[str, object],
    url: str,
    denied_action: str,
) -> None:
    admin, headers = await _admin(db_session)

    r = await client.post(url, headers=headers, json={"password": "wrong"})

    assert r.status_code == 403, r.text
    assert _budget["failures"] == [admin.id]
    rows = await _denials(db_session, denied_action)
    assert [(row.result, row.error_detail) for row in rows] == [("denied", "bad_credential")]

    r = await client.post(url, headers=headers, json={"password": _PW})
    assert r.status_code == 200, r.text
    assert _budget["failures"] == [admin.id]  # a right answer spends nothing


@pytest.mark.asyncio
async def test_an_omitted_answer_is_refused_without_spending(
    client: AsyncClient, db_session: AsyncSession, _budget: dict[str, object]
) -> None:
    _, headers = await _admin(db_session)

    r = await client.post("/api/v1/admin/agent-keys/reveal", headers=headers, json={})

    assert r.status_code == 403, r.text
    assert _budget["failures"] == []


@pytest.mark.asyncio
async def test_a_spent_budget_is_audited_and_says_when_it_resets(
    client: AsyncClient, db_session: AsyncSession, _budget: dict[str, object]
) -> None:
    _, headers = await _admin(db_session)
    _budget["blocked"] = True

    # Even the right password is refused while the budget is spent.
    r = await client.post(
        "/api/v1/admin/agent-keys/reveal", headers=headers, json={"password": _PW}
    )

    assert r.status_code == 429, r.text
    assert r.headers["Retry-After"] == "300"
    assert "5 minute" in r.json()["detail"]
    rows = await _denials(db_session, "agent_keys_reveal_denied")
    assert [(row.result, row.error_detail) for row in rows] == [("denied", "stepup_blocked")]


@pytest.mark.asyncio
async def test_a_limiter_outage_fails_closed_and_is_not_an_attempt(
    client: AsyncClient, db_session: AsyncSession, _budget: dict[str, object]
) -> None:
    _, headers = await _admin(db_session)
    _budget["down"] = True

    r = await client.post(
        "/api/v1/admin/agent-keys/reveal", headers=headers, json={"password": _PW}
    )

    assert r.status_code == 503, r.text
    assert r.headers["Retry-After"] == "60"
    assert await _denials(db_session, "agent_keys_reveal_denied") == []


@pytest.mark.asyncio
async def test_the_mfa_endpoints_share_the_gate_and_its_retry_after(
    client: AsyncClient, db_session: AsyncSession, _budget: dict[str, object]
) -> None:
    _, headers = await _admin(db_session)
    _budget["blocked"] = True

    r = await client.post("/api/v1/auth/mfa/enroll/begin", headers=headers, json={"password": _PW})

    assert r.status_code == 429, r.text
    assert r.headers["Retry-After"] == "300"


def _reverify_callers() -> dict[str, Path]:
    """Every module under app/api that calls ``reverify_operator``."""
    out: dict[str, Path] = {}
    for path in _API.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "reverify_operator"
            ):
                out[str(path.relative_to(_API))] = path
                break
    return out


def test_no_reveal_checks_the_operator_outside_the_shared_step_up() -> None:
    """A new reveal that calls ``reverify_operator`` itself skips the budget,
    which is how the seven #1413 fixed came to exist. The break-glass is the
    one exception, and it must still pass the shared budget gate."""
    callers = _reverify_callers()
    assert set(callers) == {"stepup.py", "v1/admin/feature_modules.py"}, sorted(callers)
    assert "refuse_if_stepup_blocked(" in callers["v1/admin/feature_modules.py"].read_text()
