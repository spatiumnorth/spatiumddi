"""The About page's API sources need a session (#2895).

Someone probing the server from outside must not learn which libraries it
runs, so the Python notice list and the web tier's gate both refuse an
anonymous caller and answer a signed-in one.
"""

from __future__ import annotations

import importlib
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User

# ``app.api.v1.about`` re-exports ``router`` (the APIRouter), which shadows the
# submodule of the same name, so the module is fetched by its dotted path.
about_module = importlib.import_module("app.api.v1.about.router")

PYTHON_URL = "/api/v1/about/third-party/python"
SESSION_URL = "/api/v1/about/session"


async def _token(db: AsyncSession) -> str:
    """A signed-in user with no roles at all: the About page is for anyone who
    can sign in, not only an admin."""
    user = User(
        username=f"about-{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="About reader",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    db.add(user)
    await db.flush()
    return create_access_token(str(user.id))


@pytest.fixture
def baked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "third-party-python.txt"
    path.write_text("fastapi\n0.115.0\nMIT License\n", encoding="utf-8")
    monkeypatch.setattr(about_module, "THIRD_PARTY_PYTHON", path)
    return path


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [PYTHON_URL, SESSION_URL])
async def test_anonymous_caller_is_refused(client: AsyncClient, baked: Path, url: str) -> None:
    resp = await client.get(url)

    assert resp.status_code == 401
    assert "fastapi" not in resp.text


@pytest.mark.asyncio
async def test_a_bad_token_is_refused(client: AsyncClient, baked: Path) -> None:
    resp = await client.get(PYTHON_URL, headers={"Authorization": "Bearer not-a-token"})

    assert resp.status_code == 401
    assert "fastapi" not in resp.text


@pytest.mark.asyncio
async def test_signed_in_caller_gets_the_python_list(
    client: AsyncClient, db_session: AsyncSession, baked: Path
) -> None:
    token = await _token(db_session)

    resp = await client.get(PYTHON_URL, headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "utf-8" in resp.headers["content-type"].lower()
    assert resp.text.startswith("fastapi\n0.115.0")
    # Authenticated content: a shared cache must not keep it for the next caller.
    assert "private" in resp.headers["cache-control"]
    assert "public" not in resp.headers["cache-control"]


@pytest.mark.asyncio
async def test_signed_in_caller_passes_the_gate(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _token(db_session)

    resp = await client.get(SESSION_URL, headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 204
    assert resp.content == b""


@pytest.mark.asyncio
async def test_missing_file_is_a_404_not_an_empty_200(
    client: AsyncClient,
    db_session: AsyncSession,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(about_module, "THIRD_PARTY_PYTHON", tmp_path / "absent.txt")
    token = await _token(db_session)

    resp = await client.get(PYTHON_URL, headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 404
    assert "built" in resp.json()["detail"]
