"""The About page's Python notice list is public and static (#2895)."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from httpx import AsyncClient

# ``app.api.v1.about`` re-exports ``router`` (the APIRouter), which shadows the
# submodule of the same name, so the module is fetched by its dotted path.
about_module = importlib.import_module("app.api.v1.about.router")

URL = "/api/v1/about/third-party/python"


@pytest.mark.asyncio
async def test_serves_the_baked_file_without_credentials(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    baked = tmp_path / "third-party-python.txt"
    baked.write_text("fastapi\n0.115.0\nMIT License\n", encoding="utf-8")
    monkeypatch.setattr(about_module, "THIRD_PARTY_PYTHON", baked)

    # No Authorization header at all: licence text must reach anyone who is
    # handed the software.
    resp = await client.get(URL)

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert resp.text.startswith("fastapi\n0.115.0")
    assert "max-age" in resp.headers["cache-control"]


@pytest.mark.asyncio
async def test_missing_file_is_a_404_not_an_empty_200(
    client: AsyncClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(about_module, "THIRD_PARTY_PYTHON", tmp_path / "absent.txt")

    resp = await client.get(URL)

    assert resp.status_code == 404
    assert "built" in resp.json()["detail"]
