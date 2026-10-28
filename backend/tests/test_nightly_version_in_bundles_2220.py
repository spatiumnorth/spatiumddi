"""The support bundle and appliance diagnostics name a nightly the way
``GET /api/v1/version`` does (#2220), not as the bare image tag."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.services.support_bundle import generate

from ._signed_in import signed_in_headers
from .test_diagnostic_bundle_redaction import _bundle

TAG = "nightly-20261021"
STAMP = "0.0.0-nightly-20261021+abc1234"


@pytest.fixture
def nightly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "version", TAG)
    monkeypatch.setattr(settings, "app_version", STAMP)


@pytest.mark.asyncio
async def test_support_bundle_manifest_and_versions_match_the_version_endpoint(
    nightly: None, client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await signed_in_headers(db_session)
    served = (await client.get("/api/v1/version", headers=headers)).json()["version"]
    assert served == STAMP

    result = await generate(db_session, scrubbed=True)
    with zipfile.ZipFile(BytesIO(result.archive)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        versions = json.loads(zf.read("versions.json"))

    assert manifest["product_version"] == served
    assert versions["product_version"] == served


def test_appliance_diagnostics_manifest_matches_the_version_endpoint(
    nightly: None, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    members = _bundle(monkeypatch, tmp_path, pod_log="ok\n", env_file=None)
    assert f"version: {STAMP}" in members["manifest.txt"].splitlines()
    assert TAG + "\n" not in members["manifest.txt"]


@pytest.mark.asyncio
async def test_a_release_build_is_reported_unchanged(
    monkeypatch: pytest.MonkeyPatch, db_session: AsyncSession
) -> None:
    monkeypatch.setattr(settings, "version", "2026.10.02-1")
    monkeypatch.setattr(settings, "app_version", "")
    result = await generate(db_session, scrubbed=True)
    with zipfile.ZipFile(BytesIO(result.archive)) as zf:
        assert json.loads(zf.read("manifest.json"))["product_version"] == "2026.10.02-1"
