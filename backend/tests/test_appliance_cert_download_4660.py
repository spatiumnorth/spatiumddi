"""Download the Web UI certificate a standalone agent should trust (#4660)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient

from app.config import settings

from .test_certificate_store_permission_3067 import TLS, _upload_body, _user

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def _no_deploy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "appliance_mode", False)


async def test_download_returns_public_pem_only(client: AsyncClient, db_session: Any) -> None:
    _, auth_headers = await _user(db_session, role="Appliance Operator")
    body = _upload_body(activate=True, name="agent trust/1")
    r = await client.post(f"{TLS}/upload", json=body, headers=auth_headers)
    assert r.status_code in (200, 201), r.text
    for url in (f"{TLS}/active/pem", f"{TLS}/{r.json()['id']}/pem"):
        d = await client.get(url, headers=auth_headers)
        assert d.status_code == 200, d.text
        assert d.text == body["cert_pem"]
        assert "PRIVATE KEY" not in d.text
        assert d.headers["content-disposition"] == 'attachment; filename="agent_trust_1.pem"'


async def test_download_404_and_permission(client: AsyncClient, db_session: Any) -> None:
    _, auth_headers = await _user(db_session, role="DNS Editor")
    assert (await client.get(f"{TLS}/{uuid.uuid4()}/pem", headers=auth_headers)).status_code == 404
    _, h = await _user(db_session, permissions=[])
    assert (await client.get(f"{TLS}/active/pem", headers=h)).status_code == 403
