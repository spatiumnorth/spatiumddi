"""#4939 — an RFC 2136 UPDATE the server REFUSED must not count as applied.

``dns.query.tcp`` returns the reply and raises only on transport errors, so a
REFUSED / NOTAUTH reply was discarded: the API answered 201 with no
``provider_warning`` and the op was logged applied.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import dns.message
import dns.query
import dns.rcode
import dns.update
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.drivers.dns import bind9, windows
from app.drivers.dns._axfr import send_rfc2136_update
from app.drivers.dns.base import RecordChange, RecordData
from app.models.auth import User
from tests.test_dns_agentless_after_commit_1539 import _zone


def _stub(monkeypatch: pytest.MonkeyPatch, rcode: int) -> list[Any]:
    sent: list[Any] = []

    def fake(msg: Any, *a: Any, **k: Any) -> Any:
        sent.append(msg)
        reply = dns.message.make_response(msg)
        reply.set_rcode(rcode)
        return reply

    monkeypatch.setattr(dns.query, "tcp", fake)
    for mod in (windows, bind9):
        monkeypatch.setattr(mod, "resolve_server_address", lambda *a, **k: ["192.0.2.53"])
    return sent


def _change() -> RecordChange:
    return RecordChange(
        op="create",
        zone_name="example.com.",
        record=RecordData(name="www", record_type="A", value="10.0.0.2", ttl=60),
        target_serial=1,
    )


_SERVER = SimpleNamespace(id="s1", host="192.0.2.53", api_port=53)


@pytest.mark.parametrize("rcode", [dns.rcode.REFUSED, dns.rcode.NOTAUTH, dns.rcode.SERVFAIL])
async def test_windows_rfc2136_non_noerror_raises(
    monkeypatch: pytest.MonkeyPatch, rcode: int
) -> None:
    _stub(monkeypatch, rcode)
    with pytest.raises(RuntimeError, match=dns.rcode.to_text(rcode)):
        await windows.WindowsDNSDriver().apply_record_change(_SERVER, _change())


def test_helper_raises_on_refused_for_any_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    # The BIND9 agentless path shares this helper (it is unreachable today: it
    # requires a TSIG secret nothing supplies), so pin the helper directly.
    _stub(monkeypatch, dns.rcode.REFUSED)
    with pytest.raises(RuntimeError, match="REFUSED"):
        send_rfc2136_update(dns.update.Update("example.com."), "192.0.2.53", 53, what="x")


async def test_windows_rfc2136_noerror_is_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _stub(monkeypatch, dns.rcode.NOERROR)
    await windows.WindowsDNSDriver().apply_record_change(_SERVER, _change())
    assert len(sent) == 1


async def test_api_create_record_refused_surfaces_provider_warning(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _stub(monkeypatch, dns.rcode.REFUSED)
    user = User(
        username=f"u4939-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="u",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(user)
    zone = await _zone(db_session)
    await db_session.commit()
    headers = {"Authorization": f"Bearer {create_access_token(str(user.id))}"}

    resp = await client.post(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/records",
        json={"name": "api", "record_type": "A", "value": "10.1.1.1"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    warning = resp.json()["provider_warning"]
    assert warning and "REFUSED" in warning
