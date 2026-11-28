"""#4227 — a subnet restore that only republishes live lease mirrors wakes the
zone's DNS group, so its agents apply the queued record ops now rather than on
their next safety tick. The restore-time reconcile counts the DDNS re-apply as a
change (before this, only IPAM-owned creates/updates/deletes did, and the
queued #3787 republish then found nothing to do and published no wake)."""

from __future__ import annotations

from typing import Any

import pytest

from app.api.v1.admin import trash as trash_mod

from .test_trash_restore_republishes_ddns_3787 import (
    _capture_republish,
    _no_inline_teardown,
    _publish_leases,
    _records_by_ip,
    _setup_with_admin,
)

pytestmark = pytest.mark.asyncio


async def test_restore_of_lease_mirrors_wakes_the_dns_group(
    client: Any, db_session: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    octet = 41
    server, subnet, headers = await _setup_with_admin(db_session, octet)
    sid = subnet.id
    await _publish_leases(client, db_session, server, octet)
    _no_inline_teardown(monkeypatch)
    _capture_republish(monkeypatch)
    woken: list[Any] = []

    async def capture(*channels: Any) -> None:
        woken.extend(channels)

    monkeypatch.setattr(trash_mod, "publish_wake", capture)
    gone = await client.delete(f"/api/v1/ipam/subnets/{sid}", headers=headers)
    assert gone.status_code == 204
    woken.clear()
    back = await client.post(f"/api/v1/admin/trash/subnet/{sid}/restore", headers=headers)
    assert back.status_code == 200, back.text
    db_session.expunge_all()
    assert await _records_by_ip(db_session, sid), "the live leases' records came back"
    assert woken, "the restore published no DNS group wake for the republished leases"
