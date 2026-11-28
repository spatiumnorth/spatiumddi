"""aggregate_window memory is bounded by one client, not the hour (#4275)."""

from __future__ import annotations

import os
import tracemalloc
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSServer, DNSServerGroup
from app.services.dns_threat.aggregate import aggregate_window, floor_hour

CLIENTS = int(os.environ.get("T4275_CLIENTS", "30"))
PER_CLIENT = int(os.environ.get("T4275_PER_CLIENT", "1500"))


async def _seed(db: AsyncSession, bucket: datetime, clients: int, per_client: int) -> None:
    g = DNSServerGroup(name="g-4275", description="")
    db.add(g)
    await db.flush()
    s = DNSServer(
        name="s-4275",
        host="127.0.0.1",
        port=53,
        driver="bind9",
        group_id=g.id,
        is_primary=True,
        is_enabled=True,
    )
    db.add(s)
    await db.flush()
    await db.execute(
        text(
            "INSERT INTO dns_query_log_entry (server_id, ts, client_ip, qname, qtype, raw) "
            "SELECT CAST(:sid AS uuid), CAST(:ts AS timestamptz) + (n % 3000) * interval '1 second', "
            "('10.' || (c / 250) || '.' || (c % 250) || '.1')::inet, "
            "md5(c::text || '-' || n::text) || '.' || md5(n::text) || '.tun' || (c % 7) || '.evil.example', "
            "'TXT', '' "
            "FROM generate_series(0, :c - 1) c, generate_series(0, :n - 1) n"
        ),
        {"sid": str(s.id), "ts": bucket, "c": clients, "n": per_client},
    )
    await db.flush()


@pytest.mark.asyncio
async def test_aggregate_memory_is_bounded_by_one_client(db_session: AsyncSession) -> None:
    bucket = floor_hour(datetime.now(UTC))
    await _seed(db_session, bucket, CLIENTS, PER_CLIENT)
    tracemalloc.start()
    written = await aggregate_window(db_session, window_start=bucket)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(f"RESULT clients={CLIENTS} per_client={PER_CLIENT} peak_mb={peak/1e6:.1f}")
    assert written == CLIENTS
    # One client's rows plus one fetch batch is ~3 MB here; holding the
    # hour (the #4275 defect) is ~33 MB at the default size and grows
    # with the clients, so the cap is far below it and far above noise.
    assert peak < 12e6, f"peak {peak/1e6:.1f} MB scales with the hour, not one client"
