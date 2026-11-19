"""A NUL-bearing file must not refuse the whole rendered-config snapshot (#2842).

PostgreSQL JSONB cannot store ``\\u0000``; BIND's binary companions to an
inline-signed zone carry NULs yet decode as UTF-8, so one such file used to
422 the entire push and freeze the console's view at the pre-signing snapshot.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dns.agents import (
    RenderedConfigFile,
    RenderedConfigReport,
    agent_rendered_config,
)
from app.models.dns import DNSServer, DNSServerGroup, DNSServerRuntimeState

pytestmark = pytest.mark.asyncio


async def test_nul_file_is_skipped_not_refused(db_session: AsyncSession) -> None:
    group = DNSServerGroup(name="g-2842")
    db_session.add(group)
    await db_session.flush()
    srv = DNSServer(
        group_id=group.id,
        name="ns-2842",
        driver="bind9",
        host="10.0.0.1",
    )
    db_session.add(srv)
    await db_session.flush()

    body = RenderedConfigReport(
        files=[
            RenderedConfigFile(path="named.conf", content="options { };\n"),
            RenderedConfigFile(path="zones/example.com.db.jnl", content="BIND\x00\x01"),
        ]
    )
    out = await agent_rendered_config(body, db_session, (srv, {}))

    assert out == {"status": "ok", "files": 1}
    state = await db_session.get(DNSServerRuntimeState, srv.id)
    assert state is not None
    assert [f["path"] for f in state.rendered_files] == ["named.conf"]
