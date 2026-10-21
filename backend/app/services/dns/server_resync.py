"""Force an agent-based DNS server to re-render every zone (#2281).

A disabled server is skipped by the record-op fan-out
(``record_ops.enqueue_record_op``) and by the bundle worker, while its agent
keeps polling and its daemon keeps serving the config it last applied. When
the server is enabled again the next bundle carries the current records, but
in a group without views records are not part of the structural etag, and
the agent re-renders zone files only when that etag moves. There are no ops
to drain either. So every record created, changed or deleted while the
server was off stayed missing or wrong on it until some unrelated structural
change or an agent restart.

``force_zone_resync`` closes that: it bumps ``DNSServer.zone_resync_seq``,
which ``agent_config`` folds into the structural fingerprint, so the next
bundle makes the agent render every zone from the records in the body. The
record ops still queued from before the server was disabled are retired with
it: each carries a whole RRset as it was when queued (#773), and shipped
after the re-render it would put back a record deleted while the server was
off. The re-render delivers the current state of every one of them.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.drivers.dns import is_agentless
from app.models.dns import DNSServer
from app.services.dns.agent_config import retire_queued_ops


async def force_zone_resync(db: AsyncSession, server: DNSServer) -> int:
    """Make ``server``'s next bundle re-render every zone. Returns the number
    of queued record ops retired. A no-op for an agentless server, whose
    writes go straight to the daemon and which has no bundle."""
    if is_agentless(server.driver):
        return 0
    server.zone_resync_seq = (server.zone_resync_seq or 0) + 1
    return await retire_queued_ops(db, server)
