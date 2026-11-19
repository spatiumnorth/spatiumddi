"""The id of this agent PROCESS (#3143, the DHCP side of #2044 / #2219).

Sent as ``X-Spatium-Agent-Instance`` on every config poll, heartbeat and
registration. It is how the control plane tells two live processes on one
server identity apart (a cloned VM or a copied state dir keeps the
``agent_id``): only the owner is served, the other's polls and registrations
are refused with 409, and its heartbeats neither rotate the server's token nor
put their daemon / config reports on the server row. Without it the pair
shared one token hash and staled each other's token forever.

Per process, not persisted: a restart is a new process, which the control
plane treats as a replacement and serves at once. A header, so an older
control plane ignores it.
"""

from __future__ import annotations

import uuid

AGENT_INSTANCE_HEADER = "X-Spatium-Agent-Instance"
AGENT_INSTANCE = uuid.uuid4().hex

# Set on the 409 the control plane answers when ANOTHER live agent process
# owns this server identity, on a config poll or a registration. This process
# keeps serving its cached config and asks again at this steady pace, taking
# the server back by itself once the other one stops polling.
DUPLICATE_INSTANCE_HEADER = "X-Spatium-Duplicate-Agent-Instance"
DUPLICATE_INSTANCE_BACKOFF = 30.0
