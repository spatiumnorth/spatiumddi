"""The id of this agent PROCESS (#2042, #2044).

Sent as ``X-Spatium-Agent-Instance`` on every config poll and heartbeat. The
control plane stamps it on each op it ships, so when a replacement process
polls, an op still in flight to the previous one is recognised as undelivered
and shipped again at once (#2042). It is also how the control plane tells two
live processes on one server identity apart (a cloned VM or a copied state
dir): only the owner is served, and the other's heartbeats keep their daemon /
config reports off the server row (#2044). Per process, not per ``Sync``: a
re-bootstrap keeps the heartbeat and its unsent acks, so the ops this process
received are still its own. A header, so an older control plane ignores it.

#2219 — sent on registration too. The refused half of a duplicate pair is
refused there as well, because a token minted for it would replace the
owner's and the two would trade re-registrations forever.
"""

from __future__ import annotations

import uuid

AGENT_INSTANCE_HEADER = "X-Spatium-Agent-Instance"
AGENT_INSTANCE = uuid.uuid4().hex

# #2044 — set on the 409 the control plane answers when ANOTHER live agent
# process owns this server identity (a cloned VM or a copied state dir keeps
# the agent_id), on a config poll or (#2219) a registration. Only the most
# recent process is served; this one keeps serving its cached config and asks
# again on a slow backoff, taking the server back by itself once the other one
# stops polling.
DUPLICATE_INSTANCE_HEADER = "X-Spatium-Duplicate-Agent-Instance"
DUPLICATE_INSTANCE_BACKOFF = 30.0
