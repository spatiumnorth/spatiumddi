### Fixed

- A DNS zone edit, a per-server record push, a delegation, a zone move or an IPAM reverse-zone retirement caught by a delete of the same zone no longer answers a bare 500, deadlocks, or writes into the trashed zone: each takes the zone row first, as a record write does, and answers 404 once the zone is gone. A zone move now leaves no queued record op behind for the old group. The Technitium PTR re-assert after a retried A or AAAA delete runs once the agent's ack has committed, so it can no longer deadlock with a delete of the PTR's reverse zone (#3688)
