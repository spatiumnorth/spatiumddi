### Fixed

- A blocklist entry edit no longer changes the DNS agent's whole config bundle: an agent that supports it now fetches the entries from their own versioned stream (`GET /api/v1/dns/agents/blocklist`), so the bundle and its ETag move only with real structural changes, and the agent downloads the stream only when its version changes. Older agents keep receiving the entries embedded in the bundle (#4041).
