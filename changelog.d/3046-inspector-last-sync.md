### Fixed

- A server's inspector no longer shows an empty "Last sync" for an agent-managed Kea or DNS server whose config is applied: it shows "Config applied" with the agent's apply time instead (the more recent of that and the last sync, here and in the DHCP server page's header), says "Not recorded for agentless servers" for a Windows, cloud or Technitium-API DNS server, for which nothing records a sync, and keeps the empty placeholder only for a server that has neither.
