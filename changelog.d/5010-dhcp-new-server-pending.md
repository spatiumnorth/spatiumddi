### Fixed
- A newly created agentless DHCP server (Windows DHCP, FortiGate) now shows `pending` until its first health check, which is queued at create time, instead of reading `active` for a server nobody has probed yet (#5010)
