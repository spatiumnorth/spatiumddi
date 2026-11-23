### Fixed

- The DHCP health sweep and the MAC-block sync ran every 60 seconds against every agentless DHCP server (one WinRM session each), and could not be slowed down, which loaded Windows DHCP hosts. Both intervals are now settings (Settings, DHCP, Lease Sync: 60 to 3600 s, default 60 so nothing changes until you raise them); Kea servers are still checked from the agent heartbeat every minute. The MAC-block sync also skips a server with no applicable blocks and nothing pushed before, and still syncs once to clear the filter list after the last block is removed. (#4759)
