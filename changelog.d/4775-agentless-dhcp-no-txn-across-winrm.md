### Fixed

- An agentless Windows DHCP server that does not answer no longer holds a database transaction open for ~135 s per health check and MAC-block sync (which stalled a migration's `ALTER TABLE dhcp_server`). The tasks now close their session before the WinRM call and write the result in a new one, and the health probe and MAC-block sync fail within 10 s when the WinRM port does not accept a connection.
