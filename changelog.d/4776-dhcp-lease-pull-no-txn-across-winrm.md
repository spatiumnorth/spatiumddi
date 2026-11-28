### Fixed

- The agentless DHCP lease pull no longer holds a database transaction while it waits on an unreachable Windows DHCP server. It reads the server first with no transaction open, fails within 10 seconds when the WinRM port accepts no connection, and then writes the result.
