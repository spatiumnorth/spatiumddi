### Fixed

- Logs: the server picked on the DNS Queries and DHCP Activity tabs is now kept when you switch to another Logs tab and back, instead of snapping back to the first server (#4234). A kept pick for a server you can no longer read falls back to the default.
- Logs: a server deleted since the Logs page last loaded no longer stays picked on DNS Queries / DHCP Activity. The server list is refetched on every visit, deleting a DNS or DHCP server refreshes it, and a 404 for the picked server clears the pick instead of showing "Query failed" (#4234).
