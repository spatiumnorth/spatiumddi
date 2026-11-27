### Fixed

- The scheduled DNS server sync, DNS server health check, DNS pool health check and cloud sync no longer hold a database transaction (the pool check no longer holds the pool's row lock) while they wait on a server or provider; each reads, commits, makes the network call, then writes in a fresh transaction and drops the result for a row deleted, disabled or changed meanwhile (#4808).
- The scheduled DNS server sync still pushes DB-only records to the server inside its apply transaction; that write-side call is tracked as a follow-up (#4808).
