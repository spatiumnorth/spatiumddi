### Fixed

- **Every database-unavailable error now answers 503 with `Retry-After`
  during a PostgreSQL switchover or partition, not a 500 (#3017).** #1083's
  fix covered timeouts and connection errors inside a route; four places
  still answered 500 (35 requests in one drill).
  - Agent and supervisor POSTs no longer read the maintenance flag at all:
    their paths pass a maintenance window whatever it says, so the
    middleware now checks the exemption first. For every other mutating
    request, a failed read of the flag answers the 503 rather than a 500
    (and does not let the request through as "not in maintenance", since
    the flag is unknown).
  - The request path now reuses the database-transient classifier the
    rolling upgrade and the supervisor heartbeat already use (#2177,
    #2845), on top of #1083's timeout / connection-error rule. That adds an
    `OSError` `EHOSTUNREACH` / `ENETUNREACH` (alone or inside an
    `ExceptionGroup`), a disconnect SQLAlchemy flagged, the old primary's
    "shutting down" (57P01) or read-only (25006) answer mid-statement, and a
    `PendingRollbackError` from an invalidated connection. A plain `OSError`
    counts only when the database driver raised it, so an unreachable WinRM,
    webhook or DNS target in a route keeps its 500, and a disk error never
    becomes a 503.
  - A temporary DNS failure resolving the database host (`EAI_AGAIN`, a
    node loss taking its CoreDNS replica) is now transient too, here and in
    the upgrade drive; an unknown name stays an error.
  - `get_db`'s cleanup no longer raises "response already started" when the
    closing rollback hits a closed connection or a timeout (logged at
    warning; any other cleanup error still propagates, and the close still
    runs to completion if the request is cancelled).
  - DHCP lease events no longer swallow a lost database connection in the
    DDNS, profiling or MAC-sighting step and then 500 on the session's next
    use; the batch answers 503 and the agent resends it. A DDNS target that
    refuses is still a logged skip.
  - A dependency-down error reaching the last-resort handler skips the
    diagnostics capture, which needs the database that is away.
  - The 503's wording no longer asserts the database is the cause: "a
    database failover or restart may be in progress".
