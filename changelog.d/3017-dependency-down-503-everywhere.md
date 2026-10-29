### Fixed

- **Every database-unavailable error now answers 503 with `Retry-After`
  during a PostgreSQL switchover or partition, not a 500 (#3017).** #1083's
  fix covered timeouts and connection errors inside a route; four places
  still answered 500 (35 requests in one drill). The maintenance-mode
  middleware's own settings read runs outside the exception handlers, so a
  refused connection or a timeout there 500'd every agent and supervisor
  POST; it now answers the same 503 (and does not let the request through
  as "not in maintenance", since the flag is unknown). A plain `OSError`
  with errno `EHOSTUNREACH` / `ENETUNREACH` (and the other
  unreachable-network errnos), alone or inside an `ExceptionGroup`, is now
  classified as dependency-down; other `OSError`s, such as disk errors,
  still 500. `get_db`'s cleanup no longer raises "response already
  started" when the closing rollback hits a closed connection or a
  timeout (logged at warning; any other cleanup error still propagates). A
  `PendingRollbackError` from an invalidated connection answers 503; the
  flush-failure kind stays a 500. A purely dependency-down error reaching
  the last-resort handler skips the diagnostics capture. The classifier
  now lives in one place, `app/core/dependency_down.py`.
