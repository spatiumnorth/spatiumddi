### Fixed

- **A supervisor heartbeat that meets a database failover answers 503,
  not 500 (#2845).** A CloudNativePG switchover drops the connection
  under whatever statement is running, and on a long-polling heartbeat
  that is usually the re-read of the appliance row after the hold. The
  error escaped as an unhandled 500 (on builds before #2807, as a
  `MissingGreenlet` from a log line reading a row the failed statement
  had expired), and the generic connection-closed handler recognised
  only some of the shapes a switchover produces. The heartbeat now
  answers any transient database error with 503 and `Retry-After`. The
  supervisor already treats a 5xx as a server error and retries on its
  next heartbeat; it is never a revocation strike, which only a 403
  marked `X-Spatium-Revocation` counts. A statement the database
  refused, and a revoked or deleted appliance, answer as before.
