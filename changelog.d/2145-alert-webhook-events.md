### Added

- **Webhooks publish `alert.fired` and `alert.resolved` (#2145).**
  Alert transitions are now typed, HMAC-signed webhook events with a
  versioned JSON body (rule, severity, subject, fired / resolved
  timestamps, a link to the Alerts page, and the alert event id to
  dedupe on). They go through the same outbox, retry and dead-letter
  path as other event types and are selectable per subscription.
  Alert forwarding is unchanged.
