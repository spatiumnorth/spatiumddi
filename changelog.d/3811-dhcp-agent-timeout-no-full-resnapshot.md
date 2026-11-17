### Fixed

- DHCP agent: one timed-out or 5xx lease-events post no longer triggers a full lease-table re-post; the batch is retried from the spool under the same `batch_id` (with jittered backoff), and a `control_plane_recovered` snapshot is requested only after a real outage (connection failure or 5 consecutive failed posts) (#3811).
