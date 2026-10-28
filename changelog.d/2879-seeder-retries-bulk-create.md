### Fixed

- **The perf seeder retries a records bulk-create batch answered 502, 503
  or 504 before it counts the batch failed (#2879).** One such answer, the
  API's 503 "A backend dependency did not answer in time" with
  `Retry-After: 2`, counted all 1000 records of its batch failed and,
  past the seed's max(10, 1%) bound, failed the seed (rc 3) and the load
  run with it. The batch is now sent again, never sooner than
  `Retry-After` asks (honoured up to 30 s), otherwise backing off with
  jitter: at most 8 sends and 120 s of waiting per batch. Each resend is
  a `bulk_create_retry` log event, and the seed manifest counts them
  (`authoritative_records.retries`), so a load that completed only on
  retries says so. Records an earlier send had already committed come
  back skipped from bulk-create and count as `already_present`, never
  twice. The Perf — Tests job now installs httpx, the seeder's own
  import, so the seeder's tests run there.
