### Fixed

- **A DNS agent's op page no longer makes Postgres JIT-compile a
  9,000-term expression, or cost more as the backlog grows
  (#2289).** Each page of queued ops looked up the ops still
  backing off for the page's RRsets, and a failed ack looked up the
  ops queued after it, by matching `(zone, name, type)` keys as a
  row `IN` list of up to 3,000 tuples. Postgres cannot turn that
  into an array comparison, so the plan was costed over
  `jit_above_cost` and compiled in the backend and every parallel
  worker, and with no index on `next_attempt_at` its cost also grew
  with the server's whole queue. Measured on a scratch Postgres 16:
  5.6 s and 870 MB per process at 600k queued ops, 309 s and
  1.7 GB at 1.41M. Seven agents polling a 600k-op backlog
  OOM-killed the primary at 4, 8 and 12 GiB. The keys now ride as
  three array parameters joined through `unnest()`, so the
  statement is the same size for any key count. The page reads its
  candidates through a new partial index over the ops actually in
  a retry wait, so its cost follows the page and those ops. At
  1.41M queued ops it runs in 6 ms with no JIT, or 340 ms with
  199k ops of the server backing off. It matches the same rows,
  and the op paging and lock order are unchanged.

### Migrations

- `f27379a82b17` — #2289, schema only: partial index
  `ix_dns_record_op_server_backoff` on `dns_record_op (server_id,
  next_attempt_at) WHERE state = 'pending' AND next_attempt_at IS
  NOT NULL`. It covers only ops in a retry wait, so it is small and
  builds quickly. Downgrade drops it.
