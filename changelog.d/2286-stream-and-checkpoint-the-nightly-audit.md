### Fixed

- **The nightly audit-chain verify no longer loads the whole
  `audit_log` into memory (#2286).** It read every row as an ORM object
  in one query, so on an aged install (the log is never pruned) the
  worker ran out of memory or hit the database timeout every night and
  tamper detection quietly stopped. The walk is now paged by `seq`
  (5,000 rows at a time, plain tuples, the previous hash carried across
  pages), so memory stays flat. The task records how far it verified in
  the new `audit_chain_checkpoint` table and checks only rows added
  since, re-walking the whole chain once a week and whenever the
  checkpoint no longer matches the table (a restore, a rewritten row)
  or its recorded full-pass time lies in the future, so an edit to an
  already-verified row is alerted within a week, not overnight
  (documented in SYSTEM_ADMIN.md §2.7). A run that dies keeps its progress but fails loudly; it is never
  reported as verified. `GET /audit/integrity` keeps its existing answer: a capped check reports
  `partial`, `rows_checked` and the `first_seq` / `last_seq` it walked
  (#2297). Migration `e7b2d4c81f06`.
