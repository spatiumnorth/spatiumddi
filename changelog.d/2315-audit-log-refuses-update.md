### Fixed

- **The audit log refuses UPDATE, and its conformity check now checks
  that (#2315).** `audit_log_immutable` passed whenever `audit_log`
  could be counted, so it still passed with the no-delete trigger
  dropped, and nothing stopped an UPDATE rewriting a row. A new
  `BEFORE UPDATE` trigger refuses updates, and the check reads
  `pg_trigger` and fails, naming the trigger, when the DELETE or UPDATE
  guard is missing, disabled or altered. The table is tamper-evident,
  not tamper-proof: the database owner can still drop the triggers,
  which is what the check reports. TRUNCATE stays unguarded, because a
  selective restore of the audit section truncates the table.

### Migrations

- `8ef2ed5e45c8` — #2315, adds the `audit_log_no_update` BEFORE UPDATE
  trigger and its `audit_log_block_update()` function.
