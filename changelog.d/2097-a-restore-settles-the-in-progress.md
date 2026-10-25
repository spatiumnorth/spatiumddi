### Fixed

- **A restored backup no longer brings back its own run's
  "in progress" claim (#2097).** The runner commits its claim before
  the dump, so every archive a target's own run wrote held that target
  `in_progress`. Restoring it left the target refusing Run now (409)
  and off its schedule for up to 2 h, after which the reap stamped a
  run that had succeeded `failed`, and the multi-node "on node" text
  was lost. The archive manifest now records which target wrote it
  (`run`: target, filename, node, and the exact time its claim was
  stamped), and a restore that brings back the backup-target table
  settles the claims the archive can have produced: the writing
  target, recognised by that exact claim time, becomes `success` with
  its filename and node; any other `in_progress` claim stamped at or
  before the archive's creation becomes `failed` ("outcome not
  recorded"), which a watched target's backup-failed alert reports
  until its next run; and `next_run_at` is recomputed. A claim made
  after the archive was taken is a live run's and is left alone. Each
  settled target gets a `backup_target_run_reconciled` audit row, and
  the restore audit row lists them. No migration. Archives taken
  before this change carry no `run` record, so their claims settle as
  `failed`. The stale-run reap (the schedule sweep's, and Run now's)
  now re-reads the target under a row lock and stands down while a
  restore holds its lock, so a sweep tick landing between the replay's
  commit and the settle can no longer reap an archive's two-hour-old
  claim and fire a second run.
