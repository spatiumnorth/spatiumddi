### Fixed

- **Backup retention of 0 no longer deletes every archive (#2503).**
  `retention_keep_last_n` and `retention_keep_days` now require at
  least 1, and the retention sweep never removes the newest backup or
  the archive a run has just written, so a stored 0 behaves as 1. A
  retention failure after a successful write now leaves the run
  `success` and shows on the target's last-run error line instead of
  marking the backup failed.
