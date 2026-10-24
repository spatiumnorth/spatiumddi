### Fixed

- **The restore-drill orphan reaper no longer drops a running drill's
  scratch database (#2272).** The reaper treats a `spatiumddi_drill_*`
  database with no backend as orphaned, but a drill had none between
  `CREATE DATABASE` and `pg_restore` connecting, which is as long as it
  takes to write the dump to disk. A sweep tick on another worker could
  drop it in that window, and the drill then recorded a false
  `dump_replays_cleanly` failure and a `restore_drill_failed` alert. The
  drill now holds a connection on the scratch database from creation
  until just before the drop.
