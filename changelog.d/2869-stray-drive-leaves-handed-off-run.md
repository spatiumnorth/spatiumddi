### Fixed

- **A Rolling Upgrade no longer stalls for ten minutes after its tag flip
  when its drive was delivered twice (#2869).** At a broker drop Celery
  puts the running drive task back on the queue, so the run holds a second
  copy of its own drive. When the first copy flipped the shared tags and
  handed the run to the new version, releasing the Lease for it, that copy
  ran on an old-version worker, took the Lease over and went on to the
  settle wait on the old version. The rollout then stopped its worker with
  the Lease held, and the new version's drive was refused until the 600 s
  Lease lapsed and the orphan sweep re-drove the run. A drive still on the
  version the run was handed off from now leaves the run alone unless it is
  the hand-off's own continuation (which still runs there once no worker
  on the new version has taken it for 10 minutes). A Resume made after the
  hand-off is passed on to the new version, as the continuation is. The
  worker logs `upgrade_drive_stray_after_version_handoff`.
