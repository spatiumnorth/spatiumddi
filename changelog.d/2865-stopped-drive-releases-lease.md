### Fixed

- **A Rolling Upgrade whose drive's worker is stopped mid-run no longer
  waits ten minutes for the run's Lease (#2865, #2869).** A worker pod
  stopped during a run (rolled by a chart change, drained, or deleted) shut
  down warm: it waited for its running tasks, and the run's drive, which runs
  for as long as the run, went on renewing the run's Lease through the pod's
  grace period until it was killed with the Lease held. Nothing drove the run
  until the 600 s Lease lapsed and the orphan sweep re-drove it. The worker
  now stops a running drive as soon as its own shutdown starts, and a drive
  that is stopped releases its Lease (only its own) on the way out, so the
  drive put back on the queue, or else the orphan sweep within about two
  minutes, takes the run over. The worker logs
  `upgrade_drive_stopped_for_worker_shutdown` and `upgrade_drive_stopped`.
