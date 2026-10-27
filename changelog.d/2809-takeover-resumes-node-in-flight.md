### Fixed

- **A Rolling Upgrade whose drive dies in the middle of a node now finishes
  that node (#2809).** The drive that took the run over started the node
  again at `preflight`, whose CNPG wait counts the node's own Postgres
  instance. The dead drive's drain had evicted that instance and the cordon
  kept it Pending, so the wait timed out after 900 s and the run failed
  `preflight_fail` with the node still cordoned and the CNPG maintenance
  window still open, and the alert did not say so. The per-node chain now
  records which step it is on before each step (`progress.in_flight`, with
  the run's stamp time and the node's schedulability before the cordon), and
  a drive that takes over resumes the node at that step. Every step is safe
  to run again. A failure after a takeover releases the cordon and the
  window the earlier drive took, and the run's events and per-node record
  say where the node was resumed (`resumed_at`).
  The node in flight is driven first, whatever the plan order or the new
  drive's own node, so no other node's preflight can start while it is
  still cordoned.
- **A rolling upgrade's drive no longer crashes at the end of a node after
  a Postgres switchover (#2809).** When a statement met the switchover, the
  rollback that followed expired the run row the drive was holding, and the
  next read of it raised `MissingGreenlet` ("orchestrator crashed:
  greenlet_spawn has not been called"), failing a run whose node had
  upgraded. The drive now never loads an expired attribute of the run, and
  the step checkpoint is retried on a fresh connection through the
  switchover, as a step is.
- **A rolling upgrade whose drive crashed now raises the
  cluster-upgrade-failed alert (#2809).** Only the drive's own failure paths
  raised it, so a run the crash handler marked failed paged nobody. The
  alert, and the run's error, name the node that was in flight, its step,
  and whether it may still be cordoned or in the CNPG maintenance window.
