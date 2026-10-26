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
