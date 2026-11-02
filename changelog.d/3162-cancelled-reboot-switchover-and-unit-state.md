### Fixed

- **Cancelling a reboot with F9 after the database handoff began now says the
  switchover still completes, and a cancelled reboot no longer leaves its unit
  "failed" (#3162).** Once the handoff has cordoned the node, CloudNativePG has
  been asked to move the PostgreSQL primary, and a switchover it has begun
  cannot be taken back; the console now tells the operator that the switchover
  completes (a few seconds of API unavailability) and that the node stays up.
  A cancel inside the console's 10 s grace still asks the database for nothing.
  A cancelled power action, and a cancelled Fleet reboot, now end as a clean
  stop, so `systemctl` no longer reports `spatium-power-action@reboot.service`
  or `spatiumddi-reboot-agent.service` as failed; a `systemctl reboot` that
  fails is still reported as a failure.
