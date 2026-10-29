### Fixed

- **The Fleet reboot now shares the power-action wrapper's cancel and
  banner, and the web UI's Reboot button stays disabled during the
  handoff (#3008).** `spatiumddi-reboot-agent` ran the database-primary
  handoff itself, without the wrapper's cancel-safe trap and
  in-progress marker, so stopping it mid-handoff left the node cordoned
  until the next boot and the console showed no "handing off the
  database primary" banner. It now runs `spatium-power-action reboot`
  after its trigger checks and its 5 s grace, so all three paths
  (Fleet, web UI, console) are one implementation. The wrapper also
  holds an `flock` on the release-state directory while it runs, which
  `GET /appliance/system/info` reports as `reboot_in_progress`; the
  Reboot button stays disabled until the node goes down instead of
  re-enabling once the trigger file is renamed. The lock alone covered
  under two seconds of a one-node reboot, so `reboot_in_progress` also
  reads a pending web-UI or Fleet trigger, the Fleet agent's grace
  marker, and a `power-action-issued` marker the wrapper writes just
  before `systemctl reboot`, stamped with the host's boot id so it
  expires by itself with the reboot. The Maintenance tab polls every 5 s
  (2 s while a reboot is under way) instead of every 15 s, which missed
  Fleet and console reboots entirely. The lock is on the
  directory, opened read-only, not on a file in it: the api and the
  supervisor can write in that directory and the wrapper runs as root,
  so a lock file could have been a planted symlink. The kernel releases
  the lock if the wrapper dies, so nothing can be left stuck. The info
  also gains `node`, the node it describes: these fields come from the
  host of the node whose api pod answered, which on a multi-node control
  plane is a per-request choice (Fleet's per-appliance `reboot queued`
  remains the per-node answer there).
- **A Fleet reboot can be cancelled with the console's F9 during its 5 s
  grace (#3008).** The reboot agent renames its trigger before the grace,
  and the wrapper's marker only exists after it, so F9 answered "No reboot
  is currently pending" and the node rebooted. The agent now holds a
  `reboot-fleet-grace` marker (written under a fresh name and renamed into
  place, as every root write in release-state must be) from before it
  takes the trigger until it exits; the console counts it while its process
  is alive and its boot id is current, and F9 stops the agent before it
  calls the wrapper. The supervisor writes a Fleet trigger at most once per
  boot (#1446), so a cancelled Fleet reboot is not fired again; Fleet's row
  keeps reading the reboot as queued until the node next boots, as it
  already did for a cancel during the handoff.
- **The console no longer says it is handing off the database primary on
  a one-node install,** where there is no primary to hand off; it names
  the handoff only on a multi-node cluster.
