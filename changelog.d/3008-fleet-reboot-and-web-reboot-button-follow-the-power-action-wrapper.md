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
  Reboot button stays disabled until the reboot has been issued instead
  of re-enabling once the trigger file is renamed. The lock is on the
  directory, opened read-only, not on a file in it: the api and the
  supervisor can write in that directory and the wrapper runs as root,
  so a lock file could have been a planted symlink. The kernel releases
  the lock if the wrapper dies, so nothing can be left stuck. The info
  also gains `node`, the node it describes: these fields come from the
  host of the node whose api pod answered, which on a multi-node control
  plane is a per-request choice (Fleet's per-appliance `reboot queued`
  remains the per-node answer there).
