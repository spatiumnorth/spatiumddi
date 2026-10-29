### Fixed

- **The Fleet reboot now shares the power-action wrapper's cancel and
  banner, and the web UI's Reboot button stays disabled during the
  handoff (#3008).** `spatiumddi-reboot-agent` ran the database-primary
  handoff itself, without the wrapper's cancel-safe trap and
  in-progress marker, so stopping it mid-handoff left the node cordoned
  until the next boot and the console showed no "handing off the
  database primary" banner. It now runs `spatium-power-action reboot`
  after its trigger checks, so all three paths (Fleet, web UI, console)
  are one implementation. The wrapper also holds a lock file in the
  release-state directory while it runs, which the system status
  endpoint reports as `reboot_in_progress`; the Reboot button stays
  disabled until the node goes down instead of re-enabling once the
  trigger file is renamed. The lock is released by the kernel if the
  wrapper dies, so nothing can be left stuck.
