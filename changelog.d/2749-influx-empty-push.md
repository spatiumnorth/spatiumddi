### Fixed

- **An InfluxDB target that sent nothing no longer shows an accepted push (#2749).**
  A tick with nothing to send (every "What this target carries" box
  unticked, or no new samples) contacts no one, yet it set Last push and
  cleared the target's failure, so a target on an unreachable host read
  healthy once its boxes were unticked. Such a tick now only advances the
  interval clock: Last push stays "never" or the last real success, and a
  recorded failure stays until a push is actually accepted.
