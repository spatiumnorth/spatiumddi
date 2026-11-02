### Fixed

- **A Fleet Boot once now arms its slot once, and a trial that falls back no longer leaves the request stuck (#3284).**
  The node re-ran set-next-boot on every heartbeat until the slot booted, and
  when the trial of that slot fell back to the running slot the request was
  never cleared: the node armed the failed slot again about every 30 seconds,
  the Boot once button stayed disabled and the heartbeat long-poll stayed off.
  The supervisor now runs one set-next-boot per request and reports the run
  with the boot it ran in, and once a reboot has spent the request the control
  plane retires it, whether the slot booted or fell back.
