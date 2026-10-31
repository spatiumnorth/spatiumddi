### Fixed

- **A crash-looping DNS or DHCP container now raises an alert whatever
  the kubelet calls the cause, and a silent agent no longer reads `ok`
  (#2961).** Drilling #2188 case 4, a dhcp-kea container was memcg-killed
  six times in four minutes; the kubelet recorded `reason: Error`, exit 137
  (not `OOMKilled`), so only the OOM verdict existed and nothing fired,
  while the row read `unreachable` beside a stale `daemon_status=ok`.
  The supervisor heartbeat now also stamps `daemon_status=degraded` with a
  `crash_loop:` reason when the container has restarted at least 3 times
  within 15 minutes and is not a healthy pod, and with `agent_unreachable:`
  when the agent has been silent for 3 minutes while its appliance's
  supervisor still reports the container, counted only over time the
  control plane could have heard it (from the latest of its last heartbeat,
  the container's start, and the supervisor's current unbroken run of
  heartbeats, so a reboot or a control-plane outage is not the agent's
  silence). The restarts in the window are
  counted by the control plane across supervisor heartbeats, not read from
  the kubelet's lifetime `restartCount`, which grows by one on every node
  reboot and slot upgrade: a container just restarted by a reboot is not a
  loop, however many reboots it has seen. Both reasons name the evidence and
  feed the existing default-on `agent_daemon_degraded` rule, whose 5-minute
  grace runs from when the loop was established or the silence began,
  so one restart, a reboot or a brief blip stays silent. No new rule,
  setting or migration. A restarted agent's `ok` does not hide a crash loop
  (as for OOM); the agent's `ok` clears it once the pod is healthy. The
  health sweeps now set a stale `daemon_status=ok` on a server they read
  `unreachable` to NULL (unknown) instead of leaving it green.
- **`agent_daemon_degraded` words its message by who reported (#2962).**
  It said "the agent is heartbeating ... Agent reported" even when the
  supervisor reported the kill from the kubelet. A supervisor-sourced
  verdict now reads "Supervisor reported", a silent agent reads "not
  heartbeating", and only the agent's own report keeps the old text. The
  DNS and DHCP server responses gain `daemon_reported_by` (`agent` /
  `supervisor`), and the daemon chip and banner word themselves by it.
