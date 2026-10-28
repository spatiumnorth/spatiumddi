### Fixed

- **A crash-looping DNS or DHCP container now raises an alert whatever
  the kubelet calls the cause, and a silent agent no longer reads `ok`
  (#2961).** Drilling #2188 case 4, a dhcp-kea container was memcg-killed
  six times in four minutes; the kubelet recorded `reason: Error`, exit 137
  (not `OOMKilled`), so only the OOM verdict existed and nothing fired,
  while the row read `unreachable` beside a stale `daemon_status=ok`.
  The supervisor heartbeat now also stamps `daemon_status=degraded` with a
  `crash_loop:` reason when the container has restarted at least 3 times,
  last ended within 15 minutes and is not a settled healthy pod, and with
  `agent_unreachable:` when the agent has been silent for 3 minutes while
  its appliance's supervisor still reports the container. Both name the
  restart count, last termination reason and exit code, and feed the
  existing default-on `agent_daemon_degraded` rule, whose 5-minute grace
  (timed from the loop's first sighting or the agent's last heartbeat)
  keeps one restart or a brief blip silent. No new rule, setting or
  migration. A restarted agent's `ok` does not hide a crash loop (as for
  OOM); the agent's `ok` after 10 stable minutes clears it. The health
  sweeps now set a stale `daemon_status=ok` on a server they read
  `unreachable` to NULL (unknown) instead of leaving it green.
- **`agent_daemon_degraded` words its message by who reported (#2962).**
  It said "the agent is heartbeating ... Agent reported" even when the
  supervisor reported the kill from the kubelet. A supervisor-sourced
  verdict now reads "Supervisor reported", a silent agent reads "not
  heartbeating", and only the agent's own report keeps the old text.
