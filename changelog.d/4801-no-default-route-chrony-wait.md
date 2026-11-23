### Fixed

- Appliance: k3s now starts on a network with no default route (an isolated or air-gapped segment) instead of exiting every 5 s so first boot never converged; with no route it binds to the management interface's current address. The systemd journal is now persistent, so a first-boot failure's logs survive a reboot. `chrony-wait.service` is masked, so an unreachable time source no longer leaves the system `degraded` 3 minutes after every boot, and Appliance → NTP now shows the node's NTP sync state with a calm "no time source reachable" message.
