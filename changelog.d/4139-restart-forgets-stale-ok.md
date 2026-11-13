### Fixed

- A DNS or DHCP server whose agent container restarted no longer keeps reading the previous `ok` config-apply and daemon state until the agent's first report; the new agent process clears it to unknown on its first config poll, so a restart that fails to apply is never shown as converged in the meantime.
