### Fixed

- A DNS or DHCP server whose agent container restarted no longer keeps reading the previous `ok` config-apply and daemon state while the new process boots: the agent now announces itself with a heartbeat before it applies its cached config, the server clears the old `ok` to unknown at once, and a restart that fails to apply reads the failure. The DHCP agent's cache boot now reports its applied status, so its row returns to `ok` instead of staying unknown.
