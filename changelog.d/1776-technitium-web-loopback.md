### Fixed

- The agent-managed Technitium web console and API now listen on loopback only instead of every interface on `:5380`. Fresh installs bind to `127.0.0.1` from first boot, and existing ones are switched once on the next apply; the agent's own API access is unaffected. The docs that claimed loopback are now true (#1776).
