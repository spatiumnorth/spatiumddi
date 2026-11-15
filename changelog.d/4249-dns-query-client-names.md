### Added

- Logs → DNS Queries can resolve client addresses to host names: a "Resolve client names" toggle with a source of Reverse DNS (private and non-public clients only, cached for 5 minutes) or one IP space's IPAM host names (only addresses you may read). Also available as `resolve_clients` / `ip_space_id` on `POST /logs/dns-queries` and the Copilot's DNS query-log tools.
