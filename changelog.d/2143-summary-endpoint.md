### Added

- `GET /api/v1/summary`: one read-only snapshot of platform health, IPAM, DNS, DHCP, alerts and new-device counts for external pollers such as Home Assistant, in a constant number of queries. A section the caller may not read comes back `null` with the reason in `withheld`, and a token bound to specific subnets or zones gets no whole-estate counts. The same data is the `get_platform_summary` Copilot tool.
