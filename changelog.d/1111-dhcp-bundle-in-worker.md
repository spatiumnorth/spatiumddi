### Changed

- The DHCP config bundle is now built once in the worker and stored, and the agent long-poll serves the stored bundle instead of rebuilding it on the API for every agent on every wake. The agent wire format and ETags are unchanged. A bundle is re-rendered when its inputs change and at least every 15 seconds; if the worker has not produced one within five seconds, the poll builds it inline as before. (#1111)

### Migrations

- `e7a3c91d5b28`: adds the `dhcp_agent_bundle` table and `dhcp_server.bundle_dirty_seq`. (#1111)
