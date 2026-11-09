### Fixed

- DNSSEC signing is refused with a clear 422 on both Technitium drivers (agent-managed and agentless API), and the zone's DNSSEC card disables Sign for them, because signing there is one-shot and a zone would come back unsigned while SpatiumDDI showed it signed (#3806). Already-signed zones are untouched. The DNS docs now say Technitium DNSSEC is unsupported in 1.0, and the Technitium console notes describe that it listens on every interface at `:5380` (with a firewall recommendation for host-network standalone compose) instead of loopback.
