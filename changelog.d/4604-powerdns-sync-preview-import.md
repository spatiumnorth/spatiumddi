### Fixed

- PowerDNS: Sync with Servers no longer counts a server whose every zone failed as succeeded, and the button is disabled for PowerDNS-only groups; the `pdns.conf` preview now matches the agent's fixed settings (LUA records, dual-stack listen address, ALIAS resolver, query logging) and is labelled a template; the PowerDNS importer now imports SVCB / HTTPS / DNAME always and ALIAS / LUA into a PowerDNS group; and the agent no longer reads a log-level option the bundle never carries (#4604).
