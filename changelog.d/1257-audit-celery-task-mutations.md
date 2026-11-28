### Fixed

- Celery tasks now audit the operator-visible state they change, with one summary `<system>` audit row per run: the DHCP lease expiry sweep (IPAM mirrors removed and DDNS revoked), blocklist feed refreshes that change a list's entries, and the revoked-appliance and spent-pairing-code prunes. A guard test fails when a task module writes rows without an audit path (#1257).
