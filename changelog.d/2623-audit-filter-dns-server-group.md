### Fixed

- **Audit Log: the Resource filter's DNS server group entry matches DNS server group rows** — it sent `dns_group`, which matches nothing; those rows are written `dns_server_group`. (#2623)
