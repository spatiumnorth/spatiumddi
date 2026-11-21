### Fixed

- Importing an IPAM export back (CSV, XLSX or JSON) no longer stores its computed columns (`total_ips`, `allocated_ips`, `utilization_percent`, and an address's `last_seen_at`) as custom fields on every subnet and address; they are skipped, and the import preview lists the skipped columns once. A JSON export's subnet `custom_fields` object now imports as the subnet's custom fields instead of one nested `custom_fields` entry.
