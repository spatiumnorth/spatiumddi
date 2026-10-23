### Fixed

- **The New Role dialog offers every resource type (#2439).** Twenty
  types the built-in roles grant (`nat_mapping`, `tls_cert`,
  `multicast`, `manage_dns_pools` and more) and the others
  `docs/PERMISSIONS.md` lists were missing from the resource type
  select, so a custom role could not carry them. They are added, and a
  test pins the list to the docs table and the built-in grants.
