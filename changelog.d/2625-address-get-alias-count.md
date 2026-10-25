### Fixed

- **`GET /ipam/addresses/{id}` now reports the address's alias and NAT
  counts (#2625).** The single-address read answered `alias_count: 0` for an
  address whose alias the subnet's address list counted, though the schema
  says both endpoints fill it. It now stamps `alias_count`,
  `nat_mapping_count` and the OUI vendor the way the list does.
