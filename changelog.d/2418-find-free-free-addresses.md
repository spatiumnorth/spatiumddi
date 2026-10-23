### Fixed

- IPAM Find Free: each candidate now carries its `free_addresses` (usable host count) so the result table's "Free addresses" column fills, and `min_free_addresses` filters on it instead of returning no candidate for any value (#2418).
