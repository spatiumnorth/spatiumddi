### Fixed

- **DHCP scope lease times are validated (#2499).** `lease_time`,
  `min_lease_time` and `max_lease_time` must now be positive and
  satisfy `min <= lease <= max` on create and on update (the stored
  row merged with the patch); an out-of-order set returns 422 naming
  the field instead of stopping the whole group's Kea config.
