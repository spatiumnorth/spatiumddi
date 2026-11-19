### Added

- DNS server groups have a **Resolver cache size per view** setting (`max_cache_size`, a BIND size such as `64m`), carried in the config bundle and rendered as `max-cache-size` for each recursive view. It takes precedence over `NAMED_MAX_CACHE_SIZE` and the derived quarter-of-limit default; `unlimited` and `0` are refused (#4185, part of #4183).

### Migrations

- `b7d2e4f81c59` — #4185, `dns_server_group.max_cache_size` (nullable) holds
  the group's BIND resolver cache ceiling.
