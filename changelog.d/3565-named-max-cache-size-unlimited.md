### Fixed

- The BIND9 agent no longer accepts `unlimited` or `0` for `NAMED_MAX_CACHE_SIZE`: BIND 9.21.21+ stops honouring them and falls back to 90% of host memory. An existing install that sets one still starts; the value is ignored with a warning and the container-limit-derived cache ceiling applies (#3565).
