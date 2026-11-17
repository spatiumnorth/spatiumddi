### Fixed

- **BIND9 image returns freed memory to the OS (#4192).** Alpine's
  named runs on musl malloc, which keeps freed pages, so removing a
  view or reloading a large RPZ left the memory resident until the
  container restarted. The image now links jemalloc into named with
  prompt page decay (measured: 439 MB to 274 MB after removing one of
  two views holding a 300k-entry RPZ). Set `SPATIUM_MALLOC_CONF` to
  change the options (not possible when the container starts as a
  non-root uid).
