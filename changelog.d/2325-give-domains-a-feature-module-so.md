### Fixed

- **Domains had no feature module, so the daily off-prem RDAP refresh
  could not be switched off (#2325).** The Domains router was mounted
  ungated and the hourly `refresh_due_domains` sweep ran regardless; the
  only way to stop the lookups of each domain name against the IANA
  bootstrap and the TLD registries was to delete every Domain. There is
  now a `network.domains` module (Settings → Features, group Network).
  Off, the Domains pages, API, sidebar entry, dashboard card and
  `list_domains` tool disappear, and neither the sweep nor the lookup
  queued at create time makes any RDAP call. It ships **off** on a fresh
  install, so nothing is sent, but resolves **on** wherever Domain rows
  already exist (`default_on_if_rows_in`, as `ipam.nat` does, with no
  seeded row), so an upgraded install keeps its pages and expiry
  tracking; an explicit setting wins either way. `docs/PRIVACY.md` §3.3
  names the switch.
