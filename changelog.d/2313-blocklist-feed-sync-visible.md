### Fixed

- **Blocklist rows hide feed failures; nothing alerts when a feed stops
  refreshing (#2313).** Feed-sourced blocklist rows now carry a sync
  chip (red on a failed refresh, amber past 3 update intervals without
  a success, grey when never synced), and a new default-on
  `dns_blocklist_feed_stale` alert fires per stale list. Manual-only,
  disabled and hand-made lists show no `never synced` / `stale` chip and
  never alert; the alert text carries a fixed reason, not the stored fetch
  error.

### Migrations

- `c4a8e2f7b913` — #2313, adds `dns_blocklist.last_success_at`,
  backfilled from rows whose last sync succeeded.
