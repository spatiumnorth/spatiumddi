### Added

- **Populate IPAM from existing DNS records (#2251).** A "Populate
  from DNS" button on a space, block or subnet previews and then
  creates IPAM addresses from A / AAAA records already in DNS, and
  links each to its record, so adopting a Windows DNS estate no longer
  starts with an empty IPAM. It writes no DNS: nothing is created,
  changed or re-published, and the next Sync DNS reads the pair as in
  sync. Conflicts are shown and never overwritten, DDNS-registered
  records are skipped unless you choose otherwise, and a re-run is a
  no-op. REST `POST /ipam/import/dns/{preview,commit}`; MCP
  `preview_populate_ipam_from_dns` and an approval-gated
  `propose_populate_ipam_from_dns`. The Windows Path B pull now keeps
  the record's aging timestamp (dynamic vs static).

### Migrations

- `c3d8a41f7b52` — #2251, adds the nullable `dns_record.dynamic` column.
