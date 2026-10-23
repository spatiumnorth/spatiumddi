### Changed

- **API-token scopes match their path on a whole segment.** A scope's path
  prefix used to match any path that merely started with the same letters, so
  `dns:write` also allowed writes under `/api/v1/dnsbl/...` (IP reputation
  lists, pinned IPs, DNSBL settings and checks) and `/api/v1/dns-threat/...`
  (client mutes). It now covers `/api/v1/dns` and `/api/v1/dns/...` only.
  **Tokens that lose routes:** a token whose scopes include `dns:write` (and
  no unrestricted scope set) now gets `401 Token scope insufficient` on
  `POST`/`PUT`/`DELETE` under `/api/v1/dnsbl/` and `/api/v1/dns-threat/`.
  Nothing else changes for it: zones, records, server groups, views, RPZ
  blocklists (`/api/v1/dns/blocklists`) and DNS pools all live under
  `/api/v1/dns` and stay covered. No other scope loses a mounted route
  (`ipam:write`, `dhcp:write`, `agent` and `read` had no sibling mounts); the
  segment rule applies to them too, so a router mounted later is not granted
  to existing tokens by spelling alone. A token that must write DNSBL or
  DNS-threat settings needs an empty scope set, where the owner's RBAC is the
  only gate. The unused `/api/v1/dns-pools` prefix is dropped; pools are
  served under `/api/v1/dns/pools`.

### Fixed

- **The token reveal dialog no longer carries the raw token while it is
  masked.** The masked token element had the full value in its `title`, so a
  hover tooltip, or anything reading the element's accessible description,
  showed it before Reveal was pressed. The value is now present only in the
  revealed view and the copy action.
