### Fixed

- **The group-level `allow_query_cache` option now reaches named
  (#2264).** It was accepted, validated and stored, but never
  shipped in the bundle, so only a per-view override rendered and
  BIND fell back to its own default (derived from `allow-recursion`),
  which meant narrowing cache access to stop cache snooping did
  nothing. The BIND9 agent now renders `allow-query-cache { ... };`
  in `options {}`, dropping elements named-checkconf would refuse
  and failing closed to `none`. A group still at the stored default
  (`localhost; localnets;`) ships nothing and renders byte-identical
  config, so an upgrade reloads no daemon. PowerDNS and Technitium
  have no such setting: a non-default value is refused with a 422
  for a group holding one, rather than stored and ignored.
