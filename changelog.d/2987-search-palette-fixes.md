### Fixed

- **Search: the palette opens every pick on the IPAM page, finds a subnet by a
  CIDR with host bits or by its own /32 or /128 address, counts matches
  honestly, and the IPAM address search matches `_` and `%` literally and a
  MAC in any notation (#2987, #2988, #2989, #2990, #2991).** On /ipam only the
  first palette pick opened (a one-shot latch); each pick is now applied. A
  CIDR typed as `10.0.96.5/24` is read as the network it names instead of
  making PostgreSQL refuse the cast (which answered "No results"), and
  containment is inclusive so a /32 or /128 subnet is found by its address.
  `GET /search` no longer lets `total` follow `limit`: each type is fetched up
  to a fixed cap of 100, `total` counts the matches within it and the new
  `total_capped` says when it is a floor, shown as "100+ results" in the
  palette; `total` is therefore a count of matches up to that cap, not of the
  rows returned, and an API client showing "N of `total`" should show "N+"
  when `total_capped` is set. The IPAM address search (`q`, `hostname`, `mac`)
  now reuses the global search's LIKE escaping, so "Select all" no longer
  hands a widened set to the bulk actions, and finds a MAC typed in any
  notation (dashed, bare, Cisco dotted, or a partial in whole octets such as
  `aa-bb-cc`). The match stays octet-aligned, so a hostname or address
  fragment such as `cafe`, `123` or `10.0.5` does not also match every MAC
  that happens to hold those digits across two octets.
