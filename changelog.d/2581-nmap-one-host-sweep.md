### Fixed

- A subnet or CIDR sweep that finds exactly one host is now stored as a sweep, so the console offers Stamp and `stamp-discovered` records it in IPAM; a sweep that finds nothing stamps nothing instead of answering 422 (#2581).
