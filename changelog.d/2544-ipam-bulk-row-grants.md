### Fixed

- **Bulk stale-IP deprecate checks each address against the caller's
  write grants.** `POST /ipam/reports/stale-ips/deprecate` now holds
  every row to the same per-row rule the single-address edit uses:
  write on the subnet, or an address set covering the address. A
  caller whose grants cover one subnet or one address set changes only
  those rows; the rest come back in `skipped`, as rows outside a
  subnet-bound token's scope already did. With `all_matching`, the
  selection is narrowed to subnets the caller can write in before the
  cap applies, so rows the caller cannot change no longer use it up.
  Callers with type-level subnet write, and superadmins, see no change.
