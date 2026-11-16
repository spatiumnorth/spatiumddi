### Fixed

- Logs → DNS Queries and DHCP Activity: a click anywhere on a row (or Enter / Space on the focused row) now opens its details, not only the small arrow; selecting text in a row does not open it, and focus returns to the row when the details close.

- Logs → DNS Queries: the client shows as `ip:port` (IPv6 as `[addr]:port`) instead of BIND's `ip#port`; the raw line is unchanged and Filter by client still filters by the address.
