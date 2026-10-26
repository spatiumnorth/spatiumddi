### Changed

- **The importers and the branding logo check the login before reading
  the upload, and every request body is capped.** #2772 did the first for
  the upgrade-image and backup uploads; the DNS (BIND9), DHCP (Kea / ISC)
  and IPAM importers, the DNS zone spreadsheet import and the branding
  logo still read the whole upload before checking the login. They now
  run their own login and permission checks from the request headers
  first, with the same 401 / 403 answers and the same `denied` audit row.
  Separately, the api now caps every request body at
  `MAX_REQUEST_BODY_BYTES` (default **8 MiB**), answering **413** over it:
  a declared `Content-Length` over the cap is refused before any of the
  body is read, and a body without one is refused as soon as it passes the
  cap. nginx already limits `/api/` to 1 MiB; this applies to the api port
  itself. Backups (2 GiB), upgrade images (4 GiB), the importers (25 /
  50 MiB), the zone spreadsheet import (10 MiB), supervisor packet
  captures and the DNS agent's record ingest keep their larger limits. The
  HELD endpoints now stop reading at their 64 KiB document limit instead
  of reading the body whole first.
