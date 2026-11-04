### Fixed

- **A block's and a space's Sync DNS are no longer offered to a holder
  the server refuses (#3334).** Like the subnet's since #2571, each
  stays visible and disabled with its reason, asking what its routes
  ask: read on IP blocks (or IP spaces) and IP addresses for the
  preview, and write on IP blocks (or IP spaces) for Apply, all at the
  type level. A read-only user (the built-in Viewer) could open the
  dialog and press Apply, and both of Apply's requests were refused.
  The API gates are unchanged.
- **The Sync DNS dialog's reverse-zone backfill note says the server's
  reason (#3334).** A refused backfill read "Reverse-zone backfill
  skipped: Request failed with status code 403"; it now carries the
  server's own words, as the Apply failed line beside it does.
