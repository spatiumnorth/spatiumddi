### Fixed

- **The zone-file import holds each row to the record API's rules
  (#2912, #2913, #2914).** Import zone file stored owners the record API
  and the spreadsheet import refuse (`under_score` on an A record,
  `a\032b`), and BIND9 then held the whole zone back, so the good rows
  imported beside the bad one were not served either. A new row now
  meets the same owner, check-names and value rules; one that fails is
  left out and listed under "Left alone" in the preview and the result
  with its reason, and the rest import.
  A TTL of 0 is stored as 0 instead of as no TTL. A TTL past
  2147483647 is reported and left out instead of being dropped without
  a word, so a merge no longer overwrites a record's explicit TTL with
  none, and a replace keeps the record such a row names rather than
  deleting it. A row of a type SpatiumDDI does not store (HINFO, DNSSEC types)
  is now named, by type and count, in the preview and the result.
  The list of rows left alone is capped at 500 entries plus a count of
  the rest, so a file of refused rows cannot grow the response and the
  audit row without bound.
