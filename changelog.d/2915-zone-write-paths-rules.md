### Fixed

- **Every zone write path runs the zone rules (#2915, #2916, #2917).**
  Create-from-template stored what zone create refuses: a zone name
  with an empty label, a leading hyphen or a 64-character label, a
  `zone_type` that does not exist, and records whose values the record
  API refuses (an origin IP of `not-an-ip`, a DKIM selector of
  `bad selector`). It now applies zone create's name and type rules
  and the record API's owner, value and check-names rules to every
  record it would write, and answers 422 before anything is written or
  pushed. The Admin Email (SOA RNAME) had no host-name rule, so
  `hostmaster.under_score` was stored and BIND then refused the
  whole zone; it must now be a mailbox in domain-name form (a local
  part of letters, digits, hyphens and underscores, then host-name
  labels, at least two labels). On edit only a changed value is held
  to it. Zone create, zone edit and create-from-template also refuse a
  `view_id` that is not a view of the zone's own server group, with the
  422 the record API gives.
