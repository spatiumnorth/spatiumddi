### Fixed

- **Every zone write path runs the zone rules (#2915, #2916, #2917).**
  Create-from-template stored what zone create refuses: a zone name
  with an empty label, a leading hyphen or a 64-character label, a
  `zone_type` other than primary (a secondary or stub with no masters,
  or a forward zone, none of which serves the template's records), and records whose values the record
  API refuses (an origin IP of `not-an-ip`, a DKIM selector of
  `bad selector`). It now applies zone create's name and type rules
  and the record API's owner, value and check-names rules to every
  record it would write, and answers 422 before anything is written or
  pushed. The Admin Email (SOA RNAME) had no host-name rule, so
  `hostmaster.under_score` was stored and BIND then refused the
  whole zone; it must now be a mailbox in domain-name form, checked
  the way BIND checks it: a local part of any printable character
  (`admin+dns` is fine), then host-name labels, at least two labels.
  On edit only a changed value is held to it, and the BIND9 agent
  serves the `admin.<zone>` placeholder in place of a stored value
  BIND would refuse, so a zone saved before the rule is served. Zone create, zone edit and create-from-template also refuse a
  `view_id` that is not a view of the zone's own server group, with the
  422 the record API gives.
