### Fixed

- **A DNSSEC policy's key lifetime that BIND refuses is refused at save
  (#3411).** A KSK or ZSK lifetime that is negative, past 49710 days, or
  shorter than a rollover of that key takes (a KSK under 2 days, a ZSK
  under 11) is now a 422 that gives the range BIND takes, on create and
  on edit. Before, it was stored, and once a zone was signed with the
  policy `named-checkconf` refused the whole config, so every later
  change on the server group was quarantined until the zone was
  unsigned. A policy already saved that way renders with the nearest
  lifetime BIND takes (a negative one as unlimited), with a warning.
