### Fixed

- **Settings' four DNS defaults now apply to new zones and server groups
  (#3087).** Default Zone TTL, Default Zone Type, Default DNSSEC Validation
  and Recursive by Default were stored and read by nothing: Add Zone and
  New Server Group started from fixed values, and so did the API. Add Zone
  now starts with the stored Type and TTL, New Server Group with the stored
  Allow recursion, and a zone created without a TTL, or a group created
  without `is_recursive`, takes the stored value (a new group's DNSSEC
  validation does too, including a group a DNS agent creates when it
  registers). A value sent in the request always wins, and an import keeps
  the TTL its source carried, using the default only for a zone that had
  none. The API's zone type still defaults to Primary when omitted: the
  setting only pre-selects the form, because a forward or secondary zone
  needs forwarders or masters a bare create never sends. A default that
  was changed while it did nothing now takes effect on the next new zone
  or group; stock values are unchanged.
