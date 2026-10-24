### Fixed

- **A TSIG key secret must be one base64 string, and the BIND9 key file
  only ever holds well-formed key statements.** Creating a key now
  refuses a secret that is not valid base64 or decodes to fewer than 16
  or more than 512 bytes, and updating a key refuses a secret instead of
  silently ignoring it (rotate replaces a secret). A key stored before
  this whose secret is not one base64 string is left out of the agent
  bundle with a warning, along with any reference to it, and the BIND9
  agent re-checks every key before writing its key file and skips one
  that would not form a complete `key {}` statement.
- **`none` in `allow_transfer` keeps its meaning on BIND9.** BIND reads
  `none` as "deny everyone from here on", and the agent dropped it from
  any list that had other entries, so `["none", "10.0.0.0/8"]` rendered
  as "allow 10.0.0.0/8". The list is now rendered in order after the
  group's key grants, which is how the Technitium agent already
  translates it, and the API refuses an `allow_transfer` list that
  combines `none` with other entries, on group options and on zones.
  A group or zone stored with `none` ahead of other entries allows
  transfers only to the TSIG key holders after the upgrade; set the list
  to the addresses that should transfer, or to `["none"]`.
