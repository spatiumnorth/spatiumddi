### Fixed

- **Edit DHCP Scope no longer closes as saved on a group change it
  does not store (#2479).** The dialog shows the scope's group
  read-only, and a `PUT /dhcp/scopes/{id}` naming a different
  `group_id` is refused with a 422 instead of being ignored.
