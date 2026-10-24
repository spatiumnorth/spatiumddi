### Fixed

- **Restoring a DHCP scope now runs the server group's prefix guard
  (#2733).** A trashed scope frees its prefix in the group, so a scope
  on the same CIDR of another IP space could be created meanwhile.
  Restoring the old scope answered 200 and left two active scopes on
  one prefix in the group. The config bundle kept the older one and
  silently dropped the live scope created through the front door, so
  its clients got no lease. The restore now refuses with the reason
  the create and the activation give (#844), whether the scope comes
  back from its own Trash row, its subnet's or its block's. An inactive
  scope renders nothing and restores as before.
