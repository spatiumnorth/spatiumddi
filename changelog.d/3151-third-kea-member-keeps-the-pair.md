### Fixed

- **A third Kea server joining a working HA pair's group no longer turns HA
  off for the pair (#3151).** Its HA Peer URL is left empty on purpose (#2963),
  and one member without a URL used to stop every member of the group loading
  the HA hook, leaving all three serving the same pools with no lease sync
  between them. Now the two servers with a URL keep running HA, and the server
  without one gets no HA hook and serves none of the group's scopes, so no
  address can be handed to two clients. It serves again once you give it an HA
  Peer URL or move it to another group. The group page says "More than two Kea
  members" and names it, and the group API lists it in the new
  `ha_sidelined_members` field. The HA firewall rule and the Kea version-skew
  upgrade check follow the same rule. Groups of one or two Kea servers behave
  exactly as before.
