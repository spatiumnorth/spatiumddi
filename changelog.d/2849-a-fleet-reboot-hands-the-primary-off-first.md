### Fixed

- **A Fleet reboot of the node holding the database primary no longer
  stops the API for up to a minute (#2849).** The reboot stopped the
  PostgreSQL primary with the node's other pods, and the database failed
  over only once it had stopped, while the node itself was going down:
  on a QA cluster the API failed through the other nodes for 24 to 69 s,
  and still for 44 s with the primary's shutdown bounded (#2878). A
  Fleet reboot of a cluster node now first cordons the node, as an
  upgrade's drain does, waits until CloudNativePG has switched the
  primary over to another node and its Service points there, and until
  the old primary runs again as a standby (90 s at most; past that the
  reboot goes on as before), and then reboots. The
  node uncordons itself once it is back. A node that was already
  cordoned is left as it was.
