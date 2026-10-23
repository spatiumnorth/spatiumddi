### Fixed

- **Deleting a group's primary DNS server no longer silences every
  later record write (#2276).** The delete left the group with no
  `is_primary` server, and the record-op path then returned before
  its per-server fan-out: every record created, changed or deleted
  afterwards was saved, answered 200, and reached no server, the
  surviving agents included. Deleting the primary (over the API, or by
  revoking the appliance that owned it) now elects the oldest enabled,
  unpaused survivor in the same transaction, the way a #934 move
  does, and the delete's audit row names it. A group already left
  without a primary keeps receiving writes: agent-based groups fan out
  to every enabled server regardless of the flag, an agentless group
  writes through the server the election would pick (logged as
  `dns_group_has_no_primary`), and the 60 s agent stale sweep marks
  that server primary, so existing installs heal on upgrade. Only a
  group with no servers queues nothing, and its servers-to-be get the
  records in their bundle. The 422 for clearing a group's last primary,
  the server form's hint and the Copilot's `find_dns_servers`
  description no longer claim a missing primary drops writes, and the
  scheduled pull-from-server sweep caps its primary lookup at one row so
  a group briefly holding two cannot abort it.
