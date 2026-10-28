### Fixed

- **An approved DHCP reservation request now mirrors into IPAM, and
  honours the group-wide MAC check (#2901, #2902).** The apply path
  the request portal's approve and the copilot's propose/apply share
  inserted the reservation and committed, skipping the work the REST
  create runs. The reserved IP kept reading as free in IPAM, the
  subnet and block counts stayed stale, a Windows or cloud member was
  never written through, and a MAC already reserved in another scope
  of the same server group could be reserved a second time. It now
  runs the same steps in one transaction: the conflict check, the
  write-through, the agent wake, the `static_dhcp` IPAM mirror and the
  recount. A refusal (409 for a duplicate MAC) leaves the request
  pending and commits nothing. The collision rules moved into
  `services/dhcp/static_conflicts.py` so the REST handler and the
  apply path share one copy, and the operation preview now says it
  will create the IPAM row.
