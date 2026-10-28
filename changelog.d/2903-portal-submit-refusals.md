### Fixed

- **The request portal now refuses at submit what the REST create
  refuses (#2903, #2904, #2905).** An IP request for an address the
  subnet already holds, a `static_dhcp` request with no MAC, or any
  address in a multicast subnet, and a reservation whose IP or MAC is
  already reserved, were accepted and queued pending. They now answer
  the REST create's 409 or 422 with the reason, and no request row is
  created. A reservation whose IP matched one static and whose MAC
  matched another answered 500 at submit; it is now a 409, and the
  copilot's reservation preview no longer raises on it either. The
  rules live in shared helpers the REST create and the portal both
  call.
