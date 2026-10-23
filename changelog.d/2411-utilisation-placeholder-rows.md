### Fixed

- **A full subnet no longer reads over 100% utilised (#2411).** The
  allocated count included the auto-created network and broadcast
  rows while the total leaves those two addresses out, so a full /29
  read 8 / 6 (133%) and a fresh /24 with only its gateway read 3 / 254.
  The IPv4 network and broadcast rows (and an IPv6 broadcast, which
  never exists) are now left out of `allocated_ips` everywhere it is
  computed — the API, every integration reconciler and the hourly
  recount — so allocated never exceeds total.
