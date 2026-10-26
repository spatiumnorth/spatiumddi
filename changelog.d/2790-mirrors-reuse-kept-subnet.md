### Fixed

- **A Kubernetes cluster, UniFi controller, Tailscale tenant or NetBird
  instance that is re-added, and a Kubernetes CIDR or UniFi network that
  comes back, no longer gets a second subnet beside the one it left
  (#2790).** A mirrored subnet is kept with no owner when its target is
  deleted while it holds operator content (#2287), and when a Kubernetes
  CIDR or UniFi network leaves while an address in it survives (#1558).
  The next sync looked only at the target's own subnets, so it created a
  second subnet with the same CIDR in the same IP space (Tailscale and
  NetBird a second block too), and which of the two held the target's
  addresses followed database order. These reconcilers now reuse an
  un-owned subnet at exactly the CIDR as it stands, as the Docker
  reconciler does since #2601. An address goes to the target's own
  subnet first, then to the longest prefix, with a fixed tie-break, and
  an address an operator edited stays in its subnet.
