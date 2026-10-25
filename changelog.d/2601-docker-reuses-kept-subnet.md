### Fixed

- **A Docker network that comes back, or a Docker target that is
  re-added, no longer gets a second subnet beside the one it left
  (#2601).** A mirrored subnet is kept with no owner when its network
  goes away while it holds an edited address (#1558), and when its
  target is deleted while it holds operator content (#2287). The next
  sync looked only at the target's own subnets, so it created a second
  subnet with the same CIDR and name in the same IP space, and which of
  the two held the target's addresses followed database order. The
  Docker reconciler now reuses an un-owned subnet at exactly the
  network's CIDR as it stands, without claiming or renaming it, as the
  Proxmox, Cloud and OPNsense reconcilers already do. An address goes
  to the target's own subnet first, then to the longest prefix, with a
  fixed tie-break. An address an operator edited stays in its subnet.
