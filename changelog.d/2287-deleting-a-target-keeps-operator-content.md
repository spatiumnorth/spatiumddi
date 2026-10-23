### Fixed

- **Deleting an integration target no longer destroys operator content
  in its mirrored subnets (#2287).** Every integration owner FK is
  ON DELETE CASCADE and addresses and DHCP scopes cascade from their
  subnet, so removing a Kubernetes, Docker, Proxmox, Tailscale,
  NetBird, cloud, UniFi, PAN-OS, Fortinet, Meraki or OPNsense target
  hard-deleted every operator address, DHCP scope, pool and
  reservation inside the subnets it mirrored. The #1558 guard only ran
  in the reconcilers. All eleven delete handlers now call one shared
  `release_integration_rows` first: blocks, subnets and addresses that
  hold operator content (edited or foreign-owned addresses, addresses
  with a DNS record or static reservation, DHCP scopes, subnet-domain
  links, tags, custom fields, child blocks or subnets) are un-claimed
  and kept; purely mirrored rows are removed, and an audit row records
  the counts. The delete confirmations now say exactly that.
