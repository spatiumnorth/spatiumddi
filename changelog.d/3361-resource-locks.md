### Added

- **Edit and delete locks on IPAM, DNS and DHCP objects (#3361).** A
  space, block, subnet, address, DNS server group, view, zone, record,
  DHCP scope or static reservation can be locked with a required reason.
  A `delete` lock keeps the object from being deleted; an `edit` lock
  also freezes its operative fields (address, name, CIDR, record value
  and TTL, SOA, scope ranges) while description, tags, custom fields and
  owner stay editable. Refusals are `423 Locked` with
  `code: "resource_locked"` naming the object, level and who locked it.
  A parent delete, split, merge or move that would take a locked object
  with it is refused naming it; bulk edits and deletes skip locked rows
  and report each one; an IPAM change the DNS sync would carry into a
  locked record is refused, and the automatic writers skip it. New
  `lock` permission per resource type, `/api/v1/locks`, and the
  `find_locked_resources` Copilot tool. Integration-owned rows cannot be
  locked.

- An edit-locked IP address that mirrors a DHCP reservation now also
  refuses the reservation's own hostname / MAC / address edit and its
  delete (#3361).

- A DNS server group's edit lock now also freezes its ACLs, TSIG keys,
  trust anchors and server options (an ACL's description and a key's
  notes stay editable) (#3361).
- New `resource_lock_removed` alert rule (seeded disabled): one event per
  unlock naming who removed the lock, what it protected and the reason
  given. The DNS drift report lists each locked record whose live value
  on a server differs from the saved one (#3361).

### Migrations

- `a3361c0de1f7` — #3361, adds the lock columns to `ip_space`,
  `ip_block`, `subnet`, `ip_address`, `dns_server_group`, `dns_view`,
  `dns_zone`, `dns_record`, `dhcp_scope` and `dhcp_static_assignment`.
