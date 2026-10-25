### Fixed

- **Sync DNS leaves an address in the zone it was put in (#2104).**
  Allocate, Edit and Bulk edit can put an address in a zone other than
  its subnet's, and #493 made later edits keep it. Sync DNS still
  worked each address's zone out from its subnet: the preview listed
  the address's A and PTR as mismatched (the A with the same name and
  value on both sides), and committing them, which the dialog does by
  default and auto-sync does on every run, moved the host back into
  the subnet's zone and pointed its PTR there. If the subnet had no
  zone at all, the same records were listed as stale and deleted. The
  preview and the commit, at subnet, block and space scope and in
  auto-sync, now use the address's own zone when it has one and it is
  still live, and the subnet's otherwise, which is what the record
  write already did for a hostname edit. A forward record that is in
  the wrong zone now names the zone it is in. Editing a DHCP
  reservation's row and re-importing an address no longer move it out
  of its zone either.

  **Behaviour change.** IPAM records the zone an address is published
  in, but not whether an operator chose it or it came from the subnet.
  So Sync DNS now leaves every published address in its zone:
  - Changing a subnet's zone from Z to Z2 no longer makes Sync DNS (or
    auto-sync) move the subnet's existing addresses into Z2. They read
    as in sync in Z. Move them with Bulk edit → DNS zone. New
    addresses, and addresses with no zone of their own, use Z2.
  - Removing a subnet's zone no longer lists its published addresses'
    A, AAAA and PTR records as stale, so Sync DNS and auto-sync with
    delete-stale on no longer delete them. Remove them by setting each
    address's DNS zone to None in Edit.
  An address whose zone was deleted still follows the subnet.
