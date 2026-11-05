### Fixed

- **DNS and IPAM writes no longer deadlock into a 500 against a record
  being created in the same zone (#3503).** A record create holds the
  zone's row from its serial bump and takes the audit log's chain lock at
  its commit. Several paths took the chain lock first (an audit row
  flushed early, or the utilization recount, which takes it explicitly)
  and bumped a zone's serial afterwards, so each waited for the other and
  PostgreSQL aborted one: deleting a DNS record, restoring one from the
  Trash, creating a subnet, permanently deleting a zone, editing or
  deleting a DNS pool or pool member, allocating an address in a subnet
  whose reverse zone had to be created first, bulk-editing addresses,
  importing addresses, and a DHCP lease whose DDNS name was already
  taken. They now write the zone first and their audit rows last. The
  audit hook also locks any zone row a flush is about to write before it
  takes the chain lock, so a path that stages both in one flush is safe
  whatever order it staged them in. The order is: zone row, then the
  audit-chain lock, then subnet and block rows. #3389 fixed the zone
  edit, the Dynamic Updates save and `apply-record`; its note that every
  record write already took this order was wrong for record delete.
  Approving a change request that writes DNS still takes the chain lock
  first and is left for a follow-up.
