### Fixed

- **Renaming or deleting an ACL that only a zone cites stopped the whole
  DNS group (#2283).** The ACL guard checked other ACLs, views and server
  options but not a zone's `allow_query` / `allow_transfer` /
  `also_notify`, so the name became an undefined symbol,
  `named-checkconf` failed and no agent in the group converged. Rename
  and delete now answer 409 naming the zone and field. The bundle also
  drops an ACL name it does not define from every access list, and an
  access list emptied that way (or one that lost a negated element)
  becomes `none` rather than being omitted, because an omitted zone
  `allow-query` inherits the server's, often `any`.
