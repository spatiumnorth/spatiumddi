### Fixed

- **A zone whose own name has an underscore label is served
  (#3003).** A zone such as Active Directory's `_msdcs.<forest root>`
  or a `_domainkey.<domain>` delegated to a mail provider, made with its
  name alone, was never served by BIND9: the placeholder name server
  `ns1.<zone>` and SOA mailbox `admin.<zone>` the agent writes for a zone
  that names none of its own carry the underscore label, and BIND's
  check-names refused the zone file, so it answered SERVFAIL while the
  zone API had answered 201. A Primary NS alone did not help, since the
  mailbox was still refused. Such a zone's placeholder name server and
  mailbox are now `invalid.`, outside the zone (a name that never
  resolves, as catalog zones use), and the zone is served; a Primary NS,
  NS records at the apex and an Admin Email are served as before, and
  every other zone renders the same bytes.
