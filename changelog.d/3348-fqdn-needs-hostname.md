### Fixed

- An address created through the Copilot `create_ip_address` operation with an FQDN and no hostname now takes its hostname from the FQDN's first label (and is refused if that label is not a valid host name), and a NetBox import no longer stores an FQDN for an address whose host label sanitises to nothing, so neither shows up with no name at all (#3348).
