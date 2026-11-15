### Fixed

- An RFC 2317 classless reverse zone such as `0/26.2.0.192.in-addr.arpa` can now be created from the Add Zone form, the REST API and the copilot, and wired to its parent through the record API. The `/` is accepted only as the first label of a name under `in-addr.arpa`, in the `<octet>/<prefix>` shape; in the parent zone, the delegation NS (or DS) owned by that label (`64/26`) and a CNAME whose target is `<octet>.<classless zone>` (`65.64/26.2.0.192.in-addr.arpa.`) are accepted too. Every other `/` in a zone name, record name or target is still refused.
