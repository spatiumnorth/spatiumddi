### Fixed

- The BIND9 agent now removes a zone's DNSSEC key files from the persistent key directory once the zone has been deleted, unsigned or moved to another group for 7 days (`DNSSEC_KEY_PRUNE_GRACE_SECONDS` on the agent), so private keys no longer linger on disk forever and a same-name zone created after that starts with fresh keys. A zone signed again inside the window keeps its keys, so the DS at the registrar stays valid (#2309).
- The DNSSEC card now shows the DS for a signed RFC 2317 classless reverse zone (`0/26.2.0.192.in-addr.arpa`) or a zone named in mixed case: BIND writes such names into key filenames as `%2F` and in lower case, and the agent looked for them verbatim (#2309).
