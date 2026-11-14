### Fixed

- An RFC 2317 classless reverse zone such as `0/26.2.0.192.in-addr.arpa` can now be created from the Add Zone form, the REST API and the copilot. The `/` is accepted only as the first label of a name under `in-addr.arpa`, in the `<octet>/<prefix>` shape; every other `/` in a zone name is still refused.
