### Fixed

- **ASN Delete says what goes with the ASN (#2612).** The dialog claimed it would not touch IPAM rows or BGP relationships. It now says the ASN's ROAs, peerings (either side) and communities are deleted, and that the ASN is cleared on the IP blocks, subnets, VRFs, routers and providers that carry it.
