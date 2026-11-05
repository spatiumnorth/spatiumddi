### Fixed

- A failed permissions read no longer reads as a role lacking access outside the Dashboard: the Reports cards, the IPAM BGP routes panel, the IP detail blocklist and profile-scan sections, the VRF and ASN pickers, the provider Default ASN, the DNS zone domain link and TLS certificates, the Copilot scan progress card, the Network Tools notice and the Settings caption now say the permissions could not be read and to reload, and only a grant the user really lacks keeps the role wording (#3546).
