### Fixed

- A DNS record, DHCP reservation or host-less address created by an approved portal request (or a Copilot apply) now fires `dns.record.created`, `dhcp.static.created` and `ip.created` webhook events, and the new address is seen by the compliance change alert, as with the REST creates. (#3936)
