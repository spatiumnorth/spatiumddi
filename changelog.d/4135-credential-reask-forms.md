### Fixed

- Editing the address of an integration, webhook, forwarding target, AI provider, auth provider, agentless DNS/DHCP server, SNMP device, calendar or backup destination that keeps a stored credential now clears that credential's field, marks it required with a short hint and holds Save until it is entered (or removed), instead of failing with a 422 on Save; changing the address back restores "stored".
