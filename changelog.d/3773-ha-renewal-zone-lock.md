### Fixed

- A DHCP lease renewal whose DNS name is already published and unchanged no longer locks its DNS zones while its lease-events batch runs. On a Kea HA pair both members report every renewal, and their batches used to queue behind each other on the zone row until, at load, they ran past the agent's 15 s request timeout and were sent again (#3773).
- The DHCP agent now waits up to 60 s, rather than 15 s, for the control plane to answer a lease-events batch or lease snapshot page before sending it again. Connection attempts still give up after 5 s (#3773).
