### Fixed

- A DHCP lease renewal whose DNS name is already published and unchanged no longer locks its DNS zones while its lease-events batch runs. On a Kea HA pair both members report every renewal, and their batches used to queue behind each other on the zone row until, at load, they ran past the agent's 15 s request timeout and were sent again (#3773).
