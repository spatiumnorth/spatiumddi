### Fixed

- Deferred DDNS after a DHCP lease-event batch re-checks the address's current lease before publishing, so a client the other HA member has since replaced no longer has its hostname written to DNS (#4439).
