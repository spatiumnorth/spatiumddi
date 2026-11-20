### Fixed

- A DNS group with a PowerDNS server no longer accepts recursion being turned on or a custom recursion ACL (PowerDNS is authoritative only and answered REFUSED regardless); the options page now says so and disables the Recursion card, and notes that forwarders only feed ALIAS expansion (#4562).
