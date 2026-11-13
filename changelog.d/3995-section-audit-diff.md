### Fixed

- The SSH access, DNS resolver, Syslog forwarding and APT sources settings audit rows now record only the fields that changed, with old and new values, and a save that changes nothing writes no row. SSH keys are recorded by fingerprint (no longer in full), and APT GPG keys, APT mirror auth and syslog CAs by digest, never the material (#3995).
