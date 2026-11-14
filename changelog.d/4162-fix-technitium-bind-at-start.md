### Fixed

- The Technitium console binds to loopback from its first start after an upgrade: the stored web service bind in an existing `/etc/dns` is rewritten before the daemon starts, instead of being corrected through the API a few seconds after it is already listening.
