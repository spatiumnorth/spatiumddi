### Fixed

- An address whose hostname was cleared no longer reports its old FQDN as current: the address list and detail, address search, the IPAM exports, the Ansible inventory, the TLS probe host and the Copilot IP tools now show an FQDN only while the address has a hostname. The stored FQDN is kept for the orphan restore.
