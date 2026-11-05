### Fixed

- Two DHCP agents of one server group (a Kea HA pair) posting the same new leases in different orders, or cut into batches at different points, no longer deadlock in PostgreSQL. One of the two lease batches was aborted with a 500 and the agent had to send it again. Each batch now writes its rows in one order (by subnet, then address) and creates its new IPAM rows before any DDNS update. (#3480)
