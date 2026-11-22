### Fixed

- The PowerDNS, dnsdist and Technitium images ran as ids (101 / 102) that the appliance host gives to its own system accounts, and their state lives on the host. They now use dedicated ids (PowerDNS and dnsdist 10002:10002, Technitium 10003:10003); existing state is re-owned on the first start after upgrade.
