### Fixed

- The Top-N "noisiest DNS clients" report and its Operator Copilot tool now require read access on DNS servers, the same as the DNS query log they summarise. A grant on a single DNS server group no longer reveals the client addresses querying every server. As a result the builtin DNS Editor role, which has no read on servers and so could not read the raw query log either, no longer sees this report. The Reports page now shows each card that the signed-in user lacks permission for as withheld, naming the permission it needs, instead of "Failed to load this report".
