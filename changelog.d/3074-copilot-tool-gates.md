### Fixed

- The Copilot's `current_state` rollup now shows each part only to a caller who may read it (open alerts need alert read, subnet utilisation needs subnet read, failed-login counts need audit-log read) and lists what it left out; it no longer claims to report audit-chain integrity. Proposing an IP address allocation from the Copilot now needs write on subnets, the same grant the address REST routes require, instead of write on IP addresses.
