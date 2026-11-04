### Fixed
- Waking a host now needs the same permissions everywhere: the Copilot `wake_host` operation and Wake-on-LAN schedules both require write on subnets, as waking an address through the IPAM API always has. The Copilot preview says when you lack it, and a schedule whose owner lacks it wakes nothing, checked again on every run.
