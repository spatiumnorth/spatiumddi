### Fixed

- A secondary or stub zone on a BIND9 or PowerDNS agent that predates the served-serial report no longer reads "not in sync" on every server during a rolling upgrade; the control plane only treats a serial of 0 as "holds no copy" for an agent that says it reports served serials (#4440).
