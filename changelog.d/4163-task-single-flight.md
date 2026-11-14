### Fixed

- When the Redis master moved while a long task was running (a failover, a drain), the broker handed the same message to a second worker and the task ran twice at once; during a failover drill 14 of 15 nmap scans did. nmap scans, packet captures, subnet discovery sweeps and ACME orders now take a short Redis lock, kept alive while they run, and a second delivery of the same one waits and then exits as a no-op once the first run has finished (or runs if the first run died). With Redis unreachable the task simply runs. (#4163)
