### Fixed

- The query-log severity and the two print options (category, severity) saved on a DNS server group were never sent to the BIND9 agent, so every group rendered the default `info` channel with both prints on whatever was configured. The agent bundle now carries them. (#4594)
