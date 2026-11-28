### Fixed

- On the appliance, the control chart's api Deployment was refused ("duplicate entries for key DNS_AGENT_KEY") once the chart began injecting the agent keys itself, so a fresh install never created the api and an upgrade never applied the control chart. The appliance now passes its own `.env` agent keys as `dnsAgents.agentKey.value` / `dhcpAgents.agentKey.value` instead of repeating them under `api.env`, so the api, worker and DNS/DHCP role pods share one set of keys and an upgrade keeps them. CI now fails any chart render that lists an env name twice. (#4648)
