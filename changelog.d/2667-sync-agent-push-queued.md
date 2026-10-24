### Fixed

- **DNS: Sync with Servers no longer reports a push error per record on agent-managed BIND9 servers (#2667).** The push phase called a driver write the control plane cannot make to an agent-managed server. Records missing from the server are now queued as record ops for that server's agent (no duplicate if already pending) and the result shows them as "Queued for agent". Windows, cloud and other agentless pushes are unchanged.
