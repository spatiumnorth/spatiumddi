### Fixed

- **Two DNS agents on one server identity no longer keep re-registering each
  other (#2219).** When a cloned VM or two containers sharing one agent state
  directory ran as the same DNS server, a token issued to either one made the
  other's token invalid, so the pair took turns re-registering
  (`heartbeat_will_rebootstrap` over and over). The agent the control plane
  already refuses at its config poll (#2044) is now refused at registration
  too, with the same 409, and its heartbeat no longer rotates the shared
  token. The agent that owns the server keeps its token and runs normally;
  the refused one keeps serving its cached configuration, logs
  `register_duplicate_agent_instance`, and retries every 30 s, taking over by
  itself once the other agent stops. The **Duplicate agent** chip and alert
  still show the pair. Agents older than this release send no process id when
  registering and register exactly as before.
