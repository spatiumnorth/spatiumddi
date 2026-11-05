### Fixed

- A DNS server whose `named` was OOM-killed while applying a config now says so: the server chip, banner and `agent_config_rejected` alert read "out of memory while applying config (limit X)" instead of a plain crash. On Docker Compose the agent records the kill before its container restarts; on the appliance, where the kill takes the agent with `named`, the control plane names it from the kubelet's `OOMKilled` for the container. Older agents are unaffected (#3552).
