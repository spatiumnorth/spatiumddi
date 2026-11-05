### Fixed

- A DNS agent whose `named` was OOM-killed while applying a config now says so: the server chip, banner and `agent_config_rejected` alert read "out of memory while applying config (limit X)" instead of a plain crash. The agent compares the cgroup `oom_kill` counter across the restart and reports the reason and memory limit on its heartbeat; older agents are unaffected (#3552).
