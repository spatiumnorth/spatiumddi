### Fixed

- After an undo fixes a failed DNS apply, the agent now reports its daemon healthy again together with the config verdict; before, the server kept `daemon_status: degraded` with the old `config_apply_reverted` reason until the next structural change or an agent restart (#3161).
