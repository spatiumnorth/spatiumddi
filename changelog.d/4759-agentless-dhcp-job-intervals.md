### Added

- **Configurable cadence for the agentless DHCP health sweep and
  MAC block sync (#4759).** Both jobs ran on every 60 s beat tick and
  reached every agentless DHCP server each time; on Windows DHCP that
  is a WinRM / PowerShell session on the domain controller per call,
  every minute, even when nothing changed. Two settings in Settings ›
  DHCP Lease Sync, `dhcp_health_check_interval_seconds` and
  `dhcp_mac_blocks_sync_interval_seconds`, now set how often each runs
  (default 60 s, the previous cadence, floor 60 s). The tasks gate on
  them like the lease pull does, so a change needs no beat restart.

### Migrations

- `c4d8e2f61a95` — #4759, adds `dhcp_health_check_interval_seconds`
  and `dhcp_mac_blocks_sync_interval_seconds` (default 60) and their
  `*_last_run_at` stamps to `platform_settings`.
