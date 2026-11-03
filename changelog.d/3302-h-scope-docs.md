### Fixed

- API-token docs and the token dialog now describe the scopes as they behave (#3302): a `read` token is refused mutations with a 403 but may call read-only POSTs and MCP; a write scope grants no reads outside its prefixes and a write-only token cannot use MCP; writes outside the IPAM, DNS and DHCP scopes need an unrestricted token; and each scope's cross-domain effects are named. The advice to restrict a token with `allowed_paths` (backup pull, E911) is removed, since that column is reserved and enforced nowhere.
