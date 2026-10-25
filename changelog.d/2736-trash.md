### Fixed

- **Trash (#2736).** The Delete permanently dialog on a subnet, DNS zone or DHCP scope no longer says "N other rows deleted with it are removed too". The purge takes the row's own subtree, never the rest of its deletion batch (its parent block or siblings stay in the Trash), so that count named rows that stayed. The IP block and space dialogs now also say the addresses, scopes and records go.
