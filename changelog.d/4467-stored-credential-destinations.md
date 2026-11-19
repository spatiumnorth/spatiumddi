### Fixed

- A stored credential is only kept when its destination is unchanged: editing an integration's host, port or URL now requires the credential again even when the form sends it blank, the Technitium API URL counts as a destination, block-sync write credentials are cleared when their target moves (an armed target must be disarmed first), and a connection test of a saved row that names a different host must carry its own credential.
