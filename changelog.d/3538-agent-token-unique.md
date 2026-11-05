### Fixed

- An agent token minted in the same second as the one it replaces is no longer byte-identical to it, so a displaced duplicate DNS / DHCP / Looking Glass agent is reliably refused instead of occasionally keeping a valid token (#3538).
