### Fixed

- The subnet's DHCP Pools tab told the built-in Auditor and Compliance Editor that every scope had "0 pools" and "Pools (0)", because both roles may read DHCP scopes but not pools and the card drew the refused pool list as empty. The card now says the reader may not see the scope's pools and draws no count; readers who may read pools see no change. (#4637)
