### Fixed

- A DHCP pool can no longer be left restricted to a PXE class Kea never receives: disabling a PXE profile or unbinding it from its last scope is refused (409, naming the pools) while a pool still names one of its classes, a pool naming a `pxe-…` / `voip-…` class that no rule or phone profile generates is a 422, and two boot rules selecting the same clients in one profile are refused (#3388).
