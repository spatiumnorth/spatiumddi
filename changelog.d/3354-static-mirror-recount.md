### Fixed

- Freeing a DHCP reservation's IPAM row outside a request (the hourly orphan-mirror sweep, the trash purge, scope removal, and the Windows reservation poll) now recounts the subnet's and its blocks' allocated-address figures straight away, instead of leaving them stale until the hourly recount ([#3354](https://github.com/spatiumnorth/spatiumddi/issues/3354)).
