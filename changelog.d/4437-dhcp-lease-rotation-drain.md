### Fixed

- The DHCP agent no longer loses lease rows Kea appends in the instant before a lease-file rotation: the old file is drained a second time once the rotation is seen (#4437).
