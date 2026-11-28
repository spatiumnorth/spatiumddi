### Fixed

- Appliance: `chronyd-restricted.service` is masked in the image, so `chrony.service` (the unit the NTP apply path manages) is the daemon at boot instead of conflicting with it (#4951).
