### Fixed

- A DHCP scope restored from the Trash now publishes each reservation in the DNS zone and extra zones its address was put in, instead of moving the host to the subnet's zone. A zone that no longer exists or is no longer in the subnet's DNS group falls back to the subnet's zone, and the restore response lists a warning for it (#4754).
