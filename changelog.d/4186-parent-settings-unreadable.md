### Fixed

- Edit Subnet and Edit Block said "No DNS settings configured in parent chain." and "No DHCP group configured in parent chain." when a scoped role was only refused the read of the parent's settings; they now say the parent's settings are not visible to the role. (#4186)
