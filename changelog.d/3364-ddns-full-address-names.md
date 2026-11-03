### Fixed

- Generated DDNS names now carry the whole address, `dhcp-10-1-20-5` instead of `dhcp-20-5` (IPv6 uses all 128 bits, not the low 32), so two DDNS subnets that share a zone no longer give `10.1.20.5` and `10.2.20.5` the same name. Records already published under the old form are left alone and move to the new name when their lease next renews; both forms stay reserved for the address they encode (#3364).
