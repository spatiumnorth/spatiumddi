### Fixed

- A request refused on a DNS server group or DHCP server group route is now written to the Audit Log under the same resource type as that group's changes (`dns_server_group`, `dhcp_server_group`), so one Resource filter lists both; the DHCP responder, phone/PXE profile, device policy and IP plan routes get the same treatment. The refusal reason still names the permission.
