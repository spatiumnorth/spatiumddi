### Fixed

- The DNS bulk record delete and the customer delete (row and bulk) no longer promise a restore from Administration → Trash to a user the Trash refuses: every Trash route is superadmin-only, so the dialogs now say a superadmin can restore, as the IPAM, zone and DHCP scope deletes do (#3150).
