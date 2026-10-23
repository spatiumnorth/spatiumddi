### Fixed

- **Aggregation snoozes require write on IP blocks and are audited.** The
  snooze, dismiss and clear actions on an IPAM block's aggregation
  suggestions edit one platform-wide list, so they change the badge every
  operator sees. They were admitted by any IPAM write grant, including a
  custom-field grant or an address-set grant, and wrote no audit row. All
  three now require write on IP blocks, and each change writes an
  `audit_log` row (`resource_type="aggregation_snooze"`, keyed on the
  candidate) with the entry's value before and after. The popover's
  buttons are disabled, with a reason, for operators without that
  permission.
