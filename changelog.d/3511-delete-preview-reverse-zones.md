### Fixed

- **A subnet, block or space delete's approval preview names the
  reverse zones it trashes (#3511).** Deleting a subnet, block or
  space also moves to the Trash, in the same batch, each reverse zone
  its subnets auto-created and no live subnet outside the delete still
  uses, with the zone's records. The two-person approval preview never
  counted them, so the approver was not told, and a record added to
  one of those zones between the request and the approval did not
  refuse the approval. The preview now counts them ("1 DNS zone, 2 DNS
  records"), chosen by the same rule the delete uses, so a change in
  them refuses the approval as a change in any other count does.
