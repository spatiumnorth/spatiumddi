### Fixed

- **Subnet Planner validation now predicts what apply refuses, using the
  rules New Subnet and New Block use (#2984, #2985, #2986).** A plan
  anchored to a nested block flagged every node as overlapping the blocks
  that contain the anchor, so it could never be applied; the anchor and its
  ancestors are no longer conflicts, while a node outside the anchor or
  over any other existing row (a sibling of the anchor included) still is.
  A planned subnet's gateway outside the subnet, or on the network or
  broadcast address its placeholder rows hold, is a conflict on the node
  while editing (Apply stays disabled), instead of a 422/409 after the
  confirm. New Subnet and subnet edit run the same gateway rule with the
  same words, so New Subnet now refuses a gateway on the network or
  broadcast address with a 422 naming it, where it used to answer a generic
  409 from the unique constraint. A Required custom field a planned subnet
  or block would not hold (counting what the anchor chain carries, as New
  Subnet / New Block do) is a conflict too, so apply no longer stores a row
  New Subnet or New Block would refuse. An apply failure shows inside the
  confirm dialog that promised it, each conflict named.
