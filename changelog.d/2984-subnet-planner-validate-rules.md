### Fixed

- **Subnet Planner validation now predicts what apply refuses, using the
  rules New Subnet and New Block use (#2984, #2985, #2986).** A plan
  anchored to a nested block flagged every node as overlapping the blocks
  that contain the anchor, so it could never be applied; only the anchor's
  own subtree and the space's other rows are checked now. A planned
  subnet's gateway outside the subnet, or on its network or broadcast
  address, is a conflict on the node while editing (Apply stays disabled),
  instead of a 422/409 after the confirm. A Required custom field a
  planned subnet or block would not hold (own or inherited from the anchor
  chain) is a conflict too, so apply no longer stores a subnet New Subnet
  would refuse. An apply failure now shows inside the confirm dialog that
  promised it.
