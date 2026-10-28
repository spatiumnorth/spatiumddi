### Fixed

- **Split, Merge and Resize now share one network / broadcast rule
  (#2976, #2977, #2978).** A subnet made by Split, Merge or Resize
  gets the same network (and, for IPv4, broadcast) rows a New Subnet
  at that prefix gets: below /31 for IPv4 and below /127 for IPv6.
  IPv6 Split and Merge used to drop the network row, and Merge and
  Resize of two /31s into a /30 left hosts on the result's network
  and broadcast addresses (reading 4 / 2, 200%). A host that would
  sit on a result's network or broadcast address is now refused with
  a conflict that names it, for both families, in Split (IPv6 too),
  Merge and Resize.
  Split and Merge also keep a subnet's opt-out from the auto reverse
  zone (`skip_reverse_zone`); a merge of sources that disagree takes
  the opt-out and the preview says so.
  A block resize's grow-only refusal now says "To reduce a block"
  instead of "To reduce a subnet".
