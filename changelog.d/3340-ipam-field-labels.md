### Fixed

- **IPAM dialog labels now name their controls (#3340).** The create
  and edit dialogs for spaces, blocks, subnets and addresses, and the
  subnet planner, drew a label beside each field without tying it to
  it, so a screen reader announced no name for Edit Block's Name and
  Description (and every other field) and a search by label found
  nothing. They now use the same labelled field the DHCP dialogs use.
