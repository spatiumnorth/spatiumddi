### Fixed

- **Edit Router, Edit VLAN, Edit VRF and Edit ASN no longer put back another
  client's changes (#3869).** Each dialog filled the form from the list's
  copy and saved every field, so a value changed elsewhere since the list
  loaded was silently reverted by an unrelated edit. They now read the
  object when they open and send only the fields you changed.
