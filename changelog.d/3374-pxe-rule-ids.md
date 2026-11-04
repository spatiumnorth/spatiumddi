### Fixed

- Editing a PXE boot rule's arch codes or vendor class no longer renames its generated Kea class, so a DHCP pool restricted to that class keeps matching. The Edit PXE profile dialog now identifies each existing rule, and a Save that would delete a rule a pool still names, or deleting the whole profile, is refused with the pools listed.
