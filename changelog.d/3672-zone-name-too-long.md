### Fixed

- **A zone with a very long name no longer stops its BIND9 server
  applying anything (#3672).** A zone of 250 characters with no Primary
  NS and no Admin Email was served with `ns1.<zone>` and `admin.<zone>`,
  longer than a DNS name may be, so BIND refused it. Holding that zone
  back then tried to delete a file whose name was too long for the file
  system, and the agent rejected its whole configuration: no change to
  any zone of the group was served until the long zone was deleted. Add
  Zone, Edit Zone, the template create, the Copilot and the importers
  now refuse such a zone and say which field to set. On the agent, a
  zone whose files cannot be named, or whose files cannot be cleaned up
  while it is held back, is held back on its own with the reason, and the
  rest of the configuration applies. That includes a zone of 249
  characters or more (242 or more with DNSSEC) whatever its apex: BIND
  will not load a zone whose journal file it cannot name, and such a zone
  used to fail the whole apply after it was written.
