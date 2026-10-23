### Fixed

- **Every path that publishes to DNS now validates the owner and the value.**
  A DHCP reservation whose hostname was only spaces was stored as typed,
  mirrored into IPAM and published as a record with a blank owner, which
  BIND reads as another record at the previous host's name. Such a hostname
  is now stored as no hostname. The IPAM → DNS sync publishes nothing for a
  hostname that is blank, carries whitespace or a control character, or is
  not a legal owner name (a request answers 422; background paths skip it
  and retract what an earlier name published). The requests portal and the
  Copilot now apply the REST rules: a record value carrying a newline or
  control character, an A / AAAA value that is not one address, an address
  status reserved for integrations, and a malformed reservation hostname are
  refused when the request is submitted. The DNS agent's zone-file writer
  also leaves out, and reports, any record whose owner is blank or contains
  whitespace or a control character, or whose value contains a newline, so
  a row stored before these rules cannot render a blank-owner line or a
  second record.
