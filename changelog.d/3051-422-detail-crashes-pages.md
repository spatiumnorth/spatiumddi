### Fixed

- **A validation error no longer blanks the page it came from (#3051).**
  Adding a multicast port of 70000, or saving a circuit with a negative
  bandwidth, made the server answer 422 with a list of field errors, and
  the page tried to show that list as text, failed, and was replaced by
  "This page failed to load". Sites, certificates, services, overlays,
  peerings, providers, customers, VRFs, VLANs, domains, webhooks, IPAM
  and about 30 other forms did the same, or showed raw JSON or
  "[object Object]". Every such form now shows the message, such as
  `port_start: Input should be less than or equal to 65535`, and stays
  open. A test now fails if a page reads an error's `detail` directly
  instead of going through the shared formatter.
