### Fixed

- **A linked customer the user may not read no longer shows as None
  (#3527).** For a role refused the customer list, the multicast group,
  circuit, service and overlay edit forms and the shared customer picker
  (the subnet, IP space and block forms among them) showed their empty
  "None" choice over a linked customer, as if none were linked. They now
  keep it selected as "(current customer)", the label a user who reads
  only other customers already gets, and Save still sends it unchanged.
  The multicast list's Customer cell said such a customer with the first
  8 characters of its id; it now says "linked, not shown".
