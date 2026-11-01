### Fixed

- A DNSSEC policy with NSEC3 iterations above 0 is now refused at save with a 422 (BIND 9.20 accepts only 0, RFC 9276), instead of being stored and then stopping every config change on the server group; policies already saved that way render as 0 with a warning, the form shows iterations as a fixed 0, and when `named-checkconf` prints nothing the agent's error now gives its exit status and command.
