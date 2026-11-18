### Fixed

- An ACL or TSIG key can no longer be deleted or renamed while a DNS zone in the Trash cites it (the 409 names the zone as in the Trash), and Restoring a zone whose cited ACL or key is gone is refused instead of bringing the zone back citing a name its group does not define, which its servers rendered as `allow-query { none; }` (#4226).
