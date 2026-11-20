### Fixed

- Delegate wrote a child zone's NS (and glue) records into the parent beside a CNAME at the same name, which BIND refuses ("CNAME and other data"), holding the whole parent zone on its last good copy. It now holds those rows to the record API's CNAME rule: the apply answers 409 naming the CNAME (delete or rename it first) and writes nothing, the preview lists the conflict, and the Zone menu shows Delegate disabled with the reason instead of inviting the press. (#4388)
