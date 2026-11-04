### Fixed

- **The Appliance page asks for the appliance's own details only when the
  user may read them (#3420).** A user who opens the page for the
  certificate store alone (the built-in DNS Editor, or any role with the
  store and nothing on the appliance) was refused `GET /appliance/info` on
  every load, and each refusal was written to the audit log as a denied
  read under their name. The page now asks only a user with read on the
  appliance; the certificate store works as before, and a user who may
  read the appliance still sees its version, hostname and host tabs.
