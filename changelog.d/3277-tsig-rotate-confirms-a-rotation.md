### Fixed

- **A TSIG key's Rotate no longer asks its last step as a permanent
  deletion (#3277).** On a DNS server group's TSIG Keys tab, a key's
  Rotate opened the two-step confirm with the delete wording on its
  second step: "Confirm Permanent Deletion", "This action cannot be
  undone." and a Delete button that read "Deleting…" while the request
  ran, though the button only rotates the key (a new secret replaces
  the old one and the key stays). That step now reads "Confirm TSIG Key
  Rotation", warns that the old secret is replaced and stops working on
  the next config push, and its button reads "Rotate key" ("Rotating…"
  while it runs). The two steps and the checkbox stay.
