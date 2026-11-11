### Fixed

- Deleting a DNS zone permanently, or purging it from Trash, no longer deletes the provider's copy when another group still has a live zone of the same name that may use the same Technitium, Windows DNS or cloud provider copy. The copy is left in place, the audit row lists it, and the delete response says so.
