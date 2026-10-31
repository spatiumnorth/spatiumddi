### Fixed

- Restoring a DNS zone from the Trash no longer brings back the auto-generated record of an address that was deleted for good after the zone. The single permanent address delete, the bulk permanent delete and the subnet's orphan purge now remove the address's trashed auto records with it, as the subnet purges already did (#3186).
