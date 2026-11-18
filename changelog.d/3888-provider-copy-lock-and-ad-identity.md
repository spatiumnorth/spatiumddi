### Fixed

- Deleting a zone whose provider copy another group may share is now serialised per zone name, so two groups deleting or creating the same zone at one provider can no longer both keep a stale copy or lose a freshly adopted one, and a Windows DNS server is identified by its AD domain rather than host and port, so two domain controllers holding the same AD-integrated zone no longer let one group's delete remove it for the other (#3888).
