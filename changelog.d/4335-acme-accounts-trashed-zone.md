### Fixed

- The ACME account list no longer answers 500 for every caller while one account's DNS zone sits in the Trash. The account is listed with `zone_in_trash: true`, it can be revoked, and its `/update` is refused (409) until the zone is restored.
