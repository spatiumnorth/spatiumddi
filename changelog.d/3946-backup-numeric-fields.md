### Fixed

- A backup destination's port or S3 Object Lock period that is not a whole, finite number (for example `1e999` or `21.5`) is now refused with a 422 naming the field, instead of answering 500 or being stored as sent, and the destination dialog sends those two fields as numbers.
