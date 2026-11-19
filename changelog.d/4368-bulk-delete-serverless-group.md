### Fixed

- Bulk-deleting DNS records in a zone whose server group has no server now moves them to the Trash (or removes them, with permanent delete), exactly like deleting one record; it used to skip every record with "no enabled server ... wire delete skipped" and delete nothing.
