### Fixed

- **Allocate-subnet now applies the subnet template's values (#2566).**
  `POST /ipam/blocks/{id}/allocate-subnet` with a `template_id` recorded
  the template but dropped its custom fields, tags and DNS / DDNS
  fields, because the carve rebuilt its create body with every field
  marked as sent. Only what the caller sent now beats the template.
