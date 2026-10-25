### Fixed

- **The DHCP and NetBox importers disable their steps for a non-superadmin (#2523).** Preview import (DHCP) and Test connection / Preview import (NetBox) now read "Requires superadmin" for a read-only Viewer, as the DNS importer does, instead of enabling once the form is filled and ending in a 403.
