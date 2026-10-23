### Fixed

- **The DNS server Config tab is kept from users who may not read it, and says so on a refusal (#2530).** The tab is shown to superadmins only, and a refused rendered-config read reads as a permission message and is not asked again, instead of "Failed to load, try again" every minute.
