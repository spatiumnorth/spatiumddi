### Fixed

- Retiring a subnet's auto-created reverse zone no longer deletes a same-named zone you already had on a Technitium (API), Windows DNS or cloud DNS server: SpatiumDDI now records where it created the zone and deletes it only there. Zones created before this release are treated as not created by SpatiumDDI, so retiring one leaves its provider copy in place (#1771).
