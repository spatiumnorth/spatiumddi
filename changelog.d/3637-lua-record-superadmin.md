### Fixed

- Creating a LUA record, or changing the value of one, now needs a superadmin. A DNS Editor is refused with a 403 (audited) on the record create and update, bulk create, zone-file and spreadsheet import, and create-zone-from-template routes, because a LUA snippet runs inside the PowerDNS server at query time. Existing LUA records keep serving, and deleting one still follows the normal record delete permission. The Add Record dialog hides the LUA type from non-superadmins and no longer says the agent sets per-zone metadata (it enables `enable-lua-records` for every PowerDNS server).
