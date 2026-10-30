### Fixed

- **DHCP dialogs now save what they show, and an untouched Save audits
  nothing (#3082, #3083, #3085, #3086).** Edit DHCP Scope refuses a Lease
  Time of 0 (or a blank one) with a reason instead of silently saving
  86400. Pressing Enter in a DHCP option field (DNS Servers, Routers, …)
  commits what the field shows and no longer saves the dialog with the
  old options. Edit MAC Block shows the reason a block holds, including
  the free text typed on the New Devices page, and an untouched Save keeps
  it (the update accepts the block's own stored reason). A Save that
  changes nothing in a DHCP scope, server group, server, static
  assignment, pool, client class, option template, MAC block, device
  policy, PXE profile, phone profile or DNS blocking list now audits no
  changed field, instead of naming every field the dialog sent; values are
  compared as the database holds them (empty text vs unset, list order of
  relay addresses, nested options), while an empty list is still told apart
  from unset. Detaching a scope's PXE profile is now named in its audit row.
