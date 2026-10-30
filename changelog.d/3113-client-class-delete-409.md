### Fixed

- Deleting a DHCP client class that a pool's class restriction still names now shows the server's refusal and its reason in the confirm dialog, instead of leaving it open with no explanation. The DHCP scope and pool deletes, which the server refuses for a Windows failover or split scope, now show their reason the same way (#3113).
