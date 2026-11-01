### Fixed

- Restoring a DNS record or zone from the Trash now applies the same CNAME rule as creating one. A CNAME is no longer brought back beside another record at its name (or another record beside a CNAME created since), which made the server refuse the zone and hold back every later change to it. The record stays in the Trash and the restore says why. The Trash restore dialog now also lists any rows a restore left behind (a clashing record, or a subnet's records held back with the subnet), instead of closing without a word (#3187, #3188).
