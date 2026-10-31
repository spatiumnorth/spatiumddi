### Fixed

- An alias withdrawn by Mark as Orphan is no longer listed in the Trash as a stand-alone DNS Record. Restoring it alone served a CNAME to a withdrawn host, and Delete permanently lost it for good. It now follows its address: it comes back when the address is restored and is deleted when the address is deleted permanently, and the Trash refuses a direct Restore or Delete permanently on it while the address is an orphan (#3189).
