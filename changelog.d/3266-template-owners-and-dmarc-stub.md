### Fixed

- **A zone made from a template stores record owners in the record API's form, and the Email zone always gets its DMARC stub (#3266, #3267).**
  From Template stored owners as typed (`Sel1._domainkey`, `café._domainkey`, the
  AD site name), so a BIND9 group served a non-ASCII DKIM owner as raw octets and
  its drift report never came clean. Owners are now lower-cased and IDNA-encoded
  exactly as the record API does. The Email zone template also makes a
  monitor-only `_dmarc` record (`v=DMARC1; p=none`) when the DMARC mailbox is
  left blank, as its description promises.
