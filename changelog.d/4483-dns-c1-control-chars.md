### Fixed

- A DNS record value, import row or DHCP option text carrying a C1 control character (U+0080 to U+009F, such as U+0085 from a pasted document) is now refused like a C0 one instead of being stored; the zone-file renderers also strip it. A stored row that already carries one will be refused with the usual control-character error the next time it is edited, until the character is removed. Accented and non-Latin text is unaffected.
