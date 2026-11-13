### Security

- Operator-supplied values in the PowerShell scripts that the Windows DNS and Windows DHCP drivers send over WinRM are now quoted correctly for every quote character PowerShell recognises, and are no longer placed in double-quoted strings.
- The Windows-side PowerShell that the cutover runbook and TTL pre-flight hand to the operator now keeps a host or zone name on one line, so a name containing a line break cannot end a comment or the code block it sits in.
