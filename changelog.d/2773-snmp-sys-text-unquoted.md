### Fixed

- **SNMP contact and location reach the NMS as typed (#2773).** The renderer
  wrapped `sysContact` and `sysLocation` in double quotes and escaped inner
  quotes, but snmpd serves the rest of that line literally, so every NMS showed
  `"a2 lab rack 4"` and `\"` for an inner quote. They are written unquoted now.
  A value starting with `#`, which snmpd reads as a comment, is left out with a
  note in the file instead.
