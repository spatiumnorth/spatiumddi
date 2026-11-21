### Fixed

- Moving a network device from SNMP v2c to v3 while changing its address or port could not be saved: the server asked for a community string the form no longer shows. The form now says the stored credentials the new settings no longer use will be discarded, and sends them cleared ([#4451](https://github.com/spatiumnorth/spatiumddi/issues/4451)).
