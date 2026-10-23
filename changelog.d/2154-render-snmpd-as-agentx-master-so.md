### Fixed

- **LLDP over SNMP now serves LLDP-MIB (#2154).** The LLDP "Expose
  via SNMP (AgentX)" toggle runs `lldpd -x`, which registers LLDP-MIB
  with snmpd as an AgentX subagent. That needs snmpd to be the AgentX
  master, and the `snmpd.conf` SpatiumDDI renders (it replaces
  Debian's stock file, which is where `master agentx` came from) never
  said so. The toggle saved, lldpd ran, and `lldpRemTable` was never
  served. The render now carries `master agentx` on a root-only local
  socket, `/run/agentx/master`, whenever SNMP is on, and lldpd is
  pointed at the same path with `-X`. No firewall change: the socket
  is local. lldpd re-registers on its own within about 15 seconds of
  an SNMP config change restarting snmpd. The SNMP apply's config check
  also now runs against a copy of the config on a throwaway socket, so
  it cannot take the live snmpd's socket.
